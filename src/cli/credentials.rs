use std::convert::TryInto;
use std::fs;

use failure::{bail, ensure, format_err, Fallible, ResultExt};
use getopts::Matches;

use crate::cli::CryptDirection;
use crate::credentials::{ComplexCredential, Credential};
use crate::ui::UI;
use crate::util::{try_parse_hex_string, try_parse_hex_string_checksummed};

// In this file we parse a sequence of credential-related command line arguments to create a
// potentially recursive ComplexCredential struct. Command line arguments are first converted to
// a sequence of CredentialToken, then parsed, making all required IO like asking user for a
// password, or reading a public key file.

pub(super) fn get_encrypt_credential(
    matches: &Matches,
    force: bool,
    ui: &dyn UI,
) -> Fallible<ComplexCredential> {
    let mut tokens = extract_tokens(matches)?;
    if tokens.is_empty() {
        tokens.push(CredentialToken::InteractivePassword);
    }

    Ok(parse_complex_credential(
        &mut tokens.into_iter(),
        CryptDirection::Encrypt,
        ui,
        force,
        0,
    )?)
}

pub(super) fn get_decrypt_credentials(
    matches: &Matches,
    force: bool,
    ui: &dyn UI,
) -> Fallible<Vec<Credential>> {
    let mut tokens = extract_tokens(matches)?;
    if tokens.is_empty() {
        tokens.push(CredentialToken::InteractivePassword);
    }

    let complex_cred = parse_complex_credential(
        &mut tokens.into_iter(),
        CryptDirection::Decrypt,
        ui,
        force,
        0,
    )?;
    assert_ne!(complex_cred.num_shares, 0);
    assert_eq!(complex_cred.threshold, 1);

    Ok(complex_cred
        .sub_creds
        .into_iter()
        .map(|(num_parts, cred)| {
            assert_eq!(num_parts, 1);
            cred
        })
        .collect())
}

// CredentialToken-s is a more convenient representation of corresponding command line arguments.
#[derive(Clone)]
enum CredentialToken {
    // Combinators
    KeyThreshold(usize),
    RequireAllKeys,
    KeyShares(usize),
    StartGroup,
    EndGroup,

    // Key-providing arguments
    InteractivePassword,
    NamedInteractivePassword(String),
    PasswordFile(String),
    SymmetricKeyFile(String),
    PublicKeyFile(String),
    PublicKeyText(String),
    PrivateKeyFile(String),
}

// getopts crate has a rather limited API for getting information about command line arguments,
// especially the positions. This function converts getopts Matches struct to a sequence of command
// line arguments/tokens as they were provided by the user.
fn extract_tokens(matches: &Matches) -> Fallible<Vec<CredentialToken>> {
    let mut tokens: Vec<(usize, CredentialToken)> = vec![];

    // Options without value
    let opt_types_without_value = &[
        ("password", CredentialToken::InteractivePassword),
        ("(", CredentialToken::StartGroup),
        (")", CredentialToken::EndGroup),
        ("require-all-keys", CredentialToken::RequireAllKeys),
    ];
    for (opt, cred) in opt_types_without_value {
        for pos in matches.opt_positions(opt) {
            tokens.push((pos, cred.clone()));
        }
    }

    // Options with integer value
    let opt_types_with_int_value: &[(&str, fn(usize) -> CredentialToken)] = &[
        ("key-threshold", CredentialToken::KeyThreshold),
        ("key-shares", CredentialToken::KeyShares),
    ];
    for (opt, cred) in opt_types_with_int_value {
        for (pos, val) in matches.opt_strs_pos(opt) {
            tokens.push((pos, cred(val.parse()?)));
        }
    }

    // Options with string value
    let opt_types_with_str_value: &[(&str, fn(String) -> CredentialToken)] = &[
        ("password-named", CredentialToken::NamedInteractivePassword),
        ("password-file", CredentialToken::PasswordFile),
        ("symmetric-key", CredentialToken::SymmetricKeyFile),
        ("public-key", CredentialToken::PublicKeyFile),
        ("public-key-text", CredentialToken::PublicKeyText),
        ("private-key", CredentialToken::PrivateKeyFile),
    ];
    for (opt, cred) in opt_types_with_str_value {
        for (pos, val) in matches.opt_strs_pos(opt) {
            tokens.push((pos, cred(val)));
        }
    }

    //    // Options with optional string value
    //    let opt_types_with_opt_value: &[(&str, fn(Option<String>) -> CredentialToken)] =
    //        &[("password", CredentialToken::InteractivePassword)];
    //    for (opt, cred) in opt_types_with_opt_value {
    //        let mut all_positions = matches.opt_positions(opt);
    //        let mut positions_with_values = matches.opt_strs_pos(opt);
    //        all_positions.sort();
    //        positions_with_values.sort();
    //
    //        // Match positions with values; Use None if no value provided.
    //        let mut pos_value_iter = positions_with_values.into_iter().peekable();
    //        for pos in all_positions {
    //            let value = match pos_value_iter.peek() {
    //                Some(&(val_pos, _)) if pos == val_pos => pos_value_iter.next().map(|(_, val)| val),
    //                _ => None,
    //            };
    //
    //            tokens.push((pos, cred(value)));
    //        }
    //        assert_eq!(pos_value_iter.peek(), None);
    //    }

    // Sort by argument position
    tokens.sort_by_key(|(pos, _)| *pos);

    // Disallow arguments sharing the same position (this can happen when we have several short-form
    // arguments given together like "-a("), because we can't get their ordering from getopts.
    let tokens_len = tokens.len();
    tokens.dedup_by_key(|(pos, _)| *pos);
    if tokens.len() < tokens_len {
        bail!("Merged short arguments (e.g. '-a(') are not supported. Pass them separately instead (e.g. '-a -(')");
    }

    // Lose the positions and return just the values.
    Ok(tokens.into_iter().map(|(_, val)| val).collect())
}

// This function processes a sequence of CredentialToken-s (basically command line arguments) to
// create a ComplexCredential. On the way, it will ask for passwords, read the files and recurse
// into groups.
fn parse_complex_credential(
    tokens: &mut impl Iterator<Item = CredentialToken>,
    crypt_direction: CryptDirection,
    ui: &dyn UI,
    skip_checksum: bool,
    level: usize,
) -> Fallible<ComplexCredential> {
    let mut sub_creds = vec![];
    let mut num_shares = 0;
    let mut next_key_shares = 1;

    enum KeyThresholdType {
        AllKeys,
        Threshold(usize),
    }
    let mut threshold: Option<KeyThresholdType> = None;
    let mut end_group = false;

    while let Some(token) = tokens.next() {
        // 1. Check invariants
        let (decrypt_allowed, key_shares_allowed) = match &token {
            CredentialToken::StartGroup => (false, true),
            CredentialToken::EndGroup => (false, false),
            CredentialToken::RequireAllKeys => (false, false),
            CredentialToken::KeyThreshold(_) => (false, false),
            CredentialToken::KeyShares(_) => (false, false),
            CredentialToken::InteractivePassword => (true, true),
            CredentialToken::NamedInteractivePassword(_) => (true, true),
            CredentialToken::PasswordFile(_) => (true, true),
            CredentialToken::SymmetricKeyFile(_) => (true, true),
            CredentialToken::PublicKeyFile(_) => (true, true),
            CredentialToken::PublicKeyText(_) => (true, true),
            CredentialToken::PrivateKeyFile(_) => (true, true),
        };
        if crypt_direction == CryptDirection::Decrypt && !decrypt_allowed {
            bail!("Key combinators are not needed and not allowed on decryption. Just pass a list of credentials you have.");
        }
        if next_key_shares != 1 && !key_shares_allowed {
            bail!("--key-shares argument needs to be followed by a key-providing argument");
        }

        // 2. Process the token, recursing if needed.
        let creds = match token {
            CredentialToken::StartGroup => {
                let subkeys = parse_complex_credential(
                    tokens,
                    crypt_direction,
                    ui,
                    skip_checksum,
                    level + 1,
                )?;
                Some(vec![Credential::Complex(subkeys)])
            }
            CredentialToken::EndGroup => {
                end_group = true;
                break;
            }
            CredentialToken::KeyShares(key_shares) => {
                ensure!(key_shares > 0, "--key-shares can't be zero");
                // TODO: Maybe limit key_shares?
                next_key_shares = key_shares;
                None
            }
            CredentialToken::RequireAllKeys => {
                ensure!(
                    threshold.is_none(),
                    "Multiple key threshold arguments are not allowed"
                );
                threshold = Some(KeyThresholdType::AllKeys);
                None
            }
            CredentialToken::KeyThreshold(num_keys) => {
                ensure!(
                    threshold.is_none(),
                    "Multiple key threshold arguments are not allowed"
                );
                threshold = Some(KeyThresholdType::Threshold(num_keys));
                None
            }
            CredentialToken::InteractivePassword => {
                let cred = read_password_interactively(crypt_direction, ui, None)?;
                Some(vec![cred])
            }
            CredentialToken::NamedInteractivePassword(pwd_name) => {
                let cred = read_password_interactively(crypt_direction, ui, Some(pwd_name))?;
                Some(vec![cred])
            }
            CredentialToken::PasswordFile(filename) => Some(
                read_file_lines(&filename, &|line| {
                    Ok(Credential::Password(line.to_string()))
                })
                .with_context(|e| format!("Error reading password file {}: {}", filename, e))?,
            ),
            CredentialToken::SymmetricKeyFile(filename) => Some(
                read_file_lines(&filename, &|line| {
                    Ok(Credential::SymmetricKey(*from_hex32(line, true)?))
                })
                .with_context(|e| {
                    format!("Error reading symmetric key file {}: {}", filename, e)
                })?,
            ),
            CredentialToken::PublicKeyFile(filename) => {
                ensure!(
                    crypt_direction != CryptDirection::Decrypt,
                    "Public keys should not be passed in when decrypting"
                );
                let creds = read_file_lines(&filename, &|line| {
                    Ok(Credential::PublicKey(*from_hex32(line, skip_checksum)?))
                })
                .with_context(|e| format!("Error reading public key file {}: {}", filename, e))?;
                Some(creds)
            }
            CredentialToken::PublicKeyText(public_key) => {
                ensure!(
                    crypt_direction != CryptDirection::Decrypt,
                    "Public keys should not be passed in when decrypting"
                );
                let public_key = from_hex32(&public_key, skip_checksum)
                    .with_context(|e| format!("Invalid public key {}: {}", public_key, e))?;

                Some(vec![Credential::PublicKey(*public_key)])
            }
            CredentialToken::PrivateKeyFile(filename) => {
                ensure!(
                    crypt_direction != CryptDirection::Encrypt,
                    "Private keys should not be passed in when encrypting"
                );
                let creds = read_file_lines(&filename, &|line| {
                    Ok(Credential::PrivateKey(*from_hex64(line, true)?))
                })
                .with_context(|e| format!("Error reading private key file {}: {}", filename, e))?;
                Some(creds)
            }
        };

        // Common logic to add creds to the sub_creds vector.
        if let Some(creds) = creds {
            ensure!(
                !creds.is_empty(),
                "No credentials provided in one of the files"
            );
            num_shares += next_key_shares * creds.len();
            sub_creds.extend(creds.into_iter().map(|c| (next_key_shares, c)));
            next_key_shares = 1;
        }
    }

    if level == 0 && end_group {
        bail!("Unexpected extraneous end-group argument");
    }
    if level > 0 && !end_group {
        bail!("Credential group is not closed (did you forget an --end-group argument?)");
    }

    ensure!(num_shares > 0, "Credential group cannot be empty");
    let threshold = match threshold {
        None => 1,
        Some(KeyThresholdType::Threshold(min_keys)) => min_keys,
        Some(KeyThresholdType::AllKeys) => num_shares,
    };
    ensure!(threshold > 0, "Key threshold can't be zero");
    ensure!(
        threshold <= num_shares,
        "Key threshold {} can't be larger than the number of keys {}",
        threshold,
        num_shares
    );

    Ok(ComplexCredential {
        sub_creds,
        num_shares,
        threshold,
    })
}

fn from_hex32(line: &str, skip_checksum: bool) -> Fallible<Box<[u8; 32]>> {
    let bytes = if skip_checksum {
        try_parse_hex_string(line)?
    } else {
        try_parse_hex_string_checksummed(line)?
    };

    Ok(Box::new(bytes.as_slice().try_into().map_err(|_| {
        format_err!("Invalid key length (we expect 32 bytes, or 64 hex characters)")
    })?))
}

fn from_hex64(line: &str, skip_checksum: bool) -> Fallible<Box<[u8; 64]>> {
    let bytes = if skip_checksum {
        try_parse_hex_string(line)?
    } else {
        try_parse_hex_string_checksummed(line)?
    };
    ensure!(
        bytes.len() == 64,
        "Invalid key length (we expect 64 bytes, or 128 hex characters)"
    );

    // [u8; 64] does not support TryInto<&[u8]>, so we do the conversion manually.
    let mut res = Box::new([0u8; 64]);
    res.copy_from_slice(&bytes);
    Ok(res)
}

fn read_file_lines(
    filename: &str,
    line_to_cred_fn: &dyn Fn(&str) -> Fallible<Credential>,
) -> Fallible<Vec<Credential>> {
    let credentials = fs::read_to_string(filename)?
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(line_to_cred_fn)
        .collect::<Fallible<Vec<Credential>>>()?;

    ensure!(!credentials.is_empty(), "File does not contain any keys.");
    Ok(credentials)
}

fn read_password_interactively(
    crypt_direction: CryptDirection,
    ui: &dyn UI,
    password_name: Option<String>,
) -> Fallible<Credential> {
    ensure!(
        ui.can_read(),
        "Can't read password from a non-TTY stdin. \
         Use '--password-file' if you'd like to provide password non-interactively."
    );

    let suffix = if let Some(password_name) = password_name {
        format!(" [{}]", password_name)
    } else {
        "".into()
    };
    loop {
        let message = format!("Enter password{}: ", suffix);
        let password = ui.read_password(&message)?;

        if password.is_empty() {
            ui.println_interactive("Password can not be empty, try again.")?;
            continue;
        }

        // When encrypting, we request the same password twice to ensure it's entered correctly.
        if crypt_direction == CryptDirection::Encrypt {
            let password_again = ui.read_password("Re-enter password: ")?;
            if password_again != password {
                ui.println_interactive("Passwords didn't match, try again.")?;
                continue;
            }
        }

        return Ok(Credential::Password(password));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::options::{define_credential_combinator_options, define_credential_options};
    use crate::ui::test_helpers::TestUI;
    use crate::util;
    use getopts::Options;
    use std::io::Write;

    fn define_opts() -> Options {
        let mut options = Options::new();
        define_credential_options(&mut options);
        define_credential_combinator_options(&mut options);
        options
    }

    #[test]
    fn test_empty_args() -> Fallible<()> {
        let options = define_opts();
        let matches = options.parse(&[] as &[&str])?;

        // 1. Test encryption mode
        let ui = TestUI::new()
            .expect_prompt("Enter password", Ok("abc"))
            .expect_prompt("Re-enter password", Ok("abc"));
        let cred = get_encrypt_credential(&matches, false, &ui)?;

        let expected_cred = ComplexCredential {
            sub_creds: vec![(1, Credential::Password("abc".into()))],
            num_shares: 1,
            threshold: 1,
        };
        assert_eq!(cred, expected_cred);
        ui.expect_all_prompts_asked();

        // 2. Test decryption mode
        let ui = TestUI::new().expect_prompt("Enter password", Ok("abc"));
        let creds = get_decrypt_credentials(&matches, false, &ui)?;

        assert_eq!(creds, vec![Credential::Password("abc".into())]);
        ui.expect_all_prompts_asked();

        Ok(())
    }

    #[test]
    fn test_complex_encryption_happy_path() -> Fallible<()> {
        let options = define_opts();
        let mut args = vec![];
        let mut args_end = vec![];
        let mut ui = TestUI::new();
        let mut expected_cred = ComplexCredential {
            sub_creds: vec![],
            num_shares: 0,
            threshold: 1,
        };

        // 1. Pass all kinds of credentials
        // 1a. Regular password
        args.push("-p");
        ui = ui.expect_prompt("Enter password", Ok("abc"));
        ui = ui.expect_prompt("Re-enter password", Ok("abc"));
        expected_cred
            .sub_creds
            .push((1, Credential::Password("abc".into())));
        expected_cred.num_shares += 1;

        // 1b. Named password with key-shares
        args.extend_from_slice(&["--key-shares", "3", "--password-named", "Master"]);
        ui = ui.expect_prompt("Enter password [Master]", Ok("abc1"));
        ui = ui.expect_prompt("Re-enter password", Ok("abc1"));
        expected_cred
            .sub_creds
            .push((3, Credential::Password("abc1".into())));
        expected_cred.num_shares += 3;

        // 1c. Password file with multiple passwords
        let mut pwd_file = tempfile::NamedTempFile::new()?;
        let pwd_file_path = pwd_file.path().to_str().unwrap().to_string();
        write!(pwd_file, "pass1\npass2")?;
        pwd_file.flush()?;
        args.extend_from_slice(&["--password-file", &pwd_file_path]);
        expected_cred.sub_creds.extend_from_slice(&[
            (1, Credential::Password("pass1".into())),
            (1, Credential::Password("pass2".into())),
        ]);
        expected_cred.num_shares += 2;

        // 1d. Threshold + key-shares + group + 'all keys required' flag
        args.extend_from_slice(&["-t", "5", "--key-shares", "2", "-(", "-a"]);
        args_end.extend_from_slice(&["-)"]);
        expected_cred.threshold = 5;
        let mut expected_group_cred = ComplexCredential {
            sub_creds: vec![],
            num_shares: 0,
            threshold: 0,
        };

        // 1f. Symmetric key file
        let sym_key = b"781F2372532d6B9Df2ea939339b55e8E";
        let mut sym_key_file = tempfile::NamedTempFile::new()?;
        let sym_key_file_path = sym_key_file.path().to_str().unwrap().to_string();
        write!(sym_key_file, "{}", util::to_hex_string(sym_key))?;
        sym_key_file.flush()?;
        args.extend_from_slice(&["--symmetric-key", &sym_key_file_path]);
        expected_group_cred
            .sub_creds
            .push((1, Credential::SymmetricKey(*sym_key)));
        expected_group_cred.num_shares += 1;

        // 1f. Public key file and text
        let public_key1 = b"3196bcbeb4fE883c995c3279ac0d63c3";
        let public_key2 = b"9503ae1E81E0e20Fce2c3F28d5939837";
        let mut public_key_file = tempfile::NamedTempFile::new()?;
        let public_key_file_path = public_key_file.path().to_str().unwrap().to_string();
        write!(public_key_file, "{}", util::to_hex_string(public_key1))?;
        public_key_file.flush()?;
        let public_key2_str = util::to_hex_string_checksummed(public_key2);
        args.extend_from_slice(&[
            "--public-key",
            &public_key_file_path,
            "--public-key-text",
            &public_key2_str,
        ]);
        expected_group_cred.sub_creds.extend_from_slice(&[
            (1, Credential::PublicKey(*public_key1)),
            (1, Credential::PublicKey(*public_key2)),
        ]);
        expected_group_cred.num_shares += 2;

        // (finalize 1d)
        expected_group_cred.threshold = expected_group_cred.num_shares;
        expected_cred
            .sub_creds
            .push((2, Credential::Complex(expected_group_cred)));
        expected_cred.num_shares += 2;

        // 2. Check credentials are parsed correctly.
        args_end.reverse();
        args.append(&mut args_end);
        let matches = options.parse(args)?;
        let cred = get_encrypt_credential(&matches, false, &ui)?;
        assert_eq!(cred, expected_cred);
        ui.expect_all_prompts_asked();
        Ok(())
    }

    // More Tests:
    //  * Encryption parsing failure modes
    //    Empty files; invalid formats.
    //  * Decryption parsing failure modes

    //    #[test]
    //    fn test_read_password() -> Fallible<()> {
    //        // 1. retries, 2. empty password, 3. non-tty input, etc.
    //        unimplemented!();
    //    }

    //    #[test]
    //    fn test_checksumming() -> Fallible<()> {
    //        // 1. invalid checksum, 2. --skip-checksum-check
    //        unimplemented!();
    //    }
}
