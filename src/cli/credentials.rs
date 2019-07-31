use std::convert::TryInto;
use std::fs;

use failure::{ensure, format_err, Fallible, ResultExt};
use getopts::Matches;

use crate::cli::Credential;
use crate::util::try_parse_hex_string;
use crate::RuntimeEnvironment;

pub(super) fn get_credentials(
    matches: &Matches,
    env: &RuntimeEnvironment,
    is_encrypt: bool,
) -> Fallible<Vec<Credential>> {
    let mut credentials = vec![];

    // Read the password files
    for filename in matches.opt_strs("password-file") {
        let creds = read_password_file(&filename)
            .with_context(|e| format!("Error reading password file {}: {}", filename, e))?;
        credentials.extend(creds);
    }

    // Read symmetric key files
    for filename in matches.opt_strs("symmetric-key-file") {
        let creds = read_symmetric_key_file(&filename)
            .with_context(|e| format!("Error reading symmetric key file {}: {}", filename, e))?;
        credentials.extend(creds);
    }

    // Interactively prompt for passwords (must be the last block)
    let default_num_passwords = if credentials.is_empty() { 1 } else { 0 };
    let num_passwords = matches.opt_get_default("prompt-passwords", default_num_passwords)?;
    for password_idx in 0..num_passwords {
        let password = read_password_interactively(env, is_encrypt, password_idx, num_passwords)?;
        credentials.push(password);
    }

    ensure!(credentials.len() > 0, "No credentials provided");
    Ok(credentials)
}

fn read_password_file(filename: &str) -> Fallible<Vec<Credential>> {
    let mut credentials = vec![];
    for line in fs::read_to_string(filename)?.lines() {
        let password = line.trim();
        if !password.is_empty() {
            credentials.push(Credential::Password(password.to_owned()));
        }
    }
    ensure!(
        credentials.len() > 0,
        "File does not contain any passwords."
    );
    Ok(credentials)
}

fn read_symmetric_key_file(filename: &str) -> Fallible<Vec<Credential>> {
    let mut credentials = vec![];
    for (line_idx, line) in fs::read_to_string(filename)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let key = try_parse_hex_string(line)
            .map_err(|e| format_err!("{} on line {}", e, line_idx))?
            .as_slice()
            .try_into()
            .map_err(|_| {
                format_err!("Invalid key length on line {}; must be 32 bytes", line_idx)
            })?;
        credentials.push(Credential::SymmetricKey(key));
    }
    ensure!(credentials.len() > 0, "File does not contain any keys.");
    Ok(credentials)
}

fn read_password(env: &RuntimeEnvironment, message: &str) -> Fallible<String> {
    let mut stderr = env.stderr.borrow_mut();
    let mut stdin = env.stdin.borrow_mut();
    write!(stderr, "{}", message)?;
    let res = termion::input::TermRead::read_passwd(&mut stdin.as_mut(), &mut stderr.as_mut());
    writeln!(stderr)?;

    // NOTE: `res` will be Ok(None) if user entered Ctrl-C or Ctrl-D. We translate it to 'canceled'.
    Ok(res?.ok_or_else(|| format_err!("Operation canceled."))?)
}

fn read_password_interactively(
    env: &RuntimeEnvironment,
    is_encrypt: bool,
    password_idx: usize,
    num_passwords: usize,
) -> Fallible<Credential> {
    ensure!(
        env.stdin_is_tty && env.stderr_is_tty,
        "Can't read password from a non-TTY stdin. \
         Use '--password-file /dev/stdin' if you really know what you're doing."
    );

    let suffix = if num_passwords > 1 {
        format!(" [{}/{}]", password_idx + 1, num_passwords)
    } else {
        "".into()
    };
    loop {
        let message = format!("Enter password{}: ", suffix);
        let password = read_password(&env, &message)?;

        // When encrypting, we request the same password twice to ensure it's entered correctly.
        if is_encrypt {
            let password_again = read_password(&env, "Enter password again: ")?;
            if password_again != password {
                let mut stderr = env.stderr.borrow_mut();
                writeln!(stderr, "Passwords didn't match, try again.")?;
                continue;
            }
        }

        return Ok(Credential::Password(password));
    }
}
