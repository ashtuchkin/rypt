#![deny(bare_trait_objects)]

use failure::Fallible;
use rand::thread_rng;
use rypt::cli::DEFAULT_FILE_SUFFIX;
use std::fs;
use util::CommandExt;

mod util;

#[test]
fn symlinks_not_allowed() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _) = util::create_temp_file(rng, "")?;
    let symlink_file_path = temp_file_path.with_extension("link");

    util::symlink(&temp_file_path, &symlink_file_path)?;

    let secret_key_file_path = util::create_temp_file_secret(rng)?;

    // By default, symlinks should not be encrypted.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        symlink_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?.contains("Can't encrypt/decrypt a symlink"));
    assert!(!output.status.success());

    // Force should skip the check.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        "--force",
        symlink_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    Ok(())
}

#[cfg(unix)]
#[test]
fn hardlinks_not_allowed() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _) = util::create_temp_file(rng, "")?;
    let hardlink_file_path = temp_file_path.with_extension("link");

    fs::hard_link(&temp_file_path, &hardlink_file_path)?;

    let secret_key_file_path = util::create_temp_file_secret(rng)?;

    // By default, hardlinks should not be encrypted.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        hardlink_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?
        .contains("Can't encrypt/decrypt a file with hard links"));
    assert!(!output.status.success());

    // Force should skip the check.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        "--force",
        hardlink_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    Ok(())
}

#[cfg(unix)]
#[test]
fn overwrite_existing_files_not_allowed() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, contents) = util::create_temp_file(rng, "")?;
    let temp_file_path_enc = temp_file_path.with_extension(DEFAULT_FILE_SUFFIX);
    fs::write(&temp_file_path_enc, vec![1; contents.len() + 1_000_000])?;

    let secret_key_file_path = util::create_temp_file_secret(rng)?;

    // By default, we shouldn't overwrite existing files.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        temp_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?.contains("File exists"));
    assert!(!output.status.success());

    // Force should skip the check.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        "--force",
        temp_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    // And the file should be decrypted successfully.
    let args = &[
        "-d",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        "--force",
        temp_file_path_enc.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    // To the same contents.
    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);

    Ok(())
}

#[test]
fn extension_checks_encryption() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _) = util::create_temp_file(rng, DEFAULT_FILE_SUFFIX)?;
    let temp_file_path_enc = temp_file_path.with_extension(format!("{0}.{0}", DEFAULT_FILE_SUFFIX));
    let secret_key_file_path = util::create_temp_file_secret(rng)?;

    // By default, we shouldn't try to encode a file with ".rypt" extension.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        temp_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?.contains("File already has encrypted extension"));
    assert!(!output.status.success());

    // Force should skip the check.
    let args = &[
        "--force",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        temp_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    // Check we actually encoded that file.
    assert!(temp_file_path_enc.exists());

    Ok(())
}

#[test]
fn extension_checks_decryption() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _) = util::create_temp_file(rng, "")?;
    let temp_file_path_enc = temp_file_path.with_extension(DEFAULT_FILE_SUFFIX);
    let secret_key_file_path = util::create_temp_file_secret(rng)?;

    // Initially, encrypt a file.
    let args = &[
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        temp_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    // Rename encrypted file to a different extension
    let temp_file_path2 = temp_file_path.with_extension("other");
    fs::rename(&temp_file_path_enc, &temp_file_path2)?;

    // By default, we shouldn't try to decode a file with no ".rypt" extension.
    let args = &[
        "-d",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        temp_file_path2.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(
        std::str::from_utf8(&output.stderr)?.contains("File doesn't have an encrypted extension")
    );
    assert!(!output.status.success());

    // Even --force shouldn't help.
    let args = &[
        "-d",
        "--force",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
        temp_file_path2.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(
        std::str::from_utf8(&output.stderr)?.contains("File doesn't have an encrypted extension")
    );
    assert!(!output.status.success());

    Ok(())
}

#[test]
fn write_binary_data_to_terminal_not_allowed() -> Fallible<()> {
    let rng = &mut thread_rng();
    let secret_key_file_path = util::create_temp_file_secret(rng)?;
    let plaintext = util::random_bytes(rng, 1_000_000);

    // Writing encrypted data to terminal is not allowed.
    let args = &["--symmetric-key", secret_key_file_path.to_str().unwrap()];
    let output = util::main_cmd(args)?
        .tty_override(true, true, true)
        .stdin_buf(&plaintext)?
        .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?
        .contains("Encrypted data cannot be written to a terminal"));
    assert!(!output.status.success());

    // .. but is fine if enforced.
    let args = &[
        "-f",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?
        .tty_override(true, true, true)
        .stdin_buf(&plaintext)?
        .output()?;
    assert_ne!(output.stdout.len(), 0);
    assert!(std::str::from_utf8(&output.stderr)?.contains("(stdin) -> (stdout)"));
    assert!(output.status.success());

    // Check it's a correct output.
    let ciphertext = output.stdout;
    let args = &[
        "-d",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?.stdin_buf(&ciphertext)?.output()?;
    assert_eq!(output.stdout, plaintext);
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    Ok(())
}

#[test]
fn read_binary_data_from_terminal_not_allowed() -> Fallible<()> {
    let rng = &mut thread_rng();
    let secret_key_file_path = util::create_temp_file_secret(rng)?;
    let plaintext = util::random_bytes(rng, 1_000_000);

    // First, encode the plaintext.
    let args = &["--symmetric-key", secret_key_file_path.to_str().unwrap()];
    let output = util::main_cmd(args)?.stdin_buf(&plaintext)?.output()?;
    assert_ne!(output.stdout.len(), 0);
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());
    let ciphertext = output.stdout;

    // Decoding data from terminal is not allowed.
    let args = &[
        "-d",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?
        .tty_override(true, true, true)
        .stdin_buf(&ciphertext)?
        .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?
        .contains("Encrypted data cannot be read from a terminal"));
    assert!(!output.status.success());

    // .. but is fine if enforced.
    let args = &[
        "-f",
        "-d",
        "--symmetric-key",
        secret_key_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(args)?
        .tty_override(true, true, true)
        .stdin_buf(&ciphertext)?
        .output()?;
    assert_eq!(output.stdout, plaintext);
    assert!(std::str::from_utf8(&output.stderr)?.contains("(stdin) -> (stdout)"));
    assert!(output.status.success());

    Ok(())
}
