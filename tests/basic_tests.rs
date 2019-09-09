#![deny(bare_trait_objects)]

use failure::Fallible;
use rand::{thread_rng, RngCore};
use rypt::cli::DEFAULT_FILE_SUFFIX;
use std::fs;
use std::io::Write;
use util::CommandExt;

mod util;

#[test]
fn help_message() -> Fallible<()> {
    let output = util::main_cmd(&["-h"])?.output()?;
    assert!(output.status.success());
    let output = std::str::from_utf8(&output.stdout)?;

    assert!(output.starts_with("Usage: "));
    assert!(output.contains("Commands"));
    assert!(output.contains("Home page and documentation"));
    Ok(())
}

#[test]
fn print_version() -> Fallible<()> {
    let output = util::main_cmd(&["--version"])?.output()?;
    assert!(output.status.success());
    let output = std::str::from_utf8(&output.stdout)?;

    assert!(output.starts_with("rypt"));
    assert!(output.contains("libsodium"));
    Ok(())
}

fn simple_file_encrypt_decrypt(
    rng: &mut dyn RngCore,
    extension: &str,
    algorithm_args: &[&str],
) -> Fallible<()> {
    let (temp_file_path, contents) = util::create_temp_file(rng, extension)?;
    let ext = if extension.is_empty() {
        DEFAULT_FILE_SUFFIX.to_string()
    } else {
        format!("{}.{}", extension, DEFAULT_FILE_SUFFIX)
    };
    let temp_file_path_enc = temp_file_path.with_extension(ext);
    let secret_key = util::to_hex_string(util::random_bytes(rng, 32));
    dbg!(&temp_file_path);
    dbg!(&temp_file_path_enc);
    dbg!(&secret_key);
    let mut secret_key_file = tempfile::NamedTempFile::new()?;
    secret_key_file.write_all(secret_key.as_bytes())?;
    let secret_key_file_path = secret_key_file.path().to_str().unwrap();

    let args = &[
        "--symmetric-key",
        secret_key_file_path,
        "--discard-inputs",
        temp_file_path.to_str().unwrap(),
    ];
    let output = util::main_cmd(&[algorithm_args, args].concat())?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    let output = util::main_cmd(&[
        "-d",
        "--symmetric-key",
        secret_key_file_path,
        "--discard-inputs",
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);
    assert!(!temp_file_path_enc.exists()); // Encrypted file should be removed.

    Ok(())
}

#[test]
fn simple_file_encrypt_decrypt_with_extension_aes256gcm() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "bin", &["--fast"])
}

#[test]
fn simple_file_encrypt_decrypt_without_extension_aes256gcm() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "", &["--fast"])
}

#[test]
fn simple_file_encrypt_decrypt_with_extension_xchacha20() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "bin", &[])
}

#[test]
fn simple_file_encrypt_decrypt_without_extension_xchacha20() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "", &[])
}

#[test]
fn encrypt_decrypt_stdio() -> Fallible<()> {
    let plaintext = b"abc123";
    let mut password_file = tempfile::NamedTempFile::new()?;
    password_file.write_all(b"abc")?;
    let password_file_path = password_file.path().to_str().unwrap();

    let output = util::main_cmd(&["--password-file", password_file_path])?
        .stdin_buf(plaintext)?
        .output()?;
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());
    let ciphertext = output.stdout;

    let output = util::main_cmd(&["-d", "--password-file", password_file_path])?
        .stdin_buf(ciphertext)?
        .output()?;

    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());
    assert_eq!(output.stdout, plaintext);

    Ok(())
}

#[test]
fn public_key_file_encrypt_decrypt() -> Fallible<()> {
    let rng = &mut thread_rng();

    // 1. Generate public/private key pair
    let private_key_path = util::temp_filename(rng, "key");
    let public_key_path = private_key_path.with_extension("pub");
    let output = util::main_cmd(&["-g", private_key_path.to_str().unwrap()])?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    assert!(private_key_path.exists());
    assert!(public_key_path.exists());

    // 2. Generate a file to encrypt
    let (temp_file_path, contents) = util::create_temp_file(rng, "")?;
    let temp_file_path_enc = temp_file_path.with_extension(DEFAULT_FILE_SUFFIX.to_string());

    // 3. Encrypt the file using public key
    let output = util::main_cmd(&[
        "--public-key",
        public_key_path.to_str().unwrap(),
        "--discard-inputs",
        temp_file_path.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    // 3. Decrypt the file using private key
    let output = util::main_cmd(&[
        "-d",
        "--private-key",
        private_key_path.to_str().unwrap(),
        "--discard-inputs",
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);
    assert!(!temp_file_path_enc.exists()); // Encrypted file should be removed.

    Ok(())
}

#[test]
fn threshold_encrypt_decrypt() -> Fallible<()> {
    let rng = &mut thread_rng();

    // 1. Generate 5 password files
    let mut password_paths = vec![];
    for _ in 0..5 {
        let path = util::temp_filename(rng, "password");
        let password = util::to_hex_string(util::random_bytes(rng, 16));
        fs::write(&path, password)?;
        password_paths.push(path);
    }

    // 2. Generate a file to encrypt
    let (temp_file_path, contents) = util::create_temp_file(rng, "")?;
    let temp_file_path_enc = temp_file_path.with_extension(DEFAULT_FILE_SUFFIX.to_string());

    // 3. Encrypt the file using 5 passwords with 3 password threshold
    let mut args = vec![
        "--key-threshold",
        "3",
        "--discard-inputs",
        temp_file_path.to_str().unwrap(),
    ];
    for password_path in &password_paths {
        args.push("--password-file");
        args.push(password_path.to_str().unwrap());
    }
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    // 3. Try to decrypt the file using just 2 passwords - should fail
    let output = util::main_cmd(&[
        "-d",
        "--password-file",
        password_paths[2].to_str().unwrap(),
        "--password-file",
        password_paths[4].to_str().unwrap(),
        "--discard-inputs",
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?.contains("Invalid or insufficient credentials"));
    assert!(!output.status.success());

    // 4. Decrypt the file using 3 passwords - should succeed
    let output = util::main_cmd(&[
        "-d",
        "--password-file",
        password_paths[2].to_str().unwrap(),
        "--password-file",
        password_paths[4].to_str().unwrap(),
        "--password-file",
        password_paths[0].to_str().unwrap(),
        "--discard-inputs",
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);
    assert!(!temp_file_path_enc.exists()); // Encrypted file should be removed.

    Ok(())
}

#[test]
fn max_threshold_encrypt_decrypt() -> Fallible<()> {
    let rng = &mut thread_rng();

    // 1. Generate 5 password files
    let mut password_paths = vec![];
    for _ in 0..5 {
        let path = util::temp_filename(rng, "password");
        let password = util::to_hex_string(util::random_bytes(rng, 16));
        fs::write(&path, password)?;
        password_paths.push(path);
    }

    // 2. Generate a file to encrypt
    let (temp_file_path, contents) = util::create_temp_file(rng, "")?;
    let temp_file_path_enc = temp_file_path.with_extension(DEFAULT_FILE_SUFFIX.to_string());

    // 3. Encrypt the file using 5 passwords with all 5 password threshold
    let mut args = vec![
        "--key-threshold",
        "5",
        "--discard-inputs",
        temp_file_path.to_str().unwrap(),
    ];
    for password_path in &password_paths {
        args.push("--password-file");
        args.push(password_path.to_str().unwrap());
    }
    let output = util::main_cmd(args)?.output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    // 3. Try to decrypt the file using just 2 passwords - should fail
    let output = util::main_cmd(&[
        "-d",
        "--password-file",
        password_paths[2].to_str().unwrap(),
        "--password-file",
        password_paths[4].to_str().unwrap(),
        "--discard-inputs",
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert!(std::str::from_utf8(&output.stderr)?.contains("Invalid or insufficient credentials"));
    assert!(!output.status.success());

    // 4. Decrypt the file using 5 passwords - should succeed
    let output = util::main_cmd(&[
        "-d",
        "--password-file",
        password_paths[2].to_str().unwrap(),
        "--password-file",
        password_paths[4].to_str().unwrap(),
        "--password-file",
        password_paths[0].to_str().unwrap(),
        "--password-file",
        password_paths[1].to_str().unwrap(),
        "--password-file",
        password_paths[3].to_str().unwrap(),
        "--discard-inputs",
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);
    assert!(!temp_file_path_enc.exists()); // Encrypted file should be removed.

    Ok(())
}
