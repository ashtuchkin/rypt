use failure::Fallible;
use rand::{thread_rng, RngCore};
use rypt::cli::DEFAULT_FILE_SUFFIX;
use rypt::util::to_hex_string;
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
    assert!(output.contains("Options:"));
    assert!(output.contains("Home page and documentation"));
    Ok(())
}

fn simple_file_encrypt_decrypt(
    rng: &mut RngCore,
    extension: &str,
    algorithm: &str,
) -> Fallible<()> {
    let (temp_file_path, contents) = util::create_temp_file(rng, extension)?;
    let ext = if extension.is_empty() {
        DEFAULT_FILE_SUFFIX.to_string()
    } else {
        format!("{}.{}", extension, DEFAULT_FILE_SUFFIX)
    };
    let temp_file_path_enc = temp_file_path.with_extension(ext);
    let secret_key = to_hex_string(util::random_bytes(rng, 32));
    dbg!(&temp_file_path);
    dbg!(&temp_file_path_enc);
    dbg!(&secret_key);
    let mut secret_key_file = tempfile::NamedTempFile::new()?;
    secret_key_file.write_all(secret_key.as_bytes())?;
    let secret_key_file_path = secret_key_file.path().to_str().unwrap();

    let output = util::main_cmd(&[
        "--symmetric-key-file",
        secret_key_file_path,
        algorithm,
        temp_file_path.to_str().unwrap(),
    ])?
    .output()?;
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    let output = util::main_cmd(&[
        "-d",
        "--symmetric-key-file",
        secret_key_file_path,
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
    simple_file_encrypt_decrypt(&mut thread_rng(), "bin", "--fast")
}

#[test]
fn simple_file_encrypt_decrypt_without_extension_aes256gcm() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "", "--fast")
}

#[test]
fn simple_file_encrypt_decrypt_with_extension_xchacha20() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "bin", "-q")
}

#[test]
fn simple_file_encrypt_decrypt_without_extension_xchacha20() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "", "-q")
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
