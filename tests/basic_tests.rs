use failure::Fallible;
use rand::{thread_rng, RngCore};
use rypt::util::to_hex_string;
use rypt::DEFAULT_FILE_SUFFIX;
use std::fs;
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

    let output = util::main_cmd(&[
        "--secret-key-unsafe",
        &secret_key,
        "--algorithm",
        algorithm,
        temp_file_path.to_str().unwrap(),
    ])?
    .output()?;
    assert!(output.status.success());
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    let output = util::main_cmd(&[
        "-d",
        "--secret-key-unsafe",
        &secret_key,
        temp_file_path_enc.to_str().unwrap(),
    ])?
    .output()?;
    assert!(output.status.success());
    assert_eq!(std::str::from_utf8(&output.stdout)?, "");
    assert_eq!(std::str::from_utf8(&output.stderr)?, "");

    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);
    assert!(!temp_file_path_enc.exists()); // Encrypted file should be removed.

    Ok(())
}

#[test]
fn simple_file_encrypt_decrypt_with_extension_aes256gcm() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "bin", "aes256gcm")
}

#[test]
fn simple_file_encrypt_decrypt_without_extension_aes256gcm() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "", "aes256gcm")
}

#[test]
fn simple_file_encrypt_decrypt_with_extension_xchacha20() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "bin", "xchacha20")
}

#[test]
fn simple_file_encrypt_decrypt_without_extension_xchacha20() -> Fallible<()> {
    simple_file_encrypt_decrypt(&mut thread_rng(), "", "xchacha20")
}

#[test]
fn encrypt_decrypt_stdio() -> Fallible<()> {
    let plaintext = b"abc123";
    let password = "abc";

    let output = util::main_cmd(&["--password-unsafe", password])?
        .stdin_buf(plaintext)?
        .output()?;
    assert!(output.status.success());
    let ciphertext = output.stdout;

    let output = util::main_cmd(&["-d", "--password-unsafe", password])?
        .stdin_buf(ciphertext)?
        .output()?;

    assert!(output.status.success());
    assert_eq!(output.stdout, plaintext);

    Ok(())
}
