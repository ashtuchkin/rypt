#![deny(bare_trait_objects)]

use failure::Fallible;
use rand::thread_rng;
use rypt::cli::DEFAULT_FILE_SUFFIX;
//use std::fs;
//use std::io::Write;
use std::io::Write;
use std::str::from_utf8;
use util::CommandExt;

mod util;

const PASSWORD_PROMPT_MARKER: &str = "Enter password";
const FILE_HEADER_MARKER: &str = " -> ";
const PROGRESS_MARKER: &str = "100.0 %";
const PROMPT_MARKER: &str = "Remove original file";

#[test]
fn basic_tty_usage_with_file() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _contents) = util::create_temp_file(rng, "")?;

    // Basic encoding from TTY
    let output = util::main_cmd(&[&temp_file_path])?
        .stdin_buf("password\npassword\ny\n")?   // Enter password twice, then remove original file
        .tty_override(true, true, true)
        .output()?;

    assert_eq!(from_utf8(&output.stdout)?, "");
    let stderr = from_utf8(&output.stderr)?;
    assert!(stderr.starts_with(PASSWORD_PROMPT_MARKER));
    assert!(stderr.contains(FILE_HEADER_MARKER));
    assert!(stderr.contains(PROGRESS_MARKER));
    assert!(stderr.contains(PROMPT_MARKER));
    assert!(output.status.success());

    // Basic decoding from TTY
    let output = util::main_cmd(&["-d", temp_file_path.with_extension(DEFAULT_FILE_SUFFIX).to_str().unwrap()])?
        .stdin_buf("password\ny\n")?   // Enter password once, then remove original file
        .tty_override(true, true, true)
        .output()?;

    assert_eq!(from_utf8(&output.stdout)?, "");
    let stderr = from_utf8(&output.stderr)?;
    assert!(stderr.starts_with(PASSWORD_PROMPT_MARKER));
    assert!(stderr.contains(FILE_HEADER_MARKER));
    assert!(stderr.contains(PROGRESS_MARKER));
    assert!(stderr.contains(PROMPT_MARKER));
    assert!(output.status.success());

    Ok(())
}

#[test]
fn quiet_operation() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _contents) = util::create_temp_file(rng, "")?;

    // Basic encoding from TTY, with quiet flag
    let output = util::main_cmd(&["-q", temp_file_path.to_str().unwrap()])?
        .stdin_buf("password\npassword\ny\n")?   // Enter password twice, then remove original file
        .tty_override(true, true, true)
        .output()?;

    assert_eq!(from_utf8(&output.stdout)?, "");
    let stderr = from_utf8(&output.stderr)?;
    assert!(stderr.starts_with(PASSWORD_PROMPT_MARKER));
    assert!(!stderr.contains(FILE_HEADER_MARKER));
    assert!(!stderr.contains(PROGRESS_MARKER));
    assert!(!stderr.contains(PROMPT_MARKER));
    assert!(output.status.success());

    Ok(())
}

#[test]
fn very_quiet_operation() -> Fallible<()> {
    let rng = &mut thread_rng();
    let (temp_file_path, _contents) = util::create_temp_file(rng, "")?;

    // Basic encoding from TTY, with 2 quiet flags
    let output = util::main_cmd(&["-qq", temp_file_path.to_str().unwrap()])?
        .tty_override(true, true, true)
        .output()?;

    assert_eq!(from_utf8(&output.stdout)?, "");
    assert_eq!(from_utf8(&output.stderr)?, "");
    assert!(!output.status.success()); // Not successful because the password can't be prompted

    // Same, but with password file
    let mut password_file = tempfile::NamedTempFile::new()?;
    password_file.write_all(b"abc")?;
    let password_file_path = password_file.path().to_str().unwrap();

    let output = util::main_cmd(&[
        "-qq",
        "--password-file",
        password_file_path,
        temp_file_path.to_str().unwrap(),
    ])?
    .tty_override(true, true, true)
    .output()?;

    assert_eq!(from_utf8(&output.stdout)?, "");
    assert_eq!(from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    Ok(())
}

#[test]
fn pipe_encoding_decoding() -> Fallible<()> {
    let mut password_file = tempfile::NamedTempFile::new()?;
    password_file.write_all(b"abc")?;
    let password_file_path = password_file.path().to_str().unwrap();
    let plaintext = b"abc123";

    // Basic encoding with stdin and stdout piped; stderr is still TTY
    let output = util::main_cmd(&["--password-file", password_file_path])?
        .stdin_buf(plaintext)?
        .tty_override(false, false, true)
        .output()?;

    // In this case, do no output.
    assert_eq!(from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    let ciphertext = output.stdout;
    assert_ne!(ciphertext.len(), 0);

    // Basic decoding from pipe
    let output = util::main_cmd(&["-d", "--password-file", password_file_path])?
        .stdin_buf(ciphertext)?
        .tty_override(false, false, true)
        .output()?;

    assert_eq!(&output.stdout, &plaintext);
    assert_eq!(from_utf8(&output.stderr)?, "");
    assert!(output.status.success());

    Ok(())
}

#[test]
fn pipe_tty_encoding_decoding() -> Fallible<()> {
    let password = "password";
    let plaintext = "abc123";

    // Basic encoding with TTY stdin; stderr is still TTY
    let output = util::main_cmd(&[] as &[&str])?
        .stdin_buf(format!("{}\n{}\n{}", password, password, plaintext))?
        .tty_override(true, false, true)
        .output()?;

    // We expect some output, but not progress or prompt
    let stderr = from_utf8(&output.stderr)?;
    assert!(stderr.starts_with(PASSWORD_PROMPT_MARKER));
    assert!(stderr.contains(FILE_HEADER_MARKER));
    assert!(!stderr.contains(PROGRESS_MARKER));
    assert!(!stderr.contains(PROMPT_MARKER));
    assert!(output.status.success());

    let ciphertext = output.stdout;
    assert_ne!(ciphertext.len(), 0);

    // Basic decoding from pipe to TTY
    let mut password_file = tempfile::NamedTempFile::new()?;
    write!(password_file, "{}\n", password)?;
    let password_file_path = password_file.path().to_str().unwrap();

    let output = util::main_cmd(&["-d", "--password-file", password_file_path])?
        .stdin_buf(ciphertext)?
        .tty_override(false, true, true)
        .output()?;

    assert_eq!(from_utf8(&output.stdout)?, plaintext);
    let stderr = from_utf8(&output.stderr)?;
    assert!(!stderr.starts_with(PASSWORD_PROMPT_MARKER));
    assert!(stderr.contains(FILE_HEADER_MARKER));
    assert!(!stderr.contains(PROGRESS_MARKER));
    assert!(!stderr.contains(PROMPT_MARKER));
    assert!(output.status.success());

    Ok(())
}
