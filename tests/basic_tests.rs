use crate::util::to_os_strs;
use failure::Fallible;
use rand::prelude::*;
use rypt::util::to_hex_string;
use rypt::{RuntimeEnvironment, DEFAULT_FILE_SUFFIX};
use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::path::PathBuf;
use std::{env, fs};

mod util;

#[test]
fn help_message() -> Fallible<()> {
    let (mut stdout_reader, stdout_writer) = util::create_read_write_pipe();

    let exit_code = rypt::run(&RuntimeEnvironment {
        program_name: "example-nontrivial-rypt-name".into(),
        cmdline_args: to_os_strs(&["-h"]),
        stdout: Cell::new(Box::new(stdout_writer)),
        ..Default::default()
    });
    assert_eq!(exit_code, 0);

    let output = stdout_reader.read_all()?;
    assert!(output.starts_with("Usage: example-nontrivial-rypt-name [OPTION].. [FILE].."));
    assert!(output.contains("Options:"));
    assert!(output.contains("Home page and documentation"));
    Ok(())
}

fn create_temp_file(rng: &mut RngCore, extension: &str) -> Fallible<(PathBuf, Vec<u8>)> {
    let temp_file = env::temp_dir()
        .join(util::random_str(rng, 10))
        .with_extension(extension);
    let contents = util::random_bytes(rng, 10_000);
    fs::write(&temp_file, &contents)?;
    Ok((temp_file, contents))
}

fn simple_file_encoding_decoding(
    rng: &mut RngCore,
    extension: &str,
    algorithm: &str,
) -> Fallible<()> {
    let (temp_file_path, contents) = create_temp_file(rng, extension)?;
    let ext = if extension.is_empty() {
        DEFAULT_FILE_SUFFIX.to_string()
    } else {
        format!("{}.{}", extension, DEFAULT_FILE_SUFFIX)
    };
    let temp_file_path_enc = temp_file_path.with_extension(ext);
    let secret_key: OsString = to_hex_string(util::random_bytes(rng, 32)).into();
    dbg!(&temp_file_path);
    dbg!(&temp_file_path_enc);
    dbg!(&secret_key);

    let (mut stderr_reader, stderr_writer) = util::create_read_write_pipe();
    let exit_code = rypt::run(&RuntimeEnvironment {
        cmdline_args: vec![
            "--secret-key-unsafe".into(),
            secret_key.clone(),
            "--algorithm".into(),
            algorithm.into(),
            temp_file_path.clone().into(),
        ],
        stderr: RefCell::new(Box::new(stderr_writer)),
        ..Default::default()
    });
    let stderr = stderr_reader.read_all()?;
    assert_eq!(stderr, "".to_string());
    assert_eq!(exit_code, 0);

    assert!(temp_file_path_enc.exists());
    assert!(!temp_file_path.exists()); // Original file should be removed.

    let (mut stderr_reader, stderr_writer) = util::create_read_write_pipe();
    let exit_code = rypt::run(&RuntimeEnvironment {
        cmdline_args: vec![
            "-d".into(),
            "--secret-key-unsafe".into(),
            secret_key.clone(),
            temp_file_path_enc.clone().into(),
        ],
        stderr: RefCell::new(Box::new(stderr_writer)),
        ..Default::default()
    });
    let stderr = stderr_reader.read_all()?;
    assert_eq!(stderr, "".to_string());
    assert_eq!(exit_code, 0);

    let decoded_contents = fs::read(temp_file_path)?;
    assert_eq!(decoded_contents, contents);
    assert!(!temp_file_path_enc.exists());

    Ok(())
}

#[test]
fn simple_file_encoding_decoding_with_extension_aes256gcm() -> Fallible<()> {
    simple_file_encoding_decoding(&mut thread_rng(), "bin", "aes256gcm")
}

#[test]
fn simple_file_encoding_decoding_without_extension_aes256gcm() -> Fallible<()> {
    simple_file_encoding_decoding(&mut thread_rng(), "", "aes256gcm")
}

#[test]
fn simple_file_encoding_decoding_with_extension_xchacha20() -> Fallible<()> {
    simple_file_encoding_decoding(&mut thread_rng(), "bin", "xchacha20")
}

#[test]
fn simple_file_encoding_decoding_without_extension_xchacha20() -> Fallible<()> {
    simple_file_encoding_decoding(&mut thread_rng(), "", "xchacha20")
}
