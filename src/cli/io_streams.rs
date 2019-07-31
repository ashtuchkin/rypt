use std::ffi::OsString;
use std::path::{Path, PathBuf};

use failure::{ensure, Fallible};
use getopts::Matches;

use crate::cli::DEFAULT_FILE_SUFFIX;
use crate::RuntimeEnvironment;

#[derive(Debug)]
pub struct InputOutputStream {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub remove_input_on_success: bool,
}

pub type InputOutputStreams = Vec<Fallible<InputOutputStream>>;

pub(super) fn get_input_output_streams(
    matches: &Matches,
    env: &RuntimeEnvironment,
    is_encrypt: bool,
) -> InputOutputStreams {
    // Figure out the encrypted file suffix, ensuring it always starts with a '.'
    let mut suffix = matches
        .opt_str("S")
        .unwrap_or_else(|| DEFAULT_FILE_SUFFIX.into());
    if suffix.starts_with('.') {
        suffix.remove(0);
    }
    let suffix = OsString::from(suffix);

    // Figure out the input paths.
    let mut input_paths: Vec<PathBuf> = matches
        .free
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        })
        .collect();
    if input_paths.is_empty() {
        input_paths.push(PathBuf::from("-"));
    }
    input_paths
        .into_iter()
        .map(|input_path| {
            let (output_path, remove_input_on_success) = if is_encrypt {
                get_encrypt_output_path(&input_path, &suffix, &env)?
            } else {
                get_decrypt_output_path(&input_path, &suffix, &env)?
            };
            Ok(InputOutputStream {
                input_path,
                output_path,
                remove_input_on_success,
            })
        })
        .collect()
}

fn get_encrypt_output_path(
    input_path: &Path,
    suffix: &OsString,
    env: &RuntimeEnvironment,
) -> Fallible<(PathBuf, bool)> {
    if input_path.to_str() == Some("-") {
        ensure!(
            !env.stdout_is_tty,
            "Encrypted data cannot be written to a terminal"
        );
        Ok((PathBuf::from("-"), false))
    } else {
        let mut new_ext = input_path.extension().unwrap_or_default().to_os_string();
        ensure!(
            &new_ext != suffix,
            "{}: Unexpected file extension, skipping. Did you mean to decrypt (-d) this file?",
            input_path.to_string_lossy()
        );
        if !new_ext.is_empty() {
            new_ext.push(".");
        }
        new_ext.push(suffix);
        Ok((input_path.with_extension(new_ext), true))
    }
}

fn get_decrypt_output_path(
    input_path: &Path,
    suffix: &OsString,
    env: &RuntimeEnvironment,
) -> Fallible<(PathBuf, bool)> {
    if input_path.to_str() == Some("-") {
        ensure!(
            !env.stdin_is_tty,
            "Encrypted data cannot be read from a terminal."
        );
        Ok((PathBuf::from("-"), false))
    } else {
        ensure!(
            input_path.extension() == Some(&suffix),
            "{}: Unexpected file extension, skipping.",
            input_path.to_string_lossy()
        );
        Ok((input_path.with_extension(""), true))
    }
}
