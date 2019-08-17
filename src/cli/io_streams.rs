use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use failure::{bail, ensure, Fallible};
use getopts::Matches;

use crate::cli::{CryptDirection, DEFAULT_FILE_SUFFIX};
use crate::io_streams::{InputOutputStream, InputStream, OutputStream};
use crate::{Reader, Writer};

pub(super) fn get_input_output_streams(
    matches: &Matches,
    crypt_direction: CryptDirection,
    stdin: &mut Option<Reader>,
    stdin_is_tty: bool,
    stdout: &mut Option<Writer>,
    stdout_is_tty: bool,
) -> Fallible<Vec<InputOutputStream>> {
    let stream_mode = matches.opt_present("s") || matches.free.is_empty() || matches.free == ["-"];

    Ok(if stream_mode {
        ensure!(
            matches.free.len() <= 1,
            "Streaming mode only supports a single input"
        );
        let input = match matches.free.first().map(String::as_str) {
            None | Some("-") => {
                if crypt_direction == CryptDirection::Decrypt && stdin_is_tty {
                    bail!("Encrypted data cannot be read from a terminal.");
                }
                InputStream::Stdin {
                    reader: stdin.take().unwrap(),
                }
            }
            // NOTE: In theory, `path` could point to stdin (e.g. '/dev/stdin'), in which case
            // ideally we need to check it's not a terminal if encrypting. This would break the
            // abstraction though, so we skip this check.
            Some(path) => InputStream::FileStream { path: path.into() },
        };

        if crypt_direction == CryptDirection::Encrypt && stdout_is_tty {
            bail!("Encrypted data cannot be written to a terminal");
        }
        let output = Ok(OutputStream::Stdout {
            writer: stdout.take().unwrap(),
        });

        vec![InputOutputStream { input, output }]
    } else {
        if matches.free.iter().any(|s| s.trim() == "-") {
            bail!("Stdin/stdout designator '-' can only be specified once and no other files can be processed at the same time.");
        }

        let extension = get_encrypted_file_extension(&matches);

        let io_streams: Vec<InputOutputStream> = matches
            .free
            .iter()
            .map(|input_path| {
                let input_path = PathBuf::from(input_path);
                let output_path = match crypt_direction {
                    CryptDirection::Encrypt => add_extension(&input_path, &extension),
                    CryptDirection::Decrypt => remove_extension(&input_path, &extension),
                };
                InputOutputStream {
                    input: InputStream::File { path: input_path },
                    output: output_path.map(|path| OutputStream::File { path }),
                }
            })
            .collect();

        // Bail right away if all files have failed.
        if io_streams.iter().all(|io_stream| io_stream.output.is_err()) {
            let io_stream = io_streams.into_iter().next().unwrap();
            return Err(io_stream.output.unwrap_err());
        }

        io_streams
    })
}

// Figure out the encrypted file extension, ensuring it doesn't start with a '.'
fn get_encrypted_file_extension(matches: &Matches) -> OsString {
    let mut extension = matches
        .opt_str("S")
        .unwrap_or_else(|| DEFAULT_FILE_SUFFIX.into());
    if extension.starts_with('.') {
        extension.remove(0);
    }
    OsString::from(extension)
}

fn add_extension(input_path: &Path, extension: &OsStr) -> Fallible<PathBuf> {
    let mut new_ext = input_path.extension().unwrap_or_default().to_os_string();
    ensure!(
        new_ext != extension,
        "{}: Unexpected file extension, skipping. Did you mean to decrypt (-d) this file?",
        input_path.to_string_lossy()
    );
    if !new_ext.is_empty() {
        new_ext.push(".");
    }
    new_ext.push(extension);
    Ok(input_path.with_extension(new_ext))
}

fn remove_extension(input_path: &Path, extension: &OsStr) -> Fallible<PathBuf> {
    ensure!(
        input_path.extension() == Some(&extension),
        "{}: Unexpected file extension, skipping.",
        input_path.to_string_lossy()
    );
    Ok(input_path.with_extension(""))
}
