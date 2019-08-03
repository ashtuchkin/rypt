use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use failure::{bail, ensure, Fallible};
use getopts::Matches;

use crate::cli::DEFAULT_FILE_SUFFIX;
use crate::io_streams::{InputOutputStream, InputStream, OutputStream};
use crate::RuntimeEnvironment;

pub(super) fn get_input_output_streams(
    matches: &Matches,
    env: &RuntimeEnvironment,
    is_encrypt: bool,
) -> Fallible<Vec<InputOutputStream>> {
    let stream_mode = matches.opt_present("s") || matches.free.is_empty() || matches.free == &["-"];

    Ok(if stream_mode {
        ensure!(
            matches.free.len() <= 1,
            "Streaming mode only allows a single input stream"
        );
        let input = match matches.free.first().map(String::as_str) {
            None | Some("-") => {
                if !is_encrypt && env.stdin_is_tty {
                    bail!("Encrypted data cannot be read from a terminal.");
                }
                InputStream::Stdin {
                    reader: env.stdin.replace(Box::new(std::io::empty())),
                }
            }
            Some(path) => InputStream::FileStream { path: path.into() },
        };

        if is_encrypt && env.stdout_is_tty {
            bail!("Encrypted data cannot be written to a terminal");
        }
        let output = OutputStream::Stdout {
            writer: env.stdout.replace(Box::new(std::io::sink())),
        };

        vec![InputOutputStream {
            input,
            output: Ok(output),
        }]
    } else {
        let extension = get_encrypted_file_extension(&matches);
        let remove_on_success = !matches.opt_present("k");

        matches
            .free
            .iter()
            .map(PathBuf::from)
            .map(|input_path| {
                let output_path = if is_encrypt {
                    add_extension(&input_path, &extension)
                } else {
                    remove_extension(&input_path, &extension)
                };
                InputOutputStream {
                    input: InputStream::File {
                        path: input_path,
                        remove_on_success,
                    },
                    output: output_path.map(|path| OutputStream::File { path }),
                }
            })
            .collect()
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
        &new_ext != extension,
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
