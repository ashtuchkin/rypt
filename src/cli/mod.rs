use failure::{bail, ensure, Fallible};
use getopts::Matches;

use crate::cli::credentials::{get_decrypt_credentials, get_encrypt_credential};
use crate::cli::io_streams::get_input_output_streams;
use crate::cli::key_management::get_keypair_streams;
use crate::commands::{
    Command, CryptDirectionOpts, CryptOptions, DecryptOptions, EncryptOptions,
    GenerateKeyPairOptions, InputCleanupPolicy,
};
use crate::io_streams::{InputOutputStream, InputStream, OutputStream};
use crate::ui::UI;
use crate::{ReaderFactory, WriterFactory};
use std::ffi::OsStr;

mod credentials;
mod io_streams;
mod key_management;
pub mod options;

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

#[derive(Clone, Copy, PartialEq)]
enum CryptDirection {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, PartialEq)]
enum OperationMode {
    Crypt(CryptDirection),
    GenerateKeypair,
    Help,
    Version,
}

const MODES: &[(&str, OperationMode)] = &[
    ("e", OperationMode::Crypt(CryptDirection::Encrypt)),
    ("d", OperationMode::Crypt(CryptDirection::Decrypt)),
    ("g", OperationMode::GenerateKeypair),
    ("h", OperationMode::Help),
    ("V", OperationMode::Version),
];

fn get_mode(matches: &Matches) -> OperationMode {
    let last_mode = MODES
        .iter()
        .flat_map(|(cmdline_arg, mode)| {
            matches
                .opt_positions(cmdline_arg)
                .into_iter()
                .map(move |pos| (pos, *mode))
        })
        .max_by_key(|(pos, _)| *pos)
        .map(|(_, val)| val);

    // Encrypt is the default mode
    last_mode.unwrap_or(OperationMode::Crypt(CryptDirection::Encrypt))
}

pub fn parse_command_line(
    cmdline_args: &[impl AsRef<OsStr>],
    open_stdin: ReaderFactory,
    stdin_is_tty: bool,
    open_stdout: WriterFactory,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
    ui: &mut dyn UI,
) -> Fallible<Command> {
    let options = options::define_all_options();
    let matches = options.parse(cmdline_args)?;
    let verbosity = matches.opt_count("v") as i32 - matches.opt_count("q") as i32;
    ensure!(
        -2 <= verbosity && verbosity <= 2,
        "Too many -v or -q arguments; up to 2 allowed"
    );
    ui.set_verbosity(verbosity);
    let force = matches.opt_present("f");

    // Figure out the command type: use the last command type argument (Encrypt by default), or Help
    // if no arguments given.
    let mode = if cmdline_args.is_empty() && stdout_is_tty {
        OperationMode::Help
    } else {
        get_mode(&matches)
    };

    Ok(match mode {
        OperationMode::Crypt(crypt_direction) => {
            let streams = get_input_output_streams(
                &matches,
                crypt_direction,
                force,
                open_stdin,
                open_stdout,
            )?;

            check_and_adjust_ui_verbosity(
                ui,
                verbosity,
                &streams,
                crypt_direction,
                force,
                stdin_is_tty,
                stdout_is_tty,
                stderr_is_tty,
            )?;

            let input_cleanup_policy = match (
                matches.opt_present("keep-inputs"),
                matches.opt_present("discard-inputs"),
            ) {
                (true, true) => bail!("Can't have both --keep-inputs and --discard-inputs flags."),
                (true, false) => InputCleanupPolicy::KeepFiles,
                (false, true) => InputCleanupPolicy::DeleteFiles,
                (false, false) => InputCleanupPolicy::PromptUser,
            };

            Command::CryptStreams(
                streams,
                CryptOptions {
                    input_cleanup_policy,
                    force,
                },
                match crypt_direction {
                    CryptDirection::Encrypt => CryptDirectionOpts::Encrypt(EncryptOptions {
                        credential: get_encrypt_credential(&matches, force, ui)?,
                        fast_aead_algorithm: matches.opt_present("fast"),
                    }),
                    CryptDirection::Decrypt => CryptDirectionOpts::Decrypt(DecryptOptions {
                        credentials: get_decrypt_credentials(&matches, force, ui)?,
                    }),
                },
            )
        }
        OperationMode::GenerateKeypair => {
            let streams = get_keypair_streams(&matches, open_stdout)?;
            Command::GenerateKeyPair(GenerateKeyPairOptions { streams, force })
        }
        OperationMode::Help => Command::Help(OutputStream::Stdout { open_stdout }),
        OperationMode::Version => Command::Version(OutputStream::Stdout { open_stdout }),
    })
}

// Rules of verbosity adjustment:
// 1. Only adjust if verbosity is not provided directly via -v and -q flags (verbosity == 0)
// 2. Make output more verbose (verbosity == 1) if all of stdin, stdout, stderr are TTY - we take
//    that as a sign that we're being called from TTY. Otherwise, make it less verbose (-1).
//   2a. Exception - if stdin is used as decryption input or stdout is used as encryption
//       output (binary streams), ignore the fact that they are not TTY. We require user to redirect
//       these streams, so still make output more verbose if the remaining streams are TTY.
// 3. Show progress if output is verbose (item 2 above) and progress messages won't mess up with
//    TTY stdin/stdout. We do want to support e.g. encryption of messages that user types directly
//    (stdin is TTY), and progress messages would get in the way.
#[allow(clippy::too_many_arguments)]
fn check_and_adjust_ui_verbosity(
    ui: &mut dyn UI,
    verbosity: i32,
    streams: &[InputOutputStream],
    crypt_direction: CryptDirection,
    force: bool,
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    stderr_is_tty: bool,
) -> Fallible<()> {
    let mut stdin_is_data = false;
    let mut stdout_is_data = false;
    let mut stdin_is_binary = false;
    let mut stdout_is_binary = false;

    if streams.len() == 1 {
        if let InputStream::Stdin { .. } = streams[0].input {
            stdin_is_data = true;
            stdin_is_binary = crypt_direction == CryptDirection::Decrypt;
        }
        if let Ok(OutputStream::Stdout { .. }) = streams[0].output {
            stdout_is_data = true;
            stdout_is_binary = crypt_direction == CryptDirection::Encrypt;
        }
    }

    if stdin_is_tty && stdin_is_binary && !force {
        bail!("Encrypted data cannot be read from a terminal.");
    }
    if stdout_is_tty && stdout_is_binary && !force {
        bail!("Encrypted data cannot be written to a terminal.");
    }

    if verbosity == 0 {
        fn expected_tty(is_tty: bool, is_binary: bool) -> bool {
            is_tty || is_binary
        }

        fn not_mess_up_tty(is_tty: bool, is_data: bool) -> bool {
            !(is_data && is_tty)
        }

        let increase_verbosity = stderr_is_tty
            && expected_tty(stdin_is_tty, stdin_is_binary)
            && expected_tty(stdout_is_tty, stdout_is_binary);

        if increase_verbosity {
            ui.set_verbosity(1);
        } else {
            ui.set_verbosity(-1);
        }

        let show_progress_bar = increase_verbosity
            && not_mess_up_tty(stdin_is_tty, stdin_is_data)
            && not_mess_up_tty(stdout_is_tty, stdout_is_data);

        ui.set_progress_enabled(show_progress_bar);
    }

    Ok(())
}
