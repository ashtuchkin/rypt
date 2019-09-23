use failure::{bail, ensure, Fallible};
use getopts::Matches;

use crate::cli::credentials::{get_decrypt_credentials, get_encrypt_credential};
use crate::cli::io_streams::get_input_output_streams;
use crate::cli::key_management::get_keypair_streams;
use crate::commands::{
    Command, CryptDirectionOpts, CryptOptions, DecryptOptions, EncryptOptions,
    GenerateKeyPairOptions, InputCleanupPolicy,
};
use crate::io_streams::OutputStream;
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
            let (streams, plaintext_on_tty) = get_input_output_streams(
                &matches,
                crypt_direction,
                open_stdin,
                stdin_is_tty,
                open_stdout,
                stdout_is_tty,
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
                    plaintext_on_tty,
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
            Command::GenerateKeyPair(GenerateKeyPairOptions { streams })
        }
        OperationMode::Help => Command::Help(OutputStream::Stdout { open_stdout }),
        OperationMode::Version => Command::Version(OutputStream::Stdout { open_stdout }),
    })
}
