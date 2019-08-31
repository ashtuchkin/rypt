use failure::Fallible;
use getopts::Matches;

use crate::cli::credentials::{get_decrypt_credentials, get_encrypt_credential};
use crate::cli::io_streams::get_input_output_streams;
use crate::cli::key_management::get_keypair_streams;
pub use crate::cli::options::define_options;
use crate::commands::{
    Command, CryptDirectionOpts, CryptOptions, DecryptOptions, EncryptOptions,
    GenerateKeyPairOptions, InputCleanupPolicy,
};
use crate::io_streams::OutputStream;
use crate::runtime_env::RuntimeEnvironment;
use crate::ui::{BasicUI, UI};

mod credentials;
mod io_streams;
mod key_management;
mod options;

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

fn get_mode(matches: &Matches, no_args_provided: bool) -> OperationMode {
    if no_args_provided {
        return OperationMode::Help;
    }

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
    RuntimeEnvironment {
        program_name,
        cmdline_args,
        stdin,
        stdout,
        stderr,
        stdin_is_tty,
        stdout_is_tty,
        stderr_is_tty,
    }: RuntimeEnvironment,
) -> Fallible<(Command, impl UI)> {
    let mut ui = BasicUI::from_streams(&program_name, stdin, stdin_is_tty, stderr, stderr_is_tty);

    let command_res = (|| -> Fallible<Command> {
        let options = define_options();
        let matches = options.parse(&cmdline_args)?;
        let mut verbosity = matches.opt_count("v") as i32 - matches.opt_count("q") as i32;
        if stdin_is_tty && stderr_is_tty {
            // Increase verbosity when being used interactively.
            verbosity += 1;
        }
        ui.set_verbosity(verbosity);

        // Callbacks that return stdin/stdout when called. Used to create InputStream/OutputStream
        let ui_stdin = ui.ref_input_opt();
        let open_stdin = Box::new(move || Ok(ui_stdin.borrow_mut().take().unwrap()));
        let open_stdout = Box::new(move || Ok(stdout));

        // Figure out the mode: use the last mode argument, or Help/Encrypt by default.
        let no_args_provided = cmdline_args.is_empty() && stdout_is_tty;
        let command = match get_mode(&matches, no_args_provided) {
            OperationMode::Crypt(crypt_direction) => {
                let (streams, plaintext_on_tty) = get_input_output_streams(
                    &matches,
                    crypt_direction,
                    open_stdin,
                    stdin_is_tty,
                    open_stdout,
                    stdout_is_tty,
                )?;

                let input_cleanup_policy = if matches.opt_present("keep-input-files") {
                    InputCleanupPolicy::KeepFiles
                } else if matches.opt_present("delete-input-files") {
                    InputCleanupPolicy::DeleteFiles
                } else if stdin_is_tty {
                    InputCleanupPolicy::PromptUser
                } else {
                    InputCleanupPolicy::KeepFiles
                };

                Command::CryptStreams(
                    streams,
                    CryptOptions {
                        input_cleanup_policy,
                        plaintext_on_tty,
                    },
                    match crypt_direction {
                        CryptDirection::Encrypt => CryptDirectionOpts::Encrypt(EncryptOptions {
                            credential: get_encrypt_credential(&matches, &ui)?,
                            fast_aead_algorithm: matches.opt_present("fast"),
                            associated_data: vec![],
                        }),
                        CryptDirection::Decrypt => CryptDirectionOpts::Decrypt(DecryptOptions {
                            credentials: get_decrypt_credentials(&matches, &ui)?,
                        }),
                    },
                )
            }
            OperationMode::GenerateKeypair => {
                let streams = get_keypair_streams(&matches, open_stdout)?;
                Command::GenerateKeyPair(GenerateKeyPairOptions { streams })
            }
            OperationMode::Help => {
                Command::Help(OutputStream::Stdout { open_stdout }, program_name)
            }
            OperationMode::Version => Command::Version(OutputStream::Stdout { open_stdout }),
        };
        Ok(command)
    })();

    match command_res {
        Ok(command) => Ok((command, ui)),
        Err(err) => {
            ui.print_error(&err).ok();
            Err(err)
        }
    }
}
