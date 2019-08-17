use failure::Fallible;
use getopts::Matches;

use crate::cli::credentials::get_credentials;
use crate::cli::io_streams::get_input_output_streams;
use crate::cli::key_management::get_keypair_streams;
use crate::cli::options::define_options;
use crate::io_streams::{InputOutputStream, OutputStream};
use crate::runtime_env::RuntimeEnvironment;

pub use crate::cli::credentials::Credential;
pub use crate::cli::help::{print_help, print_version};
pub use crate::cli::ui::BasicUI;

mod credentials;
mod help;
mod io_streams;
mod key_management;
mod options;
mod ui;

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

#[derive(Debug)]
pub struct EncryptOptions {
    pub credentials: Vec<Credential>,
    pub fast_aead_algorithm: bool,
    pub key_threshold: Option<usize>,
    pub associated_data: Vec<u8>,
}

#[derive(Debug)]
pub struct DecryptOptions {
    pub credentials: Vec<Credential>,
}

#[derive(Debug)]
pub enum CryptDirectionOpts {
    Encrypt(EncryptOptions),
    Decrypt(DecryptOptions),
}

#[derive(Debug)]
pub enum InputCleanupPolicy {
    KeepFiles,
    DeleteFiles,
    PromptUser,
}

#[derive(Debug)]
pub struct CryptOptions {
    pub input_cleanup_policy: InputCleanupPolicy,
}

#[derive(Debug)]
pub struct KeyPairOutputStreams {
    pub public_key_stream: Option<OutputStream>,
    pub private_key_stream: OutputStream,
}

#[derive(Debug)]
pub struct GenerateKeyPairOptions {
    pub streams: Vec<KeyPairOutputStreams>,
}

#[derive(Debug)]
pub enum Command {
    CryptStreams(Vec<InputOutputStream>, CryptOptions, CryptDirectionOpts),
    GenerateKeyPair(GenerateKeyPairOptions),
    Help(OutputStream, String),
    Version(OutputStream),
}

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
) -> Fallible<(Command, BasicUI)> {
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

        // Figure out the mode: use the last mode argument, or Help/Encrypt by default.
        let no_args_provided = cmdline_args.is_empty() && stdout_is_tty;
        let command = match get_mode(&matches, no_args_provided) {
            OperationMode::Crypt(crypt_direction) => {
                let streams = get_input_output_streams(
                    &matches,
                    crypt_direction,
                    &mut ui.borrow_input_mut(),
                    stdin_is_tty,
                    &mut Some(stdout),
                    stdout_is_tty,
                )?;

                let credentials = get_credentials(&matches, crypt_direction, &ui)?;

                let input_cleanup_policy = if matches.opt_present("keep-input-files") {
                    InputCleanupPolicy::KeepFiles
                } else if matches.opt_present("cleanup-input-files") {
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
                    },
                    match crypt_direction {
                        CryptDirection::Encrypt => CryptDirectionOpts::Encrypt(EncryptOptions {
                            credentials,
                            fast_aead_algorithm: matches.opt_present("fast"),
                            associated_data: vec![],
                            key_threshold: matches.opt_get("threshold")?,
                        }),
                        CryptDirection::Decrypt => {
                            CryptDirectionOpts::Decrypt(DecryptOptions { credentials })
                        }
                    },
                )
            }
            OperationMode::GenerateKeypair => {
                let streams = get_keypair_streams(&matches, &mut Some(stdout))?;
                Command::GenerateKeyPair(GenerateKeyPairOptions { streams })
            }
            OperationMode::Help => {
                Command::Help(OutputStream::Stdout { writer: stdout }, program_name)
            }
            OperationMode::Version => Command::Version(OutputStream::Stdout { writer: stdout }),
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

pub fn should_delete_input_files(input_cleanup_policy: &InputCleanupPolicy, ui: &BasicUI) -> bool {
    match input_cleanup_policy {
        InputCleanupPolicy::KeepFiles => false,
        InputCleanupPolicy::DeleteFiles => true,
        InputCleanupPolicy::PromptUser => loop {
            match ui.read_prompt("Would you like to remove original files? [y/N]: ") {
                Ok(s) => match s.to_ascii_lowercase().as_str() {
                    "y" | "yes" => break true,
                    "" | "n" | "no" => break false,
                    _ => {
                        ui.print_interactive("Didn't get that, enter 'y' or 'n'.")
                            .ok();
                    }
                },
                Err(e) => {
                    ui.print_error(&e).ok();
                    break false;
                }
            }
        },
    }
}
