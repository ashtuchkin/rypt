use failure::Fallible;
use getopts::Matches;

use crate::cli::credentials::get_credentials;
pub use crate::cli::credentials::Credential;
pub use crate::cli::help::{print_help, print_version};
use crate::cli::io_streams::get_input_output_streams;
use crate::io_streams::InputOutputStream;
use crate::runtime_env::RuntimeEnvironment;

mod credentials;
mod help;
mod io_streams;

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

#[derive(Debug)]
pub struct EncryptOptions {
    pub credentials: Vec<Credential>,
    pub fast_aead_algorithm: bool,
    pub associated_data: Vec<u8>,
    pub verbose: i32,
}

#[derive(Debug)]
pub struct DecryptOptions {
    pub credentials: Vec<Credential>,
    pub verbose: i32,
}

pub enum Command {
    Encrypt(Vec<InputOutputStream>, EncryptOptions),
    Decrypt(Vec<InputOutputStream>, DecryptOptions),
    Help,
    Version,
}

fn define_options() -> getopts::Options {
    let mut options = getopts::Options::new();

    // Modes / subcommands
    options
        .optflag("e", "encrypt", "encrypt files (default)")
        .optflag("d", "decrypt", "decrypt files")
        .optflag("h", "help", "display this short help and exit")
        .optflag("V", "version", "display version numbers and exit");

    // Common flags
    options
        .optflagmulti(
            "v",
            "verbose",
            "be verbose; specify twice for even more verbosity",
        )
        .optflagmulti("q", "quiet", "be quiet; skip unnecessary messages");

    // Credentials
    options
        .optopt(
            "",
            "prompt-passwords",
            "request N password(s) interactively from stdin; any one of them can decrypt the files",
            "N",
        )
        .optmulti(
            "",
            "password-file",
            "read password(s) from the file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "symmetric-key-file",
            "read 32-byte hex symmetric secret key(s) from the file, one per line",
            "FILENAME",
        );

    // Encryption/decryption flags
    options
        .optflag(
            "",
            "fast",
            "use a different encryption algorithm (AES256-GCM) that is faster, but supported only on newer x86 processors",
        )
        .optflag(
            "k",
            "keep-files",
            "don't delete original files on successful operation",
        )
        .optflag(
            "s",
            "stdout",
            "write to standard output; implies -k",
        )
        .optopt(
            "S",
            "suffix",
            &format!(
                "encrypted file suffix, defaults to \".{}\"",
                DEFAULT_FILE_SUFFIX
            ),
            ".suf",
        );
    options
}

#[derive(Clone, Copy)]
enum OperationMode {
    Encrypt,
    Decrypt,
    Help,
    Version,
}

const MODES: &[(&str, OperationMode); 4] = &[
    ("e", OperationMode::Encrypt),
    ("d", OperationMode::Decrypt),
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
    last_mode.unwrap_or(OperationMode::Encrypt)
}

pub fn parse_command_line(env: &RuntimeEnvironment) -> Fallible<Command> {
    let options = define_options();
    let matches = options.parse(&env.cmdline_args)?;
    let verbose = matches.opt_count("v") as i32 - matches.opt_count("q") as i32;

    // Figure out the mode: use the last mode argument, or Help/Encrypt by default.
    Ok(match get_mode(&matches, env.cmdline_args.is_empty()) {
        OperationMode::Encrypt => {
            let streams = get_input_output_streams(&matches, &env, verbose, true)?;
            let credentials = get_credentials(&matches, &env, true)?;
            let options = EncryptOptions {
                credentials,
                fast_aead_algorithm: matches.opt_present("fast"),
                associated_data: vec![],
                verbose,
            };
            Command::Encrypt(streams, options)
        }
        OperationMode::Decrypt => {
            let streams = get_input_output_streams(&matches, &env, verbose, false)?;
            let credentials = get_credentials(&matches, &env, false)?;
            let options = DecryptOptions {
                credentials,
                verbose,
            };
            Command::Decrypt(streams, options)
        }
        OperationMode::Help => Command::Help,
        OperationMode::Version => Command::Version,
    })
}
