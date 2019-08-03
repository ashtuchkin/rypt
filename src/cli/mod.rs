use std::io::{self, Write};

use failure::Fallible;
use getopts::Matches;

use crate::crypto::{AEADKey, PrivateKey, PublicKey};
use crate::io_streams::InputOutputStream;
use crate::runtime_env::RuntimeEnvironment;
use crate::{PKG_NAME, PKG_VERSION};

mod credentials;
mod io_streams;

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

pub enum Credential {
    Password(String),
    SymmetricKey(AEADKey),
    PublicKey(PublicKey),   // Only for encryption
    PrivateKey(PrivateKey), // Only for decryption
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Credential::Password(_) => write!(f, "Credential::Password"),
            Credential::SymmetricKey(_) => write!(f, "Credential::SymmetricKey"),
            Credential::PublicKey(_) => write!(f, "Credential::PublicKey"),
            Credential::PrivateKey(_) => write!(f, "Credential::PrivateKey"),
        }
    }
}

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
    Encrypt(EncryptOptions, Vec<InputOutputStream>),
    Decrypt(DecryptOptions, Vec<InputOutputStream>),
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
            "don't delete input files on successful encryption",
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
        OperationMode::Encrypt => Command::Encrypt(
            EncryptOptions {
                credentials: credentials::get_credentials(&matches, &env, true)?,
                fast_aead_algorithm: matches.opt_present("fast"),
                associated_data: vec![],
                verbose,
            },
            io_streams::get_input_output_streams(&matches, &env, true)?,
        ),
        OperationMode::Decrypt => Command::Decrypt(
            DecryptOptions {
                credentials: credentials::get_credentials(&matches, &env, false)?,
                verbose,
            },
            io_streams::get_input_output_streams(&matches, &env, false)?,
        ),
        OperationMode::Help => Command::Help,
        OperationMode::Version => Command::Version,
    })
}

pub fn print_help(env: &RuntimeEnvironment) -> Fallible<()> {
    let options = define_options();
    let mut stdout = env.stdout.replace(Box::new(io::sink()));
    writeln!(
        stdout,
        "\
Usage: {} [OPTION].. [FILE]..
Encrypt or decrypt FILEs

{}

With no FILE, or when FILE is -, read standard input.

Report bugs to Alexander Shtuchkin <ashtuchkin@gmail.com>.
Home page and documentation: <https://github.com/ashtuchkin/rypt>",
        env.program_name.to_string_lossy(),
        options.usage("").trim()
    )?;
    Ok(())
}

pub fn print_version(env: &RuntimeEnvironment) -> Fallible<()> {
    let mut stdout = env.stdout.replace(Box::new(io::sink()));
    writeln!(stdout, "{} {}", PKG_NAME, PKG_VERSION)?;
    let libsodium_version =
        unsafe { std::ffi::CStr::from_ptr(libsodium_sys::sodium_version_string()) };
    writeln!(stdout, "libsodium {}", libsodium_version.to_str()?)?;
    Ok(())
}
