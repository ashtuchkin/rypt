use std::convert::TryInto;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use failure::{bail, ensure, Fallible};

use crate::crypto::{AEADKey, PrivateKey, PublicKey, AEAD_KEY_LEN};
use crate::runtime_env::RuntimeEnvironment;
use crate::{util, PKG_NAME, PKG_VERSION};
use getopts::Matches;

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

#[derive(Debug)]
pub struct InputOutputStream {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub remove_input_on_success: bool,
}

#[derive(Clone)]
pub enum Credential {
    Password(String),
    SymmetricKey(AEADKey),
    PublicKey(PublicKey),
    PrivateKey(PrivateKey),
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
    Encrypt(EncryptOptions, Vec<Fallible<InputOutputStream>>),
    Decrypt(DecryptOptions, Vec<Fallible<InputOutputStream>>),
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
        .optflagmulti("q", "quiet", "be quiet; skip all unnecessary chatter");

    // Encryption/decryption flags
    options
        .optmulti(
            "p",
            "password",
            "read password interactively or from file; use several times for multiple passwords",
            "FILENAME",
        )
        .optmulti(
            "",
            "symmetric-secret-key",
            "(advanced feature) read a 32-byte symmetric secret key from file",
            "FILENAME",
        )
        .optflag(
            "",
            "fast",
            "use a different encryption algorithm (AES256-GCM) that is faster, but supported only on newer x86 processors",
        )
        .optflag(
            "s",
            "stdout",
            "write to standard output and don't delete input files",
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

fn get_mode(matches: &Matches, is_empty: bool) -> OperationMode {
    if is_empty {
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

    // If no mode is given, calculate the default.
    last_mode.unwrap_or(OperationMode::Encrypt)
}

fn get_credentials(matches: &Matches) -> Fallible<Vec<Credential>> {
    let mut credentials = vec![];
    if let Some(password) = matches.opt_str("password") {
        credentials.push(Credential::Password(password));
    }

    let secret_key = matches.opt_str("symmetric-secret-key");
    if let Some(s) = secret_key {
        let key_res: Result<AEADKey, _> = util::try_parse_hex_string(&s)?.as_slice().try_into();
        match key_res {
            Ok(key) => credentials.push(Credential::SymmetricKey(key)),
            Err(_) => bail!("Invalid secret key size, expected {} bytes", AEAD_KEY_LEN),
        }
    }
    Ok(credentials)
}

fn get_input_output_streams(
    matches: &Matches,
    env: &RuntimeEnvironment,
    is_encrypt: bool,
) -> Vec<Fallible<InputOutputStream>> {
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
    let streams = input_paths
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
        .collect();
    streams
}

pub fn parse_command_line(env: &RuntimeEnvironment) -> Fallible<Command> {
    let options = define_options();
    let matches = options.parse(&env.cmdline_args)?;
    let verbose = matches.opt_count("v") as i32 - matches.opt_count("q") as i32;

    // Figure out the mode: use the last mode argument, or Help/Encrypt by default.
    Ok(match get_mode(&matches, env.cmdline_args.is_empty()) {
        OperationMode::Encrypt => Command::Encrypt(
            EncryptOptions {
                credentials: get_credentials(&matches)?,
                fast_aead_algorithm: matches.opt_present("fast"),
                associated_data: vec![],
                verbose,
            },
            get_input_output_streams(&matches, &env, true),
        ),
        OperationMode::Decrypt => Command::Decrypt(
            DecryptOptions {
                credentials: get_credentials(&matches)?,
                verbose,
            },
            get_input_output_streams(&matches, &env, false),
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
