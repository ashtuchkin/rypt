use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use failure::{bail, ensure, Fallible};

use crate::crypto::{PrivateKey, PublicKey, AEAD_KEY_LEN};
use crate::runtime_env::RuntimeEnvironment;
use crate::{util, PKG_NAME, PKG_VERSION};
use std::convert::TryInto;

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

#[derive(Debug, Copy, Clone)]
pub enum OperationMode {
    Encrypt,
    Decrypt,
}

#[derive(Debug)]
pub struct InputOutputStream {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub remove_input_on_success: bool,
}

pub enum Credential {
    Password(String),
    SecretKey([u8; AEAD_KEY_LEN]),
    PublicKey(PublicKey),   // Only valid for encryption
    PrivateKey(PrivateKey), // Only valid for decryption
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Credential::Password(_) => write!(f, "Password")?,
            Credential::SecretKey(_) => write!(f, "SecretKey")?,
            Credential::PublicKey(_) => write!(f, "PublicKey")?,
            Credential::PrivateKey(_) => write!(f, "PrivateKey")?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Options {
    pub mode: OperationMode,
    pub fast_aead_algorithm: bool,
    pub credentials: Vec<Credential>,
    pub associated_data: Vec<u8>,
    pub verbose: i32,
}

pub fn parse_command_line(
    env: &RuntimeEnvironment,
) -> Fallible<(Option<Options>, Vec<Fallible<InputOutputStream>>)> {
    let mut options = getopts::Options::new();
    options
        .optflag("e", "encrypt", "force encryption mode (default)")
        .optflag("d", "decrypt", "force decryption mode")
        .optopt(
            "",
            "secret-key-unsafe",
            "32 byte hex-encoded secret key, to be used instead of password (not recommended)",
            "SECRET_KEY",
        )
        .optopt(
            "",
            "password-unsafe",
            "provide password directly (not recommended)",
            "PASSWORD",
        )
        .optflag(
            "",
            "fast",
            "choose a faster, x86-specific encryption algorithm (AES256-GCM)",
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
        )
        .optflagmulti(
            "v",
            "verbose",
            "be verbose; specify twice for even more verbose",
        )
        .optflag("h", "help", "display this short help and exit")
        .optflag("V", "version", "display the version numbers and exit");

    let matches = options.parse(&env.cmdline_args)?;

    // Process help and version right here.
    if matches.opt_present("h") || (env.cmdline_args.is_empty() && env.stdin_is_tty) {
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
        return Ok(Default::default());
    } else if matches.opt_present("V") {
        let mut stdout = env.stdout.replace(Box::new(io::sink()));
        writeln!(stdout, "{} {}", PKG_NAME, PKG_VERSION)?;
        let libsodium_version =
            unsafe { std::ffi::CStr::from_ptr(libsodium_sys::sodium_version_string()) };
        writeln!(stdout, "libsodium {}", libsodium_version.to_str()?)?;
        return Ok(Default::default());
    }

    // Figure out the mode: use the last mode-related argument, or Encrypt by default.
    const MODES: &[(&str, OperationMode); 2] =
        &[("e", OperationMode::Encrypt), ("d", OperationMode::Decrypt)];

    let mode: OperationMode = MODES
        .iter()
        .flat_map(|(cmdline_arg, mode)| {
            matches
                .opt_positions(cmdline_arg)
                .into_iter()
                .map(move |pos| (pos, *mode))
        })
        .max_by_key(|(pos, _)| *pos)
        .unwrap_or((0, OperationMode::Encrypt))
        .1;

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
            let (output_path, remove_input_on_success) =
                get_output_path(&input_path, mode, &suffix, &env)?;
            Ok(InputOutputStream {
                input_path,
                output_path,
                remove_input_on_success,
            })
        })
        .collect();

    let mut credentials: Vec<Credential> = vec![];

    let secret_key = matches.opt_str("secret-key-unsafe");
    if let Some(s) = secret_key {
        let key_res: Result<[u8; AEAD_KEY_LEN], _> =
            util::try_parse_hex_string(&s)?.as_slice().try_into();
        match key_res {
            Ok(key) => credentials.push(Credential::SecretKey(key)),
            Err(_) => bail!("Invalid secret key size, expected {} bytes", AEAD_KEY_LEN),
        }
    };

    if let Some(password) = matches.opt_str("password-unsafe") {
        credentials.push(Credential::Password(password));
    }

    Ok((
        Some(Options {
            mode,
            fast_aead_algorithm: matches.opt_present("fast"),
            credentials,
            verbose: matches.opt_count("v") as i32,
            associated_data: vec![],
        }),
        streams,
    ))
}

fn get_output_path(
    input_path: &Path,
    mode: OperationMode,
    suffix: &OsString,
    env: &RuntimeEnvironment,
) -> Fallible<(PathBuf, bool)> {
    if input_path.to_str() == Some("-") {
        match mode {
            OperationMode::Encrypt => ensure!(
                !env.stdout_is_tty,
                "Encrypted data cannot be written to a terminal"
            ),
            OperationMode::Decrypt => ensure!(
                !env.stdin_is_tty,
                "Encrypted data cannot be read from a terminal."
            ),
        };
        Ok((PathBuf::from("-"), false))
    } else {
        match mode {
            OperationMode::Encrypt => {
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
            OperationMode::Decrypt => {
                ensure!(
                    input_path.extension() == Some(&suffix),
                    "{}: Unexpected file extension, skipping.",
                    input_path.to_string_lossy()
                );
                Ok((input_path.with_extension(""), true))
            }
        }
    }
}
