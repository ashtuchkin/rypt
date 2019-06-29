#![warn(clippy::all)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::errors::MyError;
use crate::header::FileHeader;
use crate::progress::ProgressPrinter;
pub use crate::runtime_env::{Reader, RuntimeEnvironment, Writer};
use crate::streaming_core::stream_convert_to_completion;
use failure::{bail, Fallible, ResultExt};

mod encoding;
mod errors;
mod header;
mod key_derivation;
mod progress;
mod registry;
mod runtime_env;
mod streaming_core;
mod types;
pub mod util;

// See https://stackoverflow.com/a/27841363 for the full list.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");

pub const DEFAULT_FILE_SUFFIX: &str = "rypt";

#[derive(Debug, Copy, Clone)]
enum OperationMode {
    Auxiliary,
    Encrypt,
    Decrypt,
}

impl Default for OperationMode {
    fn default() -> Self {
        OperationMode::Auxiliary
    }
}

#[derive(Debug, Default)]
pub struct Options {
    mode: OperationMode,
    input_paths: Vec<PathBuf>,
    suffix: OsString, // File extension of encrypted files, must always start with "."
    password: Option<String>,
    secret_key: Option<String>,
    algorithm: Option<String>,
    verbose: i32,
}

fn open_streams(
    input_path: &Path,
    output_path: &Path,
    env: &RuntimeEnvironment,
) -> Fallible<(Reader, Writer, Option<usize>)> {
    let (input_stream, filesize): (Reader, Option<usize>) = match input_path.to_str() {
        Some("-") => (env.stdin.replace(Box::new(io::empty())), None),
        _ => {
            let file = OpenOptions::new()
                .read(true)
                .open(input_path)
                .with_context(|e| format!("{}: {}", input_path.to_string_lossy(), e))?;
            let filesize = file.metadata()?.len() as usize;
            (Box::new(file), Some(filesize))
        }
    };
    let output_stream: Writer = match output_path.to_str() {
        // NOTE: We only use stdin and stdout once. Using them more than once does not make sense.
        Some("-") => env.stdout.replace(Box::new(io::sink())),
        _ => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)  // Make sure we don't overwrite existing files
                .open(output_path)
                .with_context(|e| format!("{}: {}", output_path.to_string_lossy(), e))?;
            Box::new(file)
        }
    };

    Ok((input_stream, output_stream, filesize))
}

fn derive_key(file_header: &FileHeader, key_size: usize, opts: &Options) -> Fallible<Vec<u8>> {
    if let Some(secret_key) = &opts.secret_key {
        let key = util::try_parse_hex_string(secret_key)?;
        if key.len() != key_size {
            bail!(
                "Invalid secret key size: {} byte(s), expected {} bytes",
                key.len(),
                key_size
            );
        }
        Ok(key)
    } else if let Some(password) = &opts.password {
        Ok(registry::key_derivation_from_header(&file_header)?
            .derive_key_from_password(password, key_size)?)
    } else {
        Err(MyError::PasswordRequired.into())
    }
}

fn parse_command_line(env: &RuntimeEnvironment) -> Fallible<Options> {
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
        .optopt("a", "algorithm", "choose algorithm for encryption", "ALG")
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

    // Figure out the input paths.
    let input_paths = if matches.free.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        matches.free.iter().map(|s| s.into()).collect()
    };

    // Figure out the encrypted file suffix, ensuring it doesn't start with a '.'
    let mut suffix = matches
        .opt_str("S")
        .unwrap_or_else(|| DEFAULT_FILE_SUFFIX.into());
    if suffix.starts_with('.') {
        suffix.remove(0);
    }

    Ok(Options {
        mode,
        input_paths,
        suffix: OsString::from(suffix),
        password: matches.opt_str("password-unsafe"),
        secret_key: matches.opt_str("secret-key-unsafe"),
        algorithm: matches.opt_str("a"),
        verbose: matches.opt_count("v") as i32,
    })
}

fn encrypt_file(
    input_path: &Path,
    opts: &Options,
    env: &RuntimeEnvironment,
    progress_printer: &mut ProgressPrinter,
) -> Fallible<()> {
    let (output_path, remove_input) = if input_path.to_str() == Some("-") {
        if env.stdout_is_tty {
            bail!("Encrypted data cannot be written to a terminal");
        }
        (PathBuf::from("-"), false)
    } else {
        let mut new_ext = input_path.extension().unwrap_or_default().to_os_string();
        if new_ext == opts.suffix {
            bail!(
                "{}: Unexpected file extension, skipping. Did you mean to decrypt (-d) this file?",
                input_path.to_string_lossy()
            );
        }
        if !new_ext.is_empty() {
            new_ext.push(".");
        }
        new_ext.push(&opts.suffix);
        (input_path.with_extension(new_ext), true)
    };
    let (input_stream, mut output_stream, filesize) = open_streams(input_path, &output_path, &env)?;
    progress_printer.set_filesize(filesize);

    let file_header = registry::header_from_command_line(&opts.algorithm, &None)?;

    let codec = registry::codec_from_header(&file_header)?;
    let codec_config = codec.get_config();
    let key = derive_key(&file_header, codec_config.key_size, &opts)?;

    let header_buf = file_header.write(&mut output_stream)?;

    let (codec_header, stream_converter) = codec.start_encoding(key, Some(header_buf))?;
    output_stream.write_all(&codec_header)?;

    stream_convert_to_completion(
        stream_converter,
        input_stream,
        output_stream,
        file_header.chunk_size as usize,
        &mut |bytes| progress_printer.print_progress(bytes),
    )?;

    if remove_input {
        fs::remove_file(input_path)?;
    }
    Ok(())
}

fn decrypt_file(
    input_path: &Path,
    opts: &Options,
    env: &RuntimeEnvironment,
    progress_printer: &mut ProgressPrinter,
) -> Fallible<()> {
    let (output_path, remove_input) = if input_path.to_str() == Some("-") {
        if env.stdin_is_tty {
            bail!("Encrypted data cannot be read from a terminal.");
        }
        (input_path.to_path_buf(), false)
    } else {
        if input_path.extension() != Some(&opts.suffix) {
            bail!(
                "{}: Unexpected file extension, skipping.",
                input_path.to_string_lossy()
            );
        }
        (input_path.with_extension(""), true)
    };

    let (mut input_stream, output_stream, filesize) = open_streams(input_path, &output_path, &env)?;
    progress_printer.set_filesize(filesize);

    let (file_header, header_buf) = FileHeader::read(&mut input_stream)?;

    let codec = registry::codec_from_header(&file_header)?;
    let codec_config = codec.get_config();
    let key = derive_key(&file_header, codec_config.key_size, &opts)?;

    let mut codec_header = vec![0u8; codec_config.header_size];
    input_stream.read_exact(&mut codec_header)?;
    let stream_converter = codec.start_decoding(key, codec_header, Some(header_buf))?;

    stream_convert_to_completion(
        stream_converter,
        input_stream,
        output_stream,
        file_header.chunk_size as usize,
        &mut |bytes| progress_printer.print_progress(bytes),
    )?;
    if remove_input {
        fs::remove_file(input_path)?;
    }
    Ok(())
}

pub fn run(env: &RuntimeEnvironment) -> i32 {
    let mut stderr = env.stderr.borrow_mut();
    if unsafe { libsodium_sys::sodium_init() } == -1 {
        writeln!(stderr, "{}: {}", PKG_NAME, MyError::InitError).ok();
        return 1;
    }

    match parse_command_line(env) {
        Err(err) => {
            writeln!(stderr, "{}: {}", PKG_NAME, err).ok();
            return 1;
        }
        Ok(opts) => {
            let total_files = opts.input_paths.len();
            for (file_idx, input_path) in opts.input_paths.iter().enumerate() {
                let mut progress_printer = ProgressPrinter::new(&mut stderr, opts.verbose);
                progress_printer.print_file_header(input_path, file_idx, total_files);

                let res = match opts.mode {
                    OperationMode::Auxiliary => Ok(()),
                    OperationMode::Encrypt => {
                        encrypt_file(input_path, &opts, &env, &mut progress_printer)
                    }
                    OperationMode::Decrypt => {
                        decrypt_file(input_path, &opts, &env, &mut progress_printer)
                    }
                };
                std::mem::drop(progress_printer);
                if let Err(err) = res {
                    writeln!(stderr, "{}: {}", PKG_NAME, err).ok();
                }
            }
        }
    }
    0
}
