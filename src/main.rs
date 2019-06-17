use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{stdin, stdout, Read, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};

use failure::{bail, Error};

use crate::errors::MyError;
use crate::header::FileHeader;
use crate::streaming_core::stream_convert_to_completion;
use std::ffi::OsString;

mod encoding;
mod errors;
mod header;
mod key_derivation;
mod registry;
mod streaming_core;
mod types;
mod util;

// See https://stackoverflow.com/a/27841363 for full list.
const PKG_VERSION: &'static str = env!("CARGO_PKG_VERSION");
const PKG_NAME: &'static str = env!("CARGO_PKG_NAME");

#[derive(Debug, Copy, Clone)]
enum OperationMode {
    Encrypt,
    Decrypt,
}

#[derive(Debug)]
struct Options {
    mode: OperationMode,

    stdin_is_tty: bool,
    stdout_is_tty: bool,

    /// Input paths ("-" for stdin)
    input_paths: Vec<PathBuf>,

    suffix: OsString,

    /// Password
    password: Option<String>,

    algorithm: Option<String>,

    verbose: i32,
}

fn open_streams(
    input_path: &Path,
    output_path: &Path,
) -> Result<(Box<Read + Send>, Box<Write + Send>, Option<usize>), Error> {
    let filesize = match input_path.to_str() {
        Some("-") => None,
        _ => Some(std::fs::metadata(&input_path)?.len() as usize),
    };

    let input_stream: Box<Read + Send> = match input_path.to_str() {
        Some("-") => Box::new(stdin()),
        _ => Box::new(File::open(&input_path)?),
    };
    let output_stream: Box<Write + Send> = match output_path.to_str() {
        Some("-") => Box::new(stdout()),
        _ => Box::new(File::create(output_path)?),
    };

    Ok((input_stream, output_stream, filesize))
}

fn derive_key_from_password(
    file_header: &FileHeader,
    key_size: usize,
    password: &Option<String>,
) -> Result<Vec<u8>, Error> {
    if let Some(password) = password {
        Ok(registry::key_derivation_from_header(&file_header)?.derive_key_from_password(&password, key_size)?)
    } else {
        Err(MyError::PasswordRequired.into())
    }
}

fn parse_command_line() -> Result<Options, Error> {
    let mut args: VecDeque<String> = env::args().collect();
    let program = args.pop_front().unwrap();

    let mut options = getopts::Options::new();
    options
        .optflag("e", "encrypt", "force encryption mode (default)")
        .optflag("d", "decrypt", "force decryption mode")
        .optopt("p", "password", "provide password", "PASSWORD")
        .optopt("a", "algorithm", "choose algorithm for encryption", "ALG")
        .optflag("s", "stdout", "write to standard output and don't delete input files")
        .optopt("S", "suffix", "encrypted file suffix, defaults to .enc", ".suf")
        .optflagmulti("v", "verbose", "be verbose; specify twice for even more verbose")
        .optflag("h", "help", "display this short help and exit")
        .optflag("V", "version", "display the version numbers and exit");

    let matches = options.parse(&args)?;
    let stdin_is_tty = termion::is_tty(&std::io::stdin());
    let stdout_is_tty = termion::is_tty(&std::io::stdout());

    // Process help and version right here.
    if matches.opt_present("h") || (args.is_empty() && stdin_is_tty) {
        println!(
            "\
Usage: {} [OPTION].. [FILE]..
Encrypt or decrypt FILEs

{}

With no FILE, or when FILE is -, read standard input.

Report bugs to Alexander Shtuchkin <ashtuchkin@gmail.com>.
Home page and documentation: <https://github.com/ashtuchkin/xxx>",
            program,
            options.usage("").trim()
        );
        std::process::exit(0);
    } else if matches.opt_present("V") {
        println!("{} {}", PKG_NAME, PKG_VERSION);
        let libsodium_version = unsafe { std::ffi::CStr::from_ptr(libsodium_sys::sodium_version_string()) };
        println!("libsodium {}", libsodium_version.to_str()?);
        std::process::exit(0);
    }

    // Figure out the mode - it's the last mode-related argument, or Encrypt by default.
    let mut all_modes: BTreeMap<usize, OperationMode> = BTreeMap::new();
    all_modes.extend(
        matches
            .opt_positions("e")
            .into_iter()
            .map(|p| (p, OperationMode::Encrypt)),
    );
    all_modes.extend(
        matches
            .opt_positions("d")
            .into_iter()
            .map(|p| (p, OperationMode::Decrypt)),
    );

    let mode = all_modes
        .values()
        .next_back()
        .copied()
        .unwrap_or(OperationMode::Encrypt);

    // Figure out the input paths.
    let input_paths = if matches.free.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        matches.free.iter().map(|s| s.into()).collect()
    };

    Ok(Options {
        mode,
        stdin_is_tty,
        stdout_is_tty,
        input_paths,
        suffix: OsString::from(matches.opt_default("S", "enc").unwrap_or("enc".into())),
        password: matches.opt_str("p"),
        algorithm: matches.opt_str("a"),
        verbose: matches.opt_count("v") as i32,
    })
}

fn encrypt_file(input_path: &PathBuf, opts: &Options) -> Result<(), Error> {
    let (output_path, remove_input) = if input_path.to_str() == Some("-") {
        if opts.stdout_is_tty {
            bail!("Encrypted data cannot be written to a terminal");
        }
        (PathBuf::from("-"), false)
    } else {
        let mut new_ext = input_path.extension().unwrap_or_default().to_os_string();
        if !opts.suffix.to_str().unwrap_or_default().starts_with(".") {
            new_ext.push(OsString::from("."));
        }
        new_ext.push(&opts.suffix);
        (input_path.with_extension(new_ext), true)
    };
    let (input_stream, mut output_stream, _filesize) = open_streams(input_path, &output_path)?;

    let file_header = registry::header_from_command_line(&opts.algorithm, &None)?;

    let codec = registry::codec_from_header(&file_header)?;
    let codec_config = codec.get_config();
    let key = derive_key_from_password(&file_header, codec_config.key_size, &opts.password)?;

    let header_buf = file_header.write(&mut output_stream)?;

    let (codec_header, stream_converter) = codec.start_encoding(key, Some(header_buf))?;
    output_stream.write_all(&codec_header)?;

    stream_convert_to_completion(
        stream_converter,
        input_stream,
        output_stream,
        file_header.chunk_size as usize,
    )?;

    if remove_input {
        fs::remove_file(input_path)?;
    }
    Ok(())
}

fn decrypt_file(input_path: &PathBuf, opts: &Options) -> Result<(), Error> {
    let (output_path, remove_input) = if input_path.to_str() == Some("-") {
        if opts.stdout_is_tty {
            bail!("Encrypted data cannot be read from a terminal.");
        }
        (PathBuf::from("-"), false)
    } else {
        if input_path.extension() != Some(&opts.suffix) {
            bail!("{:?}: Filename has an unknown suffix, skipping.", input_path);
        }
        (input_path.with_extension(""), true)
    };

    let (mut input_stream, output_stream, _filesize) = open_streams(input_path, &output_path)?;

    let (file_header, header_buf) = FileHeader::read(&mut input_stream)?;

    let codec = registry::codec_from_header(&file_header)?;
    let codec_config = codec.get_config();
    let key = derive_key_from_password(&file_header, codec_config.key_size, &opts.password)?;

    let mut codec_header = vec![0u8; codec_config.header_size];
    input_stream.read_exact(&mut codec_header)?;
    let stream_converter = codec.start_decoding(key, codec_header, Some(header_buf))?;

    stream_convert_to_completion(
        stream_converter,
        input_stream,
        output_stream,
        file_header.chunk_size as usize,
    )?;
    if remove_input {
        fs::remove_file(input_path)?;
    }
    Ok(())
}

fn _main() -> Result<(), Error> {
    if unsafe { libsodium_sys::sodium_init() } < 0 {
        return Err(MyError::InitError.into());
    }
    let opts = parse_command_line()?;
    for (_file_idx, input_path) in opts.input_paths.iter().enumerate() {
        let res = match opts.mode {
            OperationMode::Encrypt => encrypt_file(input_path, &opts),
            OperationMode::Decrypt => decrypt_file(input_path, &opts),
        };
        if let Err(err) = res {
            eprintln!("{}: {}", PKG_NAME, err);
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = _main() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
