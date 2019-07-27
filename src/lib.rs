#![warn(clippy::all)]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use failure::{Fallible, ResultExt};

use crate::cli::{parse_command_line, InputOutputStream, OperationMode};
use crate::header::{decrypt_header, encrypt_header};
use crate::header_io::{read_header, write_header};
use crate::progress::ProgressPrinter;
pub use crate::runtime_env::{Reader, RuntimeEnvironment, Writer};

pub mod cli;
mod crypto;
mod header;
mod header_io;
mod progress;
mod proto;
mod runtime_env;
mod stream_crypto;
mod stream_pipeline;
mod types;
pub mod util;

// See https://stackoverflow.com/a/27841363 for the full list.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");

fn open_streams(
    io_stream: &InputOutputStream,
    env: &RuntimeEnvironment,
) -> Fallible<(Reader, Writer, Option<usize>)> {
    let InputOutputStream {
        input_path,
        output_path,
        ..
    } = io_stream;

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

pub fn run(env: &RuntimeEnvironment) -> i32 {
    let mut stderr = env.stderr.borrow_mut();
    match parse_command_line(env) {
        Ok((Some(opts), io_streams)) => {
            let total_files = io_streams.len();
            assert!(total_files > 0);

            for (file_idx, io_stream_res) in io_streams.into_iter().enumerate() {
                io_stream_res
                    .and_then(|io_stream| {
                        let mut progress_printer = ProgressPrinter::new(&mut stderr, opts.verbose);
                        progress_printer.print_file_header(
                            &io_stream.input_path,
                            file_idx,
                            total_files,
                        );

                        let (mut input_stream, mut output_stream, filesize) =
                            open_streams(&io_stream, &env)?;
                        progress_printer.set_filesize(filesize);

                        let (stream_converter, chunk_size) = match opts.mode {
                            OperationMode::Encrypt => {
                                let (file_header, stream_converter, chunk_size) =
                                    encrypt_header(&opts)?;
                                write_header(&mut output_stream, &file_header)?;
                                (stream_converter, chunk_size)
                            }
                            OperationMode::Decrypt => {
                                let file_header = read_header(&mut input_stream)?;
                                decrypt_header(&file_header, &opts)?
                            }
                        };

                        stream_pipeline::convert_stream(
                            stream_converter,
                            input_stream,
                            output_stream,
                            chunk_size,
                            &mut |bytes| progress_printer.print_progress(bytes),
                        )?;

                        if io_stream.remove_input_on_success {
                            fs::remove_file(&io_stream.input_path)?;
                        }
                        Ok(())
                    })
                    .unwrap_or_else(|err| {
                        writeln!(stderr, "{}: {}", PKG_NAME, err).ok();
                    });
            }
        }
        Ok((None, streams)) => {
            assert_eq!(streams.len(), 0); // Nothing to do for non-encrypt/decrypt operations
        }
        Err(err) => {
            writeln!(stderr, "{}: {}", PKG_NAME, err).ok();
            return 1;
        }
    }
    0
}
