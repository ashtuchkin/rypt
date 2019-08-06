#![warn(clippy::all)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use failure::Fallible;

use crate::cli::{parse_command_line, print_help, print_version, Command};
pub use crate::errors::EarlyTerminationError;
use crate::header::{decrypt_header, encrypt_header};
use crate::header_io::{read_header, write_header};
use crate::io_streams::InputOutputStream;
use crate::key_management::generate_key_pair_files;
use crate::progress::ProgressPrinter;
pub use crate::runtime_env::{Reader, RuntimeEnvironment, Writer};
use crate::types::StreamConverter;

pub mod cli;
mod crypto;
mod errors;
mod header;
mod header_io;
mod io_streams;
mod key_management;
mod progress;
mod proto;
mod runtime_env;
mod shamir;
mod stream_crypto;
mod stream_pipeline;
mod types;
pub mod util;

// See https://stackoverflow.com/a/27841363 for the full list.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");

fn convert_streams(
    io_streams: Vec<InputOutputStream>,
    verbose: i32,
    stderr: &mut Writer,
    terminate_flag: &Arc<AtomicBool>,
    create_converter: &Fn(&mut Read, &mut Write) -> Fallible<(Box<StreamConverter>, usize, usize)>,
) -> Fallible<()> {
    let total_files = io_streams.len();
    for (file_idx, io_stream) in io_streams.into_iter().enumerate() {
        if terminate_flag.load(Ordering::Relaxed) {
            break;
        }

        let mut progress_printer = ProgressPrinter::new(stderr, verbose);
        progress_printer.print_file_header(&io_stream.input_path(), file_idx, total_files);

        let res = io_stream.open_streams().and_then(
            |(mut input_stream, mut output_stream, input_filesize, cleanup_streams)| {
                progress_printer.set_filesize(input_filesize);

                let res = create_converter(input_stream.as_mut(), output_stream.as_mut()).and_then(
                    |(stream_converter, chunk_size, header_bytes)| {
                        progress_printer.print_progress(header_bytes);

                        stream_pipeline::convert_stream(
                            stream_converter,
                            input_stream,
                            output_stream,
                            chunk_size,
                            &mut |bytes| progress_printer.print_progress(bytes),
                            terminate_flag.clone(),
                        )
                    },
                );
                cleanup_streams(res)
            },
        );

        std::mem::drop(progress_printer); // Release mutable borrow of stderr.
        if let Err(err) = res {
            match err.downcast::<EarlyTerminationError>() {
                Ok(_) => (), // Don't print anything in case of early termination
                Err(err) => writeln!(stderr, "{}: {}", PKG_NAME, err).unwrap_or(()),
            }
        }
    }
    Ok(())
}

pub fn run(env: &RuntimeEnvironment) -> Fallible<()> {
    match parse_command_line(&env)? {
        Command::Encrypt(streams, opts) => convert_streams(
            streams,
            opts.verbose,
            &mut env.stderr.borrow_mut(),
            &env.terminate_flag,
            &|_, output_stream| {
                let (file_header, stream_converter, chunk_size) = encrypt_header(&opts)?;
                write_header(output_stream, &file_header)?;
                Ok((stream_converter, chunk_size, 0))
            },
        ),
        Command::Decrypt(streams, opts) => convert_streams(
            streams,
            opts.verbose,
            &mut env.stderr.borrow_mut(),
            &env.terminate_flag,
            &|input_stream, _| {
                let (file_header, read_header_bytes) = read_header(input_stream)?;
                let (stream_converter, chunk_size) = decrypt_header(&file_header, &opts)?;
                Ok((stream_converter, chunk_size, read_header_bytes))
            },
        ),
        Command::GenerateKeyPair(opts) => {
            generate_key_pair_files(opts.paths, opts.verbose, &mut env.stderr.borrow_mut())
        }
        Command::Help => print_help(&env),
        Command::Version => print_version(&env),
    }
}
