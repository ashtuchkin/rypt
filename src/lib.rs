#![warn(clippy::all)]
#![allow(dead_code, clippy::type_complexity)]
#![deny(bare_trait_objects)]

use failure::Fallible;

use crate::cli::{
    parse_command_line, print_help, print_version, Command, CryptDirectionOpts, CryptOptions,
    InputCleanupPolicy,
};
pub use crate::errors::EarlyTerminationError;
use crate::header::{decrypt_header, encrypt_header};
use crate::header_io::{read_header, write_header};
use crate::io_streams::InputOutputStream;
use crate::key_management::generate_key_pair_files;
use crate::progress::ProgressPrinter;
pub use crate::runtime_env::{Reader, RuntimeEnvironment, Writer};
use crate::ui::UI;

pub mod cli;
mod credentials;
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
mod terminal;
mod types;
mod ui;
pub mod util;

fn crypt_streams(
    io_streams: Vec<InputOutputStream>,
    opts: &CryptOptions,
    direction: &CryptDirectionOpts,
    ui: &dyn UI,
) -> Fallible<()> {
    let total_files = io_streams.len();
    let mut success_cleanup_cbs = vec![];
    let mut failures = vec![];
    for (file_idx, io_stream) in io_streams.into_iter().enumerate() {
        let mut input_delete_cb_opt = None;
        let mut output_delete_cb_opt = None;

        let res = (|| {
            let InputOutputStream { input, output } = io_stream;

            let mut progress_printer = ProgressPrinter::new(ui, opts.plaintext_on_tty);
            progress_printer.print_file_header(&input.path(), file_idx, total_files);

            let output = output?;

            let (mut input_stream, input_filesize, delete_cb_opt) = input.open_with_delete_cb()?;
            input_delete_cb_opt = delete_cb_opt;
            progress_printer.set_filesize(input_filesize);

            let (mut output_stream, delete_cb_opt) = output.open_with_delete_cb()?;
            output_delete_cb_opt = delete_cb_opt;

            let (stream_converter, chunk_size) = match direction {
                CryptDirectionOpts::Encrypt(opts) => {
                    let (file_header, stream_converter, chunk_size) = encrypt_header(&opts)?;
                    write_header(&mut output_stream, &file_header)?;
                    (stream_converter, chunk_size)
                }
                CryptDirectionOpts::Decrypt(opts) => {
                    let (file_header, read_header_bytes) = read_header(&mut input_stream)?;
                    progress_printer.print_progress(read_header_bytes);
                    decrypt_header(&file_header, &opts)?
                }
            };

            stream_pipeline::convert_stream(
                stream_converter,
                input_stream,
                output_stream,
                chunk_size,
                &mut |bytes| progress_printer.print_progress(bytes),
            )
        })();

        match res {
            Ok(()) => {
                // Store input file deletion callback (if not None), so that we can delete input
                // files after confirming with user at the end.
                success_cleanup_cbs.extend(input_delete_cb_opt);
            }
            Err(err) => {
                ui.print_error(&err).ok();
                failures.push(err);

                // Delete output file on error.
                if let Some(cb) = output_delete_cb_opt {
                    cb().or_else(|err| ui.print_error(&err)).ok();
                }
            }
        }
    }

    // Delete input files if necessary.
    if !success_cleanup_cbs.is_empty() {
        let should_delete_input_files = match opts.input_cleanup_policy {
            InputCleanupPolicy::KeepFiles => false,
            InputCleanupPolicy::DeleteFiles => true,
            InputCleanupPolicy::PromptUser => {
                ui.read_prompt_bool("Would you like to remove original file(s)?", false)?
            }
        };

        if should_delete_input_files {
            for cb in success_cleanup_cbs {
                cb().or_else(|err| ui.print_error(&err)).ok();
            }
        }
    }

    // TODO: return error in case of !failures.is_empty()
    Ok(())
}

pub fn run_command(command: Command, ui: &dyn UI) -> Fallible<()> {
    match command {
        Command::CryptStreams(streams, opts, direction) => {
            crypt_streams(streams, &opts, &direction, ui)
        }
        Command::GenerateKeyPair(opts) => generate_key_pair_files(opts.streams, ui),
        Command::Help(output, program_name) => print_help(output, &program_name),
        Command::Version(output) => print_version(output),
    }
}

pub fn run(env: RuntimeEnvironment) -> Fallible<()> {
    let (command, ui) = parse_command_line(env)?;

    run_command(command, &ui).or_else(|err| {
        ui.print_error(&err).ok();
        Err(err)
    })
}
