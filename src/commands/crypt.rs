use failure::Fallible;

use crate::commands::{CryptDirectionOpts, CryptOptions, InputCleanupPolicy};
use crate::errors::CompositeError;
use crate::header::{decrypt_header, encrypt_header};
use crate::header_io::{read_header, write_header};
use crate::io_streams::InputOutputStream;
use crate::progress::ProgressPrinter;
use crate::stream_pipeline;
use crate::ui::UI;

pub fn crypt_streams(
    io_streams: Vec<InputOutputStream>,
    opts: &CryptOptions,
    direction: &CryptDirectionOpts,
    ui: &dyn UI,
) -> Fallible<()> {
    let total_files = io_streams.len();
    let mut success_cleanup_cbs = vec![];
    let mut errors = vec![];
    for (file_idx, io_stream) in io_streams.into_iter().enumerate() {
        let mut input_cleanup_cb_opt = None;
        let mut output_cleanup_cb_opt = None;

        let res = (|| {
            let InputOutputStream { input, output } = io_stream;

            let mut progress_printer = ProgressPrinter::new(ui);
            progress_printer.print_file_header(
                &input.path(),
                output.as_ref().ok().map(|s| s.path()),
                file_idx,
                total_files,
            );

            let output = output?;

            let (mut input_stream, input_filesize, cleanup_cb_opt) =
                input.open_with_cleanup_cb()?;
            input_cleanup_cb_opt = cleanup_cb_opt;
            progress_printer.set_filesize(input_filesize);

            let (mut output_stream, cleanup_cb_opt) = output.open_with_cleanup_cb()?;
            output_cleanup_cb_opt = cleanup_cb_opt;

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
                success_cleanup_cbs.extend(input_cleanup_cb_opt);
            }
            Err(err) => {
                ui.print_error(&err).ok();
                errors.push(err);

                // Delete output file on error.
                if let Some(cb) = output_cleanup_cb_opt {
                    cb().or_else(|err| ui.print_error(&err)).ok();
                }
            }
        }

        ui.println(0, "")?;
    }

    // Delete input files if necessary.
    if !success_cleanup_cbs.is_empty() {
        let should_delete_input_files = match opts.input_cleanup_policy {
            InputCleanupPolicy::KeepFiles => false,
            InputCleanupPolicy::DeleteFiles => true,
            InputCleanupPolicy::PromptUser => {
                ui.read_prompt_bool(0, "Remove original file(s)?", false)?
                    .unwrap_or(false) // By default keep files
            }
        };

        if should_delete_input_files {
            for cb in success_cleanup_cbs {
                cb().or_else(|err| ui.print_error(&err)).ok();
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(CompositeError { errors }.into())
    }
}
