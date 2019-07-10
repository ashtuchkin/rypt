use std::io::{ErrorKind, Read, Write};
use std::thread;

use crossbeam_channel::{Receiver, SendError, Sender};
use failure::Fallible;

use crate::errors::MyError;
use crate::types::{Chunk, ChunkConfig, StreamConverter};

const NUM_CHUNKS_IN_PIPELINE: usize = 6; // 3 being worked on and 3 waiting in channels.

pub fn stream_convert_to_completion(
    stream_converter: Box<StreamConverter>,
    input_stream: Box<Read + Send>,
    output_stream: Box<Write + Send>,
    chunk_size: usize,
    mut authentication_data: Option<Vec<u8>>,
    progress_cb: &mut FnMut(usize),
) -> Fallible<()> {
    let ChunkConfig {
        input_chunk_offset,
        input_chunk_asize,
        output_chunk_asize,
    } = stream_converter.get_chunk_config();

    // Channels between worker threads. Capacities are all set to 1 to minimize buffering while
    // still allowing parallelization.
    let (initial_sender, read_receiver) = crossbeam_channel::bounded(1);
    let (read_sender, codec_receiver) = crossbeam_channel::bounded(1);
    let (codec_sender, write_receiver) = crossbeam_channel::bounded(1);
    let (write_sender, final_receiver) = crossbeam_channel::bounded(1);

    // Spawn worker threads
    let reader_thread = thread::Builder::new()
        .name("stream reader".into())
        .spawn(move || read_stream(input_stream, read_receiver, read_sender))?;
    let codec_thread = thread::Builder::new()
        .name("encryption/decryption".into())
        .spawn(move || convert_stream(stream_converter, codec_receiver, codec_sender))?;
    let writer_thread = thread::Builder::new()
        .name("stream writer".into())
        .spawn(move || write_stream(output_stream, write_receiver, write_sender))?;

    // Create and send initial chunks to kickstart the pipeline.
    let input_buffer_size = input_chunk_offset + chunk_size + input_chunk_asize;
    let buffer_capacity =
        input_chunk_offset + chunk_size + std::cmp::max(input_chunk_asize, output_chunk_asize) + 1; // +1 byte to allow reader to check Eof
    for _ in 0..NUM_CHUNKS_IN_PIPELINE {
        let mut buffer = vec![0u8; buffer_capacity];
        buffer.truncate(input_buffer_size);
        let chunk = Chunk {
            buffer,
            offset: input_chunk_offset,
            is_last_chunk: false,
            authentication_data: authentication_data.take(), // Only provide auth data to the first chunk
        };
        initial_sender.send(chunk).ok();
    }

    // Wait while data flows through the pipeline, resupplying used chunks back to the reader.
    let mut written_bytes = 0usize;
    for mut chunk in final_receiver {
        written_bytes += chunk.buffer.len() - chunk.offset;

        // Reset the chunk
        chunk.offset = input_chunk_offset;
        chunk.buffer.resize(input_buffer_size, 0);
        assert_eq!(chunk.buffer.capacity(), buffer_capacity);

        // Send it back to the pipeline; ok to drop vectors if reading has stopped.
        initial_sender.send(chunk).ok();

        // Call progress callback after sending, to avoid slowing down the pipe.
        progress_cb(written_bytes);
    }

    // Propagate termination state back to the beginning of the pipeline, forcing reader to exit.
    std::mem::drop(initial_sender);

    // Wait for the threads to finish. They are guaranteed to do that because input channels are all
    // closed now.
    let join_results = vec![
        (reader_thread.join(), "Reading"),
        (codec_thread.join(), "Encryption"),
        (writer_thread.join(), "Writing"),
    ];

    // Process and re-raise any errors/panics in worker threads. We expect at most one real error to
    // happen in the vast majority of cases, so just return the first one.
    for (join_res, operation) in join_results {
        match join_res {
            Ok(thread_result) => match thread_result {
                // Successful termination
                Ok(_) => {}

                Err(e) => match e.downcast::<SendError<Chunk>>() {
                    // SendError<Chunk> is not a error - it's an early termination sign; skip it.
                    Ok(_) => {}

                    // Add context to a valid error that happened in the thread.
                    Err(err) => {
                        let message = format!("{} error: {}", operation, err);
                        return Err(err.context(message).into());
                    }
                },
            },

            // Handle thread panic. Theoretically we can extract the message via Any::downcast
            // (payload is usually a &str or String), but it will be written to stderr by default
            // panic handler anyway, so we don't bother.
            Err(_) => return Err(MyError::WorkerThreadPanic(operation.to_string()).into()),
        }
    }
    Ok(())
}

fn read_stream(
    mut input_stream: Box<Read + Send>,
    input: Receiver<Chunk>,
    output: Sender<Chunk>,
) -> Fallible<()> {
    let mut last_byte = None;
    for mut chunk in input {
        chunk.buffer.push(0); // Add one byte to allow determining final chunk.

        let mut read_ptr = chunk.offset;
        if let Some(last_byte) = last_byte {
            chunk.buffer[read_ptr] = last_byte;
            read_ptr += 1;
        }

        while read_ptr < chunk.buffer.len() {
            match input_stream.read(&mut chunk.buffer[read_ptr..]) {
                Ok(read_bytes) => {
                    if read_bytes > 0 {
                        // Continue reading into the buffer, adjusting the slices.
                        read_ptr += read_bytes;
                        continue;
                    } else {
                        // Reached end of stream. Send the last chunk and exit.
                        chunk.buffer.truncate(read_ptr);
                        chunk.is_last_chunk = true;
                        output.send(chunk)?;
                        return Ok(());
                    }
                }
                Err(e) => {
                    if e.kind() == ErrorKind::Interrupted {
                        continue; // Retry when interrupted
                    }
                    return Err(e.into());
                }
            }
        }

        // Stream has more data; keep last byte and send remaining data
        last_byte = chunk.buffer.pop();
        chunk.is_last_chunk = false;
        output.send(chunk)?;
    }

    // NOTE: This can happen if later stages in the pipeline fail and we forcefully close incoming
    // stream of buffers. Semantically this is a successful exit.
    Ok(())
}

fn convert_stream(
    mut stream_converter: Box<StreamConverter>,
    input: Receiver<Chunk>,
    output: Sender<Chunk>,
) -> Fallible<()> {
    for chunk in input {
        output.send(stream_converter.convert_chunk(chunk)?)?;
    }
    Ok(())
}

fn write_stream(
    mut output_stream: Box<Write + Send>,
    input: Receiver<Chunk>,
    output: Sender<Chunk>,
) -> Fallible<()> {
    for chunk in input {
        output_stream.write_all(&chunk.buffer[chunk.offset..])?;
        if chunk.is_last_chunk {
            output_stream.flush()?;
        }
        output.send(chunk)?;
    }
    Ok(())
}
