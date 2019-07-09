use std::io::{ErrorKind, Read, Write};
use std::thread;

use crossbeam_channel::{Receiver, RecvError, Sender};
use failure::Fallible;

use crate::errors::MyError;
use crate::types::{Chunk, ChunkConfig, StreamConverter};

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

    // Channels
    let (initial_sender, read_receiver) = crossbeam_channel::unbounded();
    let (read_sender, codec_receiver) = crossbeam_channel::unbounded();
    let (codec_sender, write_receiver) = crossbeam_channel::unbounded();
    let (write_sender, final_receiver) = crossbeam_channel::unbounded();

    // Spawn worker threads
    let reader_thread =
        thread::spawn(move || read_stream(input_stream, read_receiver, read_sender));
    let codec_thread =
        thread::spawn(move || convert_stream(stream_converter, codec_receiver, codec_sender));
    let writer_thread =
        thread::spawn(move || write_stream(output_stream, write_receiver, write_sender));

    // Send initial buffers in to kickstart the pipeline.
    let input_buffer_size = input_chunk_offset + chunk_size + input_chunk_asize;
    let buffer_capacity =
        input_chunk_offset + chunk_size + std::cmp::max(input_chunk_asize, output_chunk_asize) + 1; // +1 byte to allow reader to check Eof
    for _ in 0..5 {
        let mut buffer = vec![0u8; buffer_capacity];
        buffer.truncate(input_buffer_size);
        initial_sender
            .send(Chunk {
                buffer,
                offset: input_chunk_offset,
                is_last_chunk: false,
                authentication_data: authentication_data.take(), // Only provide auth data to the first chunk
            })
            .ok();
    }

    // Wait while data flows through the pipeline, resupplying used buffers back to the reader.
    let mut written_bytes = 0usize;
    for mut chunk in final_receiver {
        // Call progress callback
        written_bytes += chunk.buffer.len() - chunk.offset;
        progress_cb(written_bytes);

        // Reset the chunk
        chunk.offset = input_chunk_offset;
        chunk.buffer.resize(input_buffer_size, 0);
        assert_eq!(chunk.buffer.capacity(), buffer_capacity);

        // Send it back to the pipeline; ok to drop vectors when reading has stopped.
        initial_sender.send(chunk).ok();
    }

    writer_thread
        .join()
        .map_err(|_| MyError::ThreadJoinError)??;
    codec_thread
        .join()
        .map_err(|_| MyError::ThreadJoinError)??;
    reader_thread
        .join()
        .map_err(|_| MyError::ThreadJoinError)??;
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
    Err(RecvError.into())
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
