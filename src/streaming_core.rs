use std::collections::VecDeque;
use std::io::{Write, Read, ErrorKind};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use failure::Error;

use crate::errors::MyError;
use crate::types::{StreamConverter, ChunkConfig, Chunk};
use crate::util;


pub fn stream_convert_to_completion(mut stream_converter: Box<StreamConverter>, input_stream: Box<Read + Send>,
                                    output_stream: Box<Write + Send>, chunk_size: usize) -> Result<(), Error> {
    let ChunkConfig {input_chunk_offset, input_chunk_asize, output_chunk_asize} = stream_converter.get_chunk_config();

    // Channels
    let (initial_sender, read_receiver) = crossbeam_channel::unbounded();
    let (read_sender, codec_receiver) = crossbeam_channel::unbounded();
    let (codec_sender, write_receiver) = crossbeam_channel::unbounded();
    let (write_sender, final_receiver) = crossbeam_channel::unbounded();

    // Threads
    let (progress_sender, progress_thread) = start_progress_thread();
    let read_thread = thread::spawn(move || read_stream(input_stream, read_receiver, read_sender));
    let codec_thread = thread::spawn(move || stream_converter.convert_blocking(codec_receiver, codec_sender));
    let write_thread = thread::spawn(move || write_stream(output_stream, write_receiver, write_sender));

    // Send initial buffers in to start the pipeline.
    let input_buffer_size = input_chunk_offset + chunk_size + input_chunk_asize;
    let buffer_capacity = input_chunk_offset + chunk_size +
        std::cmp::max(input_chunk_asize, output_chunk_asize) + 1;  // +1 byte to allow reader to check Eof
    for _ in 0..5 {
        let mut buffer = Vec::with_capacity(buffer_capacity);
        buffer.resize(input_buffer_size, 0);
        initial_sender.send(Chunk {
            buffer,
            offset: input_chunk_offset,
            is_last_chunk: false,
        }).ok();
    }

    // Wait while data flows through the pipeline, resupplying used buffers back to the reader.
    for mut chunk in final_receiver {
        progress_sender.send(chunk.buffer.len())?;
        if chunk.buffer.capacity() == buffer_capacity {
            chunk.offset = input_chunk_offset;
            chunk.buffer.resize(input_buffer_size, 0);
            initial_sender.send(chunk).ok();  // Ok to drop vectors when reading has stopped.
        }
    }
    std::mem::drop(progress_sender);

    write_thread.join().map_err(|_| MyError::ThreadJoinError)??;
    codec_thread.join().map_err(|_| MyError::ThreadJoinError)??;
    read_thread.join().map_err(|_| MyError::ThreadJoinError)??;
    progress_thread.join().map_err(|_| MyError::ThreadJoinError)?;
    Ok(())
}


fn read_stream(mut input_stream: Box<Read + Send>, input: Receiver<Chunk>, output: Sender<Chunk>) -> Result<(), Error> {
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

                    } else {
                        // Reached end of file. Send the last chunk.
                        chunk.buffer.truncate(read_ptr);
                        chunk.is_last_chunk = true;
                        output.send(chunk)?;
                        return Ok(());
                    }
                },
                Err(e) => {
                    if e.kind() != ErrorKind::Interrupted {
                        return Err(e.into());
                    }
                    // Retry when interrupted
                },
            }
        }

        // Stream has more data; keep last byte and send remaining data
        last_byte = chunk.buffer.pop();
        chunk.is_last_chunk = false;
        output.send(chunk)?;
    }
    Err(std::io::Error::from(ErrorKind::NotConnected).into())
}

fn write_stream(mut output_stream: Box<Write+Send>, input: Receiver<Chunk>, output: Sender<Chunk>) -> Result<(), Error> {
    for chunk in input {
        output_stream.write_all(&chunk.buffer[chunk.offset..])?;
        if chunk.is_last_chunk {
            output_stream.flush()?;
        }
        output.send(chunk)?;
    }
    Ok(())
}


fn start_progress_thread() -> (Sender<usize>, thread::JoinHandle<()>) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    const PRINT_PERIOD: Duration = Duration::from_millis(100);
    const SPEED_CALC_PERIOD: Duration = Duration::from_secs(10);  // Calculate speed over the last 5 seconds
    const KEEP_STAMPS_COUNT: usize = (SPEED_CALC_PERIOD.as_millis() / PRINT_PERIOD.as_millis()) as usize;
    let print_ticker = crossbeam_channel::tick(PRINT_PERIOD);
    let start_time = Instant::now();
    let mut cur_progress = 0usize;
    let mut cur_progress_time = Instant::now();
    let mut stamps = VecDeque::new();
    stamps.push_back((cur_progress_time, cur_progress));
    let mut has_ever_printed = false;

    fn human_readable_duration(dur: Duration) -> String {
        let secs_f64 = dur.as_millis() as f64 / 1000f64;
        format!("{:.1}s", secs_f64)
    }

    let mut print_progress = move |stamps: &VecDeque<(Instant, usize)>, final_print: bool| {
        let (end_period_time, end_period_progress) = *stamps.back().unwrap();
        let (start_period_time, start_period_progress) = *stamps.front().unwrap();
        let delta_time = (end_period_time - start_period_time).as_millis() as usize;
        let delta_progress = end_period_progress - start_period_progress;
        if delta_time > 0 && delta_progress > 0 {
            let speed = delta_progress * 1000 / delta_time;
            eprint!(
                "\r{}Progress: {}, Speed: {}/s, Time: {}",
                termion::clear::CurrentLine,
                util::human_file_size(end_period_progress),
                util::human_file_size(speed),
                human_readable_duration(Instant::now() - start_time),

            );
            if final_print && has_ever_printed {
                eprintln!();
            }
            has_ever_printed = true;
        }
    };

    let join_handle = thread::spawn(move || {
        loop {
            crossbeam_channel::select! {
                recv(receiver) -> res => match res {
                    Ok(increment_size) => {
                        cur_progress += increment_size;
                        cur_progress_time = std::cmp::max(cur_progress_time, Instant::now());
                    },
                    Err(_) => {  // Disconnected - finish printing and exit.
                        print_progress(&stamps, true);
                        break;
                    }
                },
                recv(print_ticker) -> _ => {
                    stamps.push_back((cur_progress_time, cur_progress));
                    if stamps.len() > KEEP_STAMPS_COUNT {
                        stamps.pop_front();
                    }

                    print_progress(&stamps, false);
                },
            }
        }
    });

    (sender, join_handle)
}
