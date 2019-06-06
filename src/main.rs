use std::io::{Read, Write, ErrorKind, stdin, stdout};
use std::path::PathBuf;
use std::fs::{File, metadata};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

use structopt::StructOpt;
use sodiumoxide::crypto::pwhash;
use failure::{Error};
use humansize::{FileSize, file_size_opts::CONVENTIONAL as ConventionalSize};
use crossbeam_channel::{Sender, Receiver, unbounded as unbounded_channel, tick};
use crate::codec::{MyError, Chunk, StreamCodec, ChunkConfig};
use crate::xchacha20::XChaCha20;
use crate::aes256_gcm::Aes256Gcm;

mod codec;
mod xchacha20;
mod aes256_gcm;

const CHUNK_SIZE: usize = 1 * 1024 * 1024;

fn start_read_thread(input_path: PathBuf, input: Receiver<Chunk>, output: Sender<Chunk>, header_size: Option<usize>)
                        -> Result<(thread::JoinHandle<Result<(), Error>>, Option<u64>), Error> {
    let filesize = match input_path.to_str() {
        Some("-") => None,
        _ => Some(metadata(&input_path)?.len()),
    };

    let handle = thread::spawn(move || -> Result<(), Error> {
        let stdin = stdin();
        let mut input_stream: Box<Read> = match input_path.to_str() {
            Some("-") => Box::new(stdin.lock()),
            _ => Box::new(File::open(&input_path)?),
        };

        if let Some(header_size) = header_size {
            let mut header_buf = vec![0u8; header_size];
            input_stream.read_exact(header_buf.as_mut_slice())?;
            output.send(Chunk {buffer: header_buf, offset: 0, is_last_chunk: false})?;
        }

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
    });

    Ok((handle, filesize))
}

fn start_write_thread(output_path: PathBuf, input: Receiver<Chunk>, output: Sender<Chunk>) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        let stdout = stdout();
        let mut output_stream: Box<Write> = match output_path.to_str() {
            Some("-") => Box::new(stdout.lock()),
            _ => Box::new(File::create(output_path)?),
        };

        for chunk in input {
            output_stream.write_all(&chunk.buffer[chunk.offset..])?;
            if chunk.is_last_chunk {
                output_stream.flush()?;
            }
            output.send(chunk)?;
        }
        Ok(())
    })
}

fn derive_key_from_password(password: &str, key_size: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_size];  // KEYBYTES = 32
    let salt =   // NOTE: We use static salt.
        "rust-crypto-test-salt".bytes().cycle().take(pwhash::SALTBYTES).collect::<Vec<u8>>();
    let salt = pwhash::Salt::from_slice(&salt).unwrap();
    pwhash::derive_key_interactive(key.as_mut_slice(), password.as_bytes(), &salt).unwrap();

    key
}

fn start_progress_thread() -> (Sender<usize>, thread::JoinHandle<()>) {
    let (sender, receiver) = unbounded_channel();
    const PRINT_PERIOD: Duration = Duration::from_millis(100);
    const SPEED_CALC_PERIOD: Duration = Duration::from_secs(10);  // Calculate speed over the last 5 seconds
    const KEEP_STAMPS_COUNT: usize = (SPEED_CALC_PERIOD.as_millis() / PRINT_PERIOD.as_millis()) as usize;
    let print_ticker = tick(PRINT_PERIOD);
    let start_time = Instant::now();
    let mut cur_progress = 0usize;
    let mut cur_progress_time = Instant::now();
    let mut term = term::stderr().unwrap();
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
            term.carriage_return().ok();
            term.delete_line().ok();
            write!(
                term, "Progress: {}, Speed: {}/s, Time: {}",
                end_period_progress.file_size(ConventionalSize).unwrap(),
                speed.file_size(ConventionalSize).unwrap(),
                human_readable_duration(Instant::now() - start_time),
            ).ok();
            if final_print && has_ever_printed {
                writeln!(term).ok();
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

#[derive(Debug, StructOpt)]
// #[structopt(name = "sodium-codec", about = "A command line utility to do encryption/decryption.")]
enum Opt {
//    /// Set speed
//    #[structopt(short = "s", long = "speed", default_value = "42")]
//    speed: f64,

    #[structopt(name = "enc")]
    Encrypt {
        /// Input path ("-" for stdin)
        #[structopt(parse(from_os_str))]
        input: PathBuf,

        /// Output path ("-" for stdout)
        #[structopt(parse(from_os_str))]
        output: PathBuf,

        /// Password
        #[structopt(short = "p", long = "password")]
        password: Option<String>,

        #[structopt(long = "algorithm", default_value = "xchacha20")]
        algorithm: String,
    },

    #[structopt(name = "dec")]
    Decrypt {
        /// Input path ("-" for stdin)
        #[structopt(parse(from_os_str))]
        input: PathBuf,

        /// Output path ("-" for stdout)
        #[structopt(parse(from_os_str))]
        output: PathBuf,

        /// Password
        #[structopt(short = "p", long = "password")]
        password: Option<String>,

        #[structopt(long = "algorithm", default_value = "xchacha20")]
        algorithm: String,
    }
}

#[allow(dead_code)]
fn to_hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter()
       .map(|b| format!("{:02X}", b))
       .collect::<Vec<String>>()
       .join("")
}

fn main() -> Result<(), Error> {
    sodiumoxide::init().map_err(MyError::InitError)?;
    let opt = Opt::from_args();

    match &opt {
        Opt::Encrypt {input, output, password, algorithm} |
        Opt::Decrypt {input, output, password, algorithm} => {
            let (progress_sender, progress_thread) = start_progress_thread();

            let codec: Box<StreamCodec> = match algorithm.as_str() {
                "xchacha20" => Box::new(XChaCha20::new()),
                "aes256gcm" => Box::new(Aes256Gcm::new(false)),
                "aes256gcm-ext" => Box::new(Aes256Gcm::new(true)),
                _ => return Err(MyError::UnknownAlgorithm(algorithm.clone()).into()),
            };
            let codec_config = codec.get_config();

            let key: Vec<u8> = if let Some(password) = password {
                derive_key_from_password(password.as_str(), codec_config.key_size)
            } else {
                return Err(MyError::PasswordRequired.into());
            };

            // Channels
            let (initial_sender, read_receiver) = unbounded_channel();
            let (read_sender, codec_receiver) = unbounded_channel();
            let (codec_sender, write_receiver) = unbounded_channel();
            let (write_sender, final_receiver) = unbounded_channel();

            let header_size = match &opt {
                Opt::Encrypt{..} => None,
                Opt::Decrypt{..} => Some(codec_config.header_size),
            };

            let (read_thread, _file_size) = start_read_thread(
                input.clone(), read_receiver, read_sender, header_size
            )?;

            let mut stream_converter = match &opt {
                Opt::Encrypt{..} => {
                    let (header, stream_converter) = codec.start_encoding(key)?;
                    codec_sender.send(Chunk{buffer: header, offset: 0, is_last_chunk: false})?;
                    stream_converter
                },
                Opt::Decrypt{..} => {
                    let header = codec_receiver.recv()?;
                    codec.start_decoding(key, header.buffer)?
                },
            };
            let ChunkConfig {input_chunk_offset, input_chunk_asize, output_chunk_asize} = stream_converter.get_chunk_config();

            let codec_thread = thread::spawn(move || stream_converter.convert_blocking(codec_receiver, codec_sender));
            let write_thread = start_write_thread(output.clone(),write_receiver, write_sender);

            // Send initial buffers in to start the pipeline.
            let input_chunk_size = input_chunk_offset + CHUNK_SIZE + input_chunk_asize;
            let buf_capacity = input_chunk_offset + CHUNK_SIZE +
                std::cmp::max(input_chunk_asize, output_chunk_asize) + 1;  // +1 byte to allow reader to check Eof
            for _ in 0..5 {
                let mut buffer = Vec::with_capacity(buf_capacity);
                buffer.resize(input_chunk_size, 0);
                initial_sender.send(Chunk{
                    buffer,
                    offset: input_chunk_offset,
                    is_last_chunk: false,
                })?;
            }

            // Wait while pipeline works, resupplying used buffers back to the reader.
            for mut chunk in final_receiver {
                progress_sender.send(chunk.buffer.len())?;
                if chunk.buffer.capacity() == buf_capacity {
                    chunk.offset = input_chunk_offset;
                    chunk.buffer.resize(input_chunk_size, 0);
                    initial_sender.send(chunk).ok();  // Ok to drop vectors when reading has stopped.
                }
            }
            std::mem::drop(progress_sender);

            progress_thread.join().map_err(|_| MyError::ThreadJoinError)?;
            read_thread.join().map_err(|_| MyError::ThreadJoinError)??;
            codec_thread.join().map_err(|_| MyError::ThreadJoinError)??;
            write_thread.join().map_err(|_| MyError::ThreadJoinError)??;
        },
    }

    Ok(())
}
