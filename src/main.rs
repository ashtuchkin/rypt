use std::io::{Read, Write, ErrorKind, stdin, stdout};
use std::path::PathBuf;
use std::fs::{File, metadata};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

use structopt::StructOpt;
use sodiumoxide::crypto::pwhash;
use failure::{Fail, Error};
use humansize::{FileSize, file_size_opts::CONVENTIONAL as ConventionalSize};
use crossbeam_channel::{Sender, Receiver, unbounded as unbounded_channel, tick};
use libsodium_sys::{
    crypto_secretstream_xchacha20poly1305_state as StreamState,
    crypto_secretstream_xchacha20poly1305_init_push as init_push,
    crypto_secretstream_xchacha20poly1305_push as stream_push,
    crypto_secretstream_xchacha20poly1305_init_pull as init_pull,
    crypto_secretstream_xchacha20poly1305_pull as stream_pull,
};
use std::os::raw::c_ulonglong;

const ABYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;
const KEYBYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;
const HEADERBYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;
const TAG_MESSAGE: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8;
const TAG_FINAL: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8;

const CHUNK_SIZE: usize = 1 * 1024 * 1024;

#[derive(Fail, Debug)]
enum MyError {
    #[fail(display = "Sodium library initialization error")]
    InitError(()),

    #[fail(display = "Password required")]
    PasswordRequired,

    #[fail(display = "Decryption Error")]
    DecryptionError,

    #[fail(display = "Invalid header")]
    InvalidHeader,

    #[fail(display = "Thread Join Error")]
    ThreadJoinError,
}

#[derive(Debug)]
struct Chunk {
    pub buffer: Vec<u8>,
    pub reserved_prefix_size: usize,
    pub last_chunk: bool,
}

fn start_encode_thread(input: Receiver<Chunk>, output: Sender<Chunk>, key: Vec<u8>) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        assert_eq!(key.len(), KEYBYTES);
        let mut header = vec![0u8; HEADERBYTES];
        let mut state: StreamState = unsafe {
            let mut state: StreamState = std::mem::zeroed();
            init_push(&mut state, header.as_mut_ptr(), key.as_ptr()); // NOTE: init_push always succeeds.
            state
        };
        output.send(Chunk{buffer: header, reserved_prefix_size: 0, last_chunk: false})?;

        for mut chunk in input {
            const PREFIX_SIZE: usize = 1;
            const SUFFIX_SIZE: usize = ABYTES - PREFIX_SIZE;
            assert!(chunk.reserved_prefix_size >= PREFIX_SIZE);

            let plaintext_len = chunk.buffer.len() - chunk.reserved_prefix_size;
            chunk.buffer.resize(chunk.buffer.len() + SUFFIX_SIZE, 0);
            let tag = if chunk.last_chunk {TAG_FINAL} else {TAG_MESSAGE} as u8;

            unsafe {
                // NOTE: `stream_push` always succeeds.
                // NOTE: The buffer is encoded in-place. This is only possible due to the pointer shift
                // made by PREFIX_SIZE. (see function's internals at https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L147
                // and the fact that crypto_stream_chacha20_ietf_xor_ic can do encryption in-place: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20#usage)
                stream_push(
                    &mut state,
                    chunk.buffer.as_mut_ptr().offset((chunk.reserved_prefix_size - PREFIX_SIZE) as isize),
                    std::ptr::null_mut(),
                    chunk.buffer.as_ptr().offset(chunk.reserved_prefix_size as isize),
                    plaintext_len as c_ulonglong,
                    std::ptr::null(),
                    0 as c_ulonglong,
                    tag,
                );
            }
            chunk.reserved_prefix_size -= PREFIX_SIZE;
            output.send(chunk)?;
        }
        Ok(())
    })
}

fn start_decode_thread(input: Receiver<Chunk>, output: Sender<Chunk>, key: Vec<u8>) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        assert_eq!(key.len(), KEYBYTES);

        // 1. Receive the header.
        let header = input.recv()?;
        assert_eq!(header.buffer.len(), HEADERBYTES);
        assert_eq!(header.reserved_prefix_size, 0);

        // 2. Initialize the stream state.
        let mut state: StreamState = unsafe {
            let mut state: StreamState = std::mem::zeroed();
            let rc = init_pull(&mut state, header.buffer.as_ptr(), key.as_ptr());
            if rc != 0 {
                return Err(MyError::InvalidHeader.into());
            }
            state
        };

        for mut chunk in input {
            const PREFIX_SIZE: usize = 1;
            const SUFFIX_SIZE: usize = ABYTES - PREFIX_SIZE;
            let chunk_size = chunk.buffer.len() - chunk.reserved_prefix_size;
            if chunk_size < ABYTES {
                return Err(MyError::DecryptionError.into());  // Chunk too small to be valid.
            }
            let mut tag: u8 = unsafe { std::mem::zeroed() };

            let rc = unsafe {
                // NOTE: The buffer is decoded in-place. This is only possible due to the pointer shift
                // made by PREFIX_SIZE. (see function's internals at https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L147
                // and the fact that crypto_stream_chacha20_ietf_xor_ic can do encryption in-place: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20#usage)
                stream_pull(
                    &mut state,
                    chunk.buffer.as_mut_ptr().offset((chunk.reserved_prefix_size + PREFIX_SIZE) as isize),
                    std::ptr::null_mut(),
                    &mut tag,
                    chunk.buffer.as_ptr().offset(chunk.reserved_prefix_size as isize),
                    chunk_size as c_ulonglong,
                    std::ptr::null(),
                    0 as c_ulonglong,
                )
            };
            if rc != 0 {
                return Err(MyError::DecryptionError.into());  // Invalid chunk.
            }
            if (tag == TAG_FINAL) != chunk.last_chunk {
                return Err(MyError::DecryptionError.into());  // Final chunk is not the last chunk.
            }

            chunk.buffer.truncate(chunk.buffer.len() - SUFFIX_SIZE);
            chunk.reserved_prefix_size += PREFIX_SIZE;
            output.send(chunk)?;
        }
        Ok(())
    })
}

fn start_read_thread(input_path: PathBuf, input: Receiver<Vec<u8>>, output: Sender<Chunk>,
                     chunk_size: usize, reserved_prefix_size: usize, header_size: Option<usize>)
                        -> Result<(thread::JoinHandle<Result<(), Error>>, Option<u64>), Error> {
    let stdin = stdin();
    let (mut input_stream, filesize): (Box<Read + Send>, Option<u64>) = match input_path.to_str() {
        Some("-") => (Box::new(stdin), None),
        _ => (Box::new(File::open(&input_path)?), Some(metadata(&input_path)?.len())),
    };

    let handle = thread::spawn(move || -> Result<(), Error> {
        if let Some(header_size) = header_size {
            let mut header_buf = vec![0u8; header_size];
            input_stream.read_exact(header_buf.as_mut_slice())?;
            output.send(Chunk {buffer: header_buf, reserved_prefix_size: 0, last_chunk: false})?;
        }

        let total_buf_size = reserved_prefix_size + chunk_size + 1;
        let mut last_byte = None;

        for mut buffer in input {
            buffer.resize(total_buf_size, 0);
            let mut read_ptr = if let Some(last_byte) = last_byte {
                buffer[reserved_prefix_size] = last_byte;
                reserved_prefix_size + 1
            } else {
                reserved_prefix_size
            };

            while read_ptr < total_buf_size {
                match input_stream.read(&mut buffer[read_ptr..]) {
                    Ok(read_bytes) => {
                        if read_bytes > 0 {
                            // Continue reading into the buffer, adjusting the slices.
                            read_ptr += read_bytes;

                        } else {
                            // Reached end of file. Send the last chunk.
                            buffer.truncate(read_ptr);
                            output.send(Chunk {buffer, reserved_prefix_size, last_chunk: true})?;
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

            // Stream has more data; keep last piece and send remaining data
            last_byte = Some(*buffer.last().unwrap());

            buffer.truncate(reserved_prefix_size + chunk_size);
            output.send(Chunk {buffer, reserved_prefix_size, last_chunk: false})?;
        }
        Err(std::io::Error::from(ErrorKind::NotConnected).into())
    });

    Ok((handle, filesize))
}

fn start_write_thread(output_path: PathBuf, input: Receiver<Chunk>, output: Sender<Vec<u8>>) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        let stdout = stdout();
        let mut output_stream: Box<Write> = match output_path.to_str() {
            Some("-") => Box::new(stdout.lock()),
            _ => Box::new(File::create(output_path)?),
        };

        for chunk in input {
            output_stream.write_all(&chunk.buffer[chunk.reserved_prefix_size..])?;
            if chunk.last_chunk {
                output_stream.flush()?;
            }
            output.send(chunk.buffer)?;
        }
        Ok(())
    })
}

fn derive_key_from_password(password: &str) -> Vec<u8> {
    let key = &mut [0u8; KEYBYTES];  // KEYBYTES = 32
    let salt =   // NOTE: We use static salt.
        "rust-crypto-test-salt".bytes().cycle().take(pwhash::SALTBYTES).collect::<Vec<u8>>();
    let salt = pwhash::Salt::from_slice(&salt).unwrap();
    pwhash::derive_key_interactive(key, password.as_bytes(), &salt).unwrap();

    key.to_vec()
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
        Opt::Encrypt {input, output, password} |
        Opt::Decrypt {input, output, password} => {
            let (progress_sender, progress_thread) = start_progress_thread();

            let key: Vec<u8> = if let Some(password) = password {
                derive_key_from_password(password.as_str())
            } else {
                return Err(MyError::PasswordRequired.into());
            };

            // Channels
            let (initial_sender, read_receiver) = unbounded_channel();
            let (read_sender, codec_receiver) = unbounded_channel();
            let (encodec_sender, write_receiver) = unbounded_channel();
            let (write_sender, final_receiver) = unbounded_channel();

            const PREFIX_SIZE: usize = 16;  // Must be >= 1; we use 16 for better alignment.
            const SUFFIX_SIZE: usize = 16;  // Must be >= 16
            const BUF_CAPACITY: usize = PREFIX_SIZE + CHUNK_SIZE + SUFFIX_SIZE + 1;  // +1 byte to allow reader to check Eof

            // Threads
            let (chunk_size, prefix_size, header_size) = match &opt {
                Opt::Encrypt{..} => (CHUNK_SIZE, PREFIX_SIZE, None),
                Opt::Decrypt{..} => (CHUNK_SIZE + SUFFIX_SIZE + 1, PREFIX_SIZE - 1, Some(HEADERBYTES)),
            };
            let (read_thread, _file_size) = start_read_thread(
                input.clone(), read_receiver, read_sender, chunk_size, prefix_size, header_size
            )?;
            let codec_thread = match &opt {
                Opt::Encrypt{..} => start_encode_thread(codec_receiver, encodec_sender, key),
                Opt::Decrypt{..} => start_decode_thread(codec_receiver, encodec_sender, key),
            };
            let write_thread = start_write_thread(output.clone(),write_receiver, write_sender);

            // Send initial buffers in to start the pipeline.
            for _ in 0..5 {
                initial_sender.send(Vec::with_capacity(BUF_CAPACITY))?;
            }

            // Wait while pipeline works, resupplying used buffers back to the reader.
            for buf in final_receiver {
                progress_sender.send(buf.len())?;
                if buf.capacity() == BUF_CAPACITY {
                    initial_sender.send(buf).ok();  // Ok to drop vectors when reading has stopped.
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
