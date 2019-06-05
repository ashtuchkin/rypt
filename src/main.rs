use std::io::{Read, Write, ErrorKind, stdin, stdout};
use std::path::PathBuf;
use std::fs::File;
use std::thread;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

use structopt::StructOpt;
use sodiumoxide::crypto::secretstream::{Stream, Header, Tag, Key, HEADERBYTES, KEYBYTES, ABYTES};
use sodiumoxide::crypto::pwhash;
use failure::{Fail, Error};
use humansize::{FileSize, file_size_opts::CONVENTIONAL as ConventionalSize};
use crossbeam_channel::{Sender, Receiver, unbounded as unbounded_channel, RecvTimeoutError};
use libsodium_sys::{
//    crypto_secretstream_xchacha20poly1305_ABYTES as ABYTES,
//    crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES,
//    crypto_secretstream_xchacha20poly1305_HEADERBYTES as HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_init_push as init_push,
    crypto_secretstream_xchacha20poly1305_push as stream_push,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_state as StreamState,
};
use std::os::raw::c_ulonglong;

const BUF_SIZE: usize = 1 * 1024 * 1024;

#[derive(Fail, Debug)]
enum MyError {
    #[fail(display = "Sodium library initialization error")]
    InitError(()),

    #[fail(display = "Password required")]
    PasswordRequired,

    #[fail(display = "Encryption Error")]
    EncryptionError(()),

    #[fail(display = "Decryption Error")]
    DecryptionError(()),

    #[fail(display = "Thread Join Error")]
    ThreadJoinError,
}

// * Fill up the buffer up to buf_size and pass it to the callback (except the last chunk)
// * Always keep `last_piece_size` bytes at the end and return it after the end of iteration
// * Retry ErrorKind::Interrupted.
fn read_chunks(input_stream: &mut Read, buf_size: usize, last_piece_size: usize,
                 mut cb: impl FnMut(&[u8]) -> Result<(), Error>) -> Result<Vec<u8>, Error> {
    let total_buf_size = buf_size + last_piece_size + 1;
    let mut buffer = vec![0u8; total_buf_size];
    let mut read_ptr = 0usize;

    loop {
        while read_ptr < total_buf_size {
            match input_stream.read(&mut buffer[read_ptr..]) {
                Ok(read_bytes) => {
                    if read_bytes > 0 {
                        // Continue reading into the buffer, adjusting the slices.
                        read_ptr += read_bytes;

                    } else {
                        // Reached end of file. Extract the last piece
                        if read_ptr < last_piece_size {
                            return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into());
                        } else if read_ptr > last_piece_size {
                            cb(&buffer[..read_ptr-last_piece_size])?;
                        }
                        let last_piece = &buffer[read_ptr-last_piece_size..read_ptr];
                        assert_eq!(last_piece.len(), last_piece_size);
                        return Ok(last_piece.to_vec())
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

        // Stream has more data; process this chunk and continue
        cb(&buffer[..buf_size])?;

        // Move bytes from the last piece to the beginning and reset reading_space.
        let (main_buf, last_piece) = buffer.split_at_mut(buf_size);
        main_buf[..last_piece_size+1].copy_from_slice(last_piece);
        read_ptr = last_piece_size+1;
    }
}

fn start_encode_thread(input: Receiver<Vec<u8>>, output: Sender<Vec<u8>>, key: Key) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        let mut header = vec![0u8; HEADERBYTES];
        let mut state: StreamState = unsafe { std::mem::uninitialized() };
        let rc = unsafe {
            init_push(&mut state, header.as_mut_ptr(), key.0.as_ptr())
        };
        if rc != 0 {
            return Err(MyError::EncryptionError(()).into());
        }

        output.send(header)?;

        for mut plaintext in input {
            let plaintext_len = plaintext.len();
            let ciphertext_len = plaintext_len + ABYTES;
            plaintext.resize(ciphertext_len, 0);

            let rc = unsafe {
                stream_push(
                    &mut state,
                    plaintext.as_mut_ptr(),
                    &mut (ciphertext_len as c_ulonglong),
                    plaintext.as_ptr(),
                    plaintext_len as c_ulonglong,
                    std::ptr::null(),
                    0 as c_ulonglong,
                    TAG_MESSAGE as u8,
                )
            };
            if rc != 0 {
                return Err(MyError::EncryptionError(()).into());
            }
            let ciphertext = plaintext;

//            let ciphertext = enc_stream.push(&plaintext, None, Tag::Message)
//                .map_err()?;
            //assert!(ciphertext.len() == plaintext.len() + ABYTES);  // ABYTES = 17
            output.send(ciphertext)?;
        }

        let ciphertext_len = ABYTES;
        let mut ciphertext = vec![0u8; ABYTES];
        let rc = unsafe {
            stream_push(
                &mut state,
                ciphertext.as_mut_ptr(),
                &mut (ciphertext_len as c_ulonglong),
                ciphertext.as_ptr(),
                0 as c_ulonglong,
                std::ptr::null(),
                0 as c_ulonglong,
                TAG_FINAL as u8,
            )
        };
        if rc != 0 {
            return Err(MyError::EncryptionError(()).into());
        }


//        let ciphertext = enc_stream.finalize(None)
//            .map_err(MyError::EncryptionError)?;
        output.send(ciphertext)?;
        Ok(())
    })
}

fn start_read_thread(input_path: PathBuf, input: Receiver<Vec<u8>>, output: Sender<Vec<u8>>,
                     chunk_size: usize, last_piece_size: usize) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        let stdin = stdin();
        let mut input_stream: Box<Read> = match input_path.to_str() {
            Some("-") => Box::new(stdin.lock()),
            _ => Box::new(File::open(input_path)?),
        };

        let total_buf_size = chunk_size + last_piece_size + 1;
        let mut last_piece: Option<Vec<u8>> = None;

        for mut buffer in input {
            buffer.resize(total_buf_size, 0);
            let mut read_ptr = if let Some(ref last_piece) = last_piece {
                buffer[..last_piece_size+1].copy_from_slice(&last_piece);
                last_piece_size+1
            } else {
                0usize
            };

            while read_ptr < total_buf_size {
                match input_stream.read(&mut buffer[read_ptr..]) {
                    Ok(read_bytes) => {
                        if read_bytes > 0 {
                            // Continue reading into the buffer, adjusting the slices.
                            read_ptr += read_bytes;

                        } else {
                            // Reached end of file. Extract the last piece
                            if read_ptr < last_piece_size {
                                return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into());
                            } else {
                                let mut last_piece = match last_piece.take() {
                                    Some(mut piece) => { piece.truncate(last_piece_size); piece },
                                    None => vec![0u8; last_piece_size],
                                };
                                last_piece.copy_from_slice(&buffer[read_ptr-last_piece_size..read_ptr]);

                                buffer.truncate(read_ptr-last_piece_size);
                                if !buffer.is_empty() {
                                    output.send(buffer)?;
                                }
                                if !last_piece.is_empty() {
                                    output.send(last_piece)?;
                                }
                                return Ok(());
                            }
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
            last_piece.get_or_insert_with(|| vec![0u8; last_piece_size+1])
                .copy_from_slice(&buffer[chunk_size..]);

            buffer.truncate(chunk_size);
            output.send(buffer)?;
        }
        Err(std::io::Error::from(ErrorKind::NotConnected).into())
    })
}

fn start_write_thread(output_path: PathBuf, input: Receiver<Vec<u8>>, output: Sender<Vec<u8>>) -> thread::JoinHandle<Result<(), Error>> {
    thread::spawn(move || -> Result<(), Error> {
        let stdout = stdout();
        let mut output_stream: Box<Write> = match output_path.to_str() {
            Some("-") => Box::new(stdout.lock()),
            _ => Box::new(File::create(output_path)?),
        };

        for buffer in input {
            output_stream.write_all(&buffer)?;
            output.send(buffer)?;
        }
        Ok(())
    })
}

/*
fn encode_stream(input_stream: &mut Read, output_stream: &mut Write, key: &Key, mut progress_cb: Box<FnMut(usize)->()>) -> Result<(), Error> {
    let (mut enc_stream, header) = Stream::init_push(&key)
        .map_err(MyError::EncryptionError)?;

    assert!(header.as_ref().len() == HEADERBYTES);
    output_stream.write_all(header.as_ref())?;

    read_chunks(input_stream, BUF_SIZE, 0,|plaintext| {
        let ciphertext = enc_stream.push(plaintext, None, Tag::Message)
            .map_err(MyError::EncryptionError)?;
        assert!(ciphertext.len() == plaintext.len() + ABYTES);  // ABYTES = 17
        output_stream.write_all(&ciphertext)?;
        progress_cb(ciphertext.len());
        Ok(())
    })?;

    let ciphertext = enc_stream.finalize(None)
        .map_err(MyError::EncryptionError)?;
    output_stream.write_all(&ciphertext)?;
    progress_cb(ciphertext.len());

    output_stream.flush()?;

    Ok(())
}
*/
fn decode_stream(input_stream: &mut Read, output_stream: &mut Write, key: &Key, mut progress_cb: Box<FnMut(usize)->()>) -> Result<(), Error> {
    let header_buf = &mut [0u8; HEADERBYTES];  // HEADERBYTES = 24.
    input_stream.read_exact(header_buf)?;
    let header = Header::from_slice(header_buf).unwrap();

    let mut dec_stream = Stream::init_pull(&header, &key)
        .map_err(MyError::DecryptionError)?;

    let last_piece = read_chunks(input_stream, BUF_SIZE + ABYTES, ABYTES, |ciphertext| {
        let (plaintext, _tag) = dec_stream.pull(ciphertext, None)
            .map_err(MyError::DecryptionError)?;
        assert!(ciphertext.len() == plaintext.len() + ABYTES);
        output_stream.write_all(&plaintext)?;
        progress_cb(plaintext.len());
        Ok(())
    })?;

    let (plaintext, tag) = dec_stream.pull(&last_piece, None)
        .map_err(MyError::DecryptionError)?;
    assert!(plaintext.len() == 0 && tag == Tag::Final);
    assert!(dec_stream.is_finalized());

    output_stream.flush()?;

    Ok(())
}

fn derive_key_from_password(password: &str) -> Key {
    let key = &mut [0u8; KEYBYTES];  // KEYBYTES = 32
    let salt =   // NOTE: We use static salt.
        "rust-crypto-test-salt".bytes().cycle().take(pwhash::SALTBYTES).collect::<Vec<u8>>();
    let salt = pwhash::Salt::from_slice(&salt).unwrap();
    pwhash::derive_key_interactive(key, password.as_bytes(), &salt).unwrap();

    Key::from_slice(key).unwrap()
}

fn open_streams(input: PathBuf, output: PathBuf) -> Result<(Box<Read>, Box<Write>), std::io::Error> {
    let input_stream: Box<Read> = match input.to_str() {
        Some("-") => Box::new(stdin()),
        _ => Box::new(File::open(input)?),
    };

    let output_stream: Box<Write> = match output.to_str() {
        Some("-") => Box::new(stdout()),
        _ => Box::new(File::create(output)?),
    };

    Ok((input_stream, output_stream))
}

fn start_progress_thread() -> (Sender<usize>, thread::JoinHandle<()>) {
    let (sender, receiver) = unbounded_channel();

    let join_handle = thread::spawn(move || {
        const PRINT_PERIOD: Duration = Duration::from_millis(500);
        const ADD_STAMP_PERIOD: Duration = Duration::from_millis(250);
        const KEEP_STAMPS: usize = 40;  // average over 10 seconds

        let mut cur_progress = 0usize;
        let mut term = term::stderr().unwrap();
        let mut has_ever_printed = false;
        let now = Instant::now();
        let mut last_printed_time = now;
        let mut last_added_time = now;
        let mut stamps = VecDeque::new();
        stamps.push_front((now, cur_progress));

        loop {
            let passed_time = Instant::now() - last_printed_time;
            let timeout = if PRINT_PERIOD > passed_time  {
                PRINT_PERIOD - passed_time
            } else {
                Duration::from_millis(0)
            };
            match receiver.recv_timeout(timeout) {
                Ok(increment_size) => {
                    cur_progress += increment_size;
                    let now = Instant::now();
                    while now > last_added_time + ADD_STAMP_PERIOD {
                        stamps.push_back((now, cur_progress));
                        last_added_time += ADD_STAMP_PERIOD;
                    }
                    while stamps.len() > KEEP_STAMPS {
                        stamps.pop_front();
                    }
                },
                Err(RecvTimeoutError::Timeout) => {
                    // Print current values.
                    term.carriage_return().ok();
                    term.delete_line().ok();
                    let (start_time, start_progress) = stamps.front().unwrap();
                    let (end_time, end_progress) = stamps.back().unwrap();
                    let delta_time = (*end_time - *start_time).as_millis() as usize;
                    let delta_progress = end_progress - start_progress;
                    if delta_time > 0 && delta_progress > 0 {
                        let speed = delta_progress * 1000 / delta_time;
                        write!(
                            term, "Progress: {}, Speed: {}/s",
                            end_progress.file_size(ConventionalSize).unwrap(),
                            speed.file_size(ConventionalSize).unwrap(),
                        ).ok();
                        has_ever_printed = true;
                    }
                    last_printed_time += PRINT_PERIOD;
                },
                Err(RecvTimeoutError::Disconnected) => {
                    if has_ever_printed {
                        writeln!(term).ok();
                    }
                    break;
                },
            }
        }
    });

    (sender, join_handle)
}

#[derive(Debug, StructOpt)]
// #[structopt(name = "sodium-codec", about = "A command line utility to do encryption/decryption.")]
enum Opt {
//    /// Activate debug mode
//    #[structopt(short = "d", long = "debug")]
//    debug: bool,
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
    let (progress_sender, progress_thread) = start_progress_thread();

    match opt {
        Opt::Encrypt {input, output, password} => {
            let key: Key = if let Some(password) = password {
                derive_key_from_password(password.as_str())
            } else {
                return Err(MyError::PasswordRequired.into());
            };

            // Channels
            let (initial_sender, read_receiver) = unbounded_channel();
            let (read_sender, encode_receiver) = unbounded_channel();
            let (encode_sender, write_receiver) = unbounded_channel();
            let (write_sender, initial_receiver) = unbounded_channel();

            // Threads
            let read_thread = start_read_thread(
                input, read_receiver, read_sender, BUF_SIZE, 0
            );
            let encode_thread = start_encode_thread(encode_receiver, encode_sender, key);
            let write_thread = start_write_thread(output,write_receiver, write_sender);

            // Send initial buffers in to start the pipeline.
            for _ in 0..5 {
                initial_sender.send(Vec::with_capacity(BUF_SIZE + ABYTES))?;
            }

            // Wait while pipeline works, resupplying buffers.
            for buf in initial_receiver {
                progress_sender.send(buf.len())?;
                if buf.capacity() >= BUF_SIZE + ABYTES {
                    initial_sender.send(buf)?;
                }
            }
            std::mem::drop(initial_sender);

            read_thread.join().map_err(|_| MyError::ThreadJoinError)??;
            encode_thread.join().map_err(|_| MyError::ThreadJoinError)??;
            write_thread.join().map_err(|_| MyError::ThreadJoinError)??;
        },
        Opt::Decrypt {input, output, password} => {
            let (mut input_stream, mut output_stream) = open_streams(input, output)?;

            let key: Key = if let Some(password) = password {
                derive_key_from_password(password.as_str())
            } else {
                return Err(MyError::PasswordRequired.into());
            };

            decode_stream(&mut input_stream, &mut output_stream, &key, Box::new(move |inc_progress| {
                progress_sender.send(inc_progress).unwrap();
            }))?;
        },
    }

    progress_thread.join().unwrap();  // NOTE: Ensure progress_sender is dropped before this.

    Ok(())
}
