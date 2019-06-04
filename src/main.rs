use std::io::{Read, Write, ErrorKind, stdin, stdout};
use std::path::PathBuf;
use std::fs::File;
use std::thread;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use structopt::StructOpt;
use sodiumoxide::crypto::secretstream::{Stream, Header, Tag, Key, HEADERBYTES, KEYBYTES, ABYTES};
use sodiumoxide::crypto::pwhash;
use failure::{Fail, Error};
use humansize::{FileSize, file_size_opts::CONVENTIONAL as ConventionalSize};
use std::collections::VecDeque;

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

fn decode_stream(input_stream: &mut Read, output_stream: &mut Write, key: &Key, mut progress_cb: Box<FnMut(usize)->()>) -> Result<(), Error> {
    let header_buf = &mut [0u8; HEADERBYTES];  // HEADERBYTES = 24.
    input_stream.read_exact(header_buf)?;
    let header = Header::from_slice(header_buf).unwrap();

    let mut dec_stream = Stream::init_pull(&header, &key)
        .map_err(MyError::DecryptionError)?;

    let last_piece = read_chunks(input_stream, BUF_SIZE + ABYTES, ABYTES, |ciphertext| {
        //dbg!(ciphertext.len());
        //dbg!(to_hex_string(ciphertext));
        let (plaintext, _tag) = dec_stream.pull(ciphertext, None)
            .map_err(MyError::DecryptionError)?;
        assert!(ciphertext.len() == plaintext.len() + ABYTES);
        output_stream.write_all(&plaintext)?;
        progress_cb(plaintext.len());
        Ok(())
    })?;
    //dbg!(last_piece.len());
    //dbg!(to_hex_string(&last_piece));

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

fn start_progress_thread() -> (mpsc::Sender<usize>, thread::JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel();

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
                Err(mpsc::RecvTimeoutError::Timeout) => {
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
                Err(mpsc::RecvTimeoutError::Disconnected) => {
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
            let (mut input_stream, mut output_stream) = open_streams(input, output)?;

            let key: Key = if let Some(password) = password {
                derive_key_from_password(password.as_str())
            } else {
                return Err(MyError::PasswordRequired.into());
            };

            encode_stream(&mut input_stream, &mut output_stream, &key, Box::new(move |inc_progress| {
                progress_sender.send(inc_progress).unwrap();
            }))?;
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
