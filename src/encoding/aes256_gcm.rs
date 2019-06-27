use std::os::raw::{c_ulonglong, c_void};

use crossbeam_channel::{Receiver, Sender};
use failure::Fallible;
use libsodium_sys::{
    crypto_aead_aes256gcm_decrypt as aes256gcm_decrypt,
    crypto_aead_aes256gcm_encrypt as aes256gcm_encrypt,
    crypto_aead_aes256gcm_is_available as aes256gcm_is_available,
    crypto_aead_aes256gcm_messagebytes_max as messagebytes_max, crypto_hash_sha512 as hash_sha512,
    randombytes_buf, sodium_increment,
};

use crate::errors::MyError;
use crate::header::AES256GCMConfig;
use crate::types::{Chunk, ChunkConfig, StreamCodec, StreamCodecConfig, StreamConverter};

const ABYTES: usize = libsodium_sys::crypto_aead_aes256gcm_ABYTES as usize; // 16
const KEYBYTES: usize = libsodium_sys::crypto_aead_aes256gcm_KEYBYTES as usize; // 32
const NONCE_BYTES: usize = libsodium_sys::crypto_aead_aes256gcm_NPUBBYTES as usize; // 12 (regular nonce length)
const SHA512_BYTES: usize = libsodium_sys::crypto_hash_sha512_BYTES as usize; // 64 bytes.

const LONG_NONCE_BYTES: usize = 24; // 192 bits should be enough to allow random nonces.
const MESSAGE_COUNTER_BYTES: usize = 8;

const STATE_BYTES: usize = LONG_NONCE_BYTES + MESSAGE_COUNTER_BYTES + KEYBYTES; // 64 bytes

/*
This is an implementation of AES256-GCM streaming encoding/decoding with authentication.
For each chunk, the nonce is 96 bit (12 bytes); remaining 32 bits are used as a counter within the chunk.
 => This means chunks can be no larger than (2^32 - 2) * 16 bytes = 32 bytes less than 64 Gb (note counter starts with 2).
    this is stored in messagebytes_max() and is checked by the encoding functions.

Reference: NIST SP 800-38D (https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf).
As described in section 8.2 of the above document, there can be several options for constructing IV (Nonce).
Deterministic mode is unpractical to use here, so we use RBG-based (as described in section 8.2.2).
In short this means we choose a random initial Nonce, then incrementing it for each subsequent message.
This nonce is stored in the stream header, so that decryption can use it as well.
With a target max probability for collision at 2^-32 (as recommended by NIST), birthday paradox formula
gives us an estimate that we can encrypt ~6*10^9 chunks safely, which maps to 6 petabytes of data if using
1 Mb sized chunks.

See also discussion in https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#nonces

If that estimate is not enough, we can use a nonce extension algorithm as described in
https://libsodium.gitbook.io/doc/secret-key_cryptography/encrypted-messages#short-nonces
    * Generate a much longer random nonce N (we use 192 bits = 24 bytes), save it in the file header.
    * Keep a 64 bit counter of messages I.
    * For each message, increment I, then use (key, nonce) = HASH(I || N || K), where K is the original key.
      For compatibility and performance, we use raw SHA512 as the HASH function here. No need for HMAC or anything like that.

Note that there are several differences with libsodium secretstream construction (https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream):
 1. Chunks are authenticated independently, not using data from previous chunks. This will help localize
    stream errors to a single chunk and, potentially, implement parallelization of chunk encoding/decoding
    in the future. Given that each chunk's key and nonce are one-way derived from the message counter,
    this shouldn't affect any safety properties.
 2. "Tag" byte is not used. This algorithm does not require rekeying (64 bit overflow is not practical),
    plus adding a straw byte to the ciphertext screws up the byte alignment, slowing down both encoding and .
    One downside is that we can't mark a message as "final". The only case when it matters is when the
    plaintext is whole number of chunks in length and we'll need to read one more chunk to reject the
    attacker's extension. Seems like a good tradeoff.
*/

fn header_size(extended_nonce: bool) -> usize {
    if extended_nonce {
        LONG_NONCE_BYTES
    } else {
        NONCE_BYTES
    }
}

pub struct Aes256Gcm {
    extended_nonce: bool, // Whether we use nonce extension mechanism, or just random 96-bit nonce.
}

impl Aes256Gcm {
    pub fn new(config: &AES256GCMConfig) -> Aes256Gcm {
        Aes256Gcm {
            extended_nonce: config.extended_nonce,
        }
    }
}

impl StreamCodec for Aes256Gcm {
    fn get_config(&self) -> StreamCodecConfig {
        StreamCodecConfig {
            header_size: header_size(self.extended_nonce),
            key_size: KEYBYTES,
        }
    }

    fn start_encoding(
        &self,
        key: Vec<u8>,
        authenticate_data: Option<Vec<u8>>,
    ) -> Fallible<(Vec<u8>, Box<StreamConverter>)> {
        let (converter, header) =
            Aes256GcmEncoder::new(key, authenticate_data, self.extended_nonce)?;
        Ok((header, Box::new(converter)))
    }

    fn start_decoding(
        &self,
        key: Vec<u8>,
        header: Vec<u8>,
        authenticate_data: Option<Vec<u8>>,
    ) -> Fallible<Box<StreamConverter>> {
        Ok(Box::new(Aes256GcmDecoder::new(
            key,
            header,
            authenticate_data,
            self.extended_nonce,
        )?))
    }
}

struct Aes256GcmEncoder {
    state: [u8; STATE_BYTES], // 32 byte key, 24 byte long nonce, 8 byte counter.
    authenticate_data: Option<Vec<u8>>,
    extended_nonce: bool,
}

impl Aes256GcmEncoder {
    fn new(
        key: Vec<u8>,
        authenticate_data: Option<Vec<u8>>,
        extended_nonce: bool,
    ) -> Fallible<(Aes256GcmEncoder, Vec<u8>)> {
        assert_eq!(key.len(), KEYBYTES);
        if unsafe { aes256gcm_is_available() } == 0 {
            return Err(MyError::HardwareUnsupported.into());
        }

        // Create a random nonce.
        let nonce_len = header_size(extended_nonce);
        let mut nonce = vec![0u8; nonce_len];
        unsafe { randombytes_buf(nonce.as_mut_ptr() as *mut c_void, nonce_len) };

        // Create algorithm state from long nonce and key. message counter starts with 0.
        let mut state = [0u8; STATE_BYTES];
        state[..KEYBYTES].copy_from_slice(&key);
        state[KEYBYTES..KEYBYTES + nonce_len].copy_from_slice(&nonce);

        // Header is just the nonce
        let header = nonce;
        let encoder = Aes256GcmEncoder {
            state,
            extended_nonce,
            authenticate_data,
        };
        Ok((encoder, header))
    }
}

impl StreamConverter for Aes256GcmEncoder {
    fn get_chunk_config(&self) -> ChunkConfig {
        ChunkConfig {
            input_chunk_offset: 0,
            input_chunk_asize: 0,
            output_chunk_asize: ABYTES,
        }
    }

    #[allow(clippy::assertions_on_constants)]
    fn convert_blocking(&mut self, input: Receiver<Chunk>, output: Sender<Chunk>) -> Fallible<()> {
        assert!(SHA512_BYTES > KEYBYTES + NONCE_BYTES);
        let mut hash_buf = [0u8; SHA512_BYTES];

        for mut chunk in input {
            let plaintext_len = chunk.buffer.len();
            assert!(plaintext_len < unsafe { messagebytes_max() });

            chunk.buffer.resize(plaintext_len + ABYTES, 0);

            let adata = self.authenticate_data.take().unwrap_or_default();

            let key_and_nonce = if self.extended_nonce {
                unsafe {
                    // Increment counter in the state.
                    sodium_increment(
                        self.state.as_mut_ptr().add(KEYBYTES + LONG_NONCE_BYTES),
                        MESSAGE_COUNTER_BYTES,
                    );

                    // Hash state to get the key and nonce for this chunk.
                    hash_sha512(
                        hash_buf.as_mut_ptr(),
                        self.state.as_ptr(),
                        self.state.len() as c_ulonglong,
                    );
                }
                hash_buf
            } else {
                // Regular nonce: increment it.
                unsafe {
                    sodium_increment(self.state.as_mut_ptr().add(KEYBYTES), NONCE_BYTES);
                }
                self.state
            };

            unsafe {
                // Use the key and nonce for this chunk. NOTE: Encryption happens in-place.
                aes256gcm_encrypt(
                    chunk.buffer.as_mut_ptr(),
                    std::ptr::null_mut(),
                    chunk.buffer.as_ptr(),
                    plaintext_len as c_ulonglong,
                    adata.as_ptr(),
                    adata.len() as c_ulonglong,
                    std::ptr::null(),
                    key_and_nonce.as_ptr().add(KEYBYTES),
                    key_and_nonce.as_ptr(),
                );
            }

            output.send(chunk)?;
        }
        Ok(())
    }
}

struct Aes256GcmDecoder {
    state: [u8; STATE_BYTES], // 8 byte counter, then 24 byte long nonce, then 32 byte key.
    authenticate_data: Option<Vec<u8>>,
    extended_nonce: bool,
}

impl Aes256GcmDecoder {
    fn new(
        key: Vec<u8>,
        header: Vec<u8>,
        authenticate_data: Option<Vec<u8>>,
        extended_nonce: bool,
    ) -> Fallible<Aes256GcmDecoder> {
        let nonce_len = header_size(extended_nonce);
        let nonce = header;
        assert_eq!(key.len(), KEYBYTES);
        if nonce.len() != nonce_len {
            return Err(MyError::InvalidHeader("Invalid Aes256Gcm header length".into()).into());
        }
        if unsafe { aes256gcm_is_available() } == 0 {
            return Err(MyError::HardwareUnsupported.into());
        }

        // Create algorithm state from long nonce in header and the key. message counter starts with 0.
        let mut state = [0u8; STATE_BYTES];
        state[..KEYBYTES].copy_from_slice(&key);
        state[KEYBYTES..KEYBYTES + nonce_len].copy_from_slice(&nonce);

        Ok(Aes256GcmDecoder {
            state,
            authenticate_data,
            extended_nonce,
        })
    }
}

impl StreamConverter for Aes256GcmDecoder {
    fn get_chunk_config(&self) -> ChunkConfig {
        ChunkConfig {
            input_chunk_offset: 0,
            input_chunk_asize: ABYTES,
            output_chunk_asize: 0,
        }
    }

    fn convert_blocking(&mut self, input: Receiver<Chunk>, output: Sender<Chunk>) -> Fallible<()> {
        let mut hash_buf = [0u8; SHA512_BYTES];
        for mut chunk in input {
            let ciphertext_len = chunk.buffer.len();
            assert!(ciphertext_len >= ABYTES);
            assert!(ciphertext_len < ABYTES + unsafe { messagebytes_max() });

            let adata = self.authenticate_data.take().unwrap_or_default();

            let key_and_nonce = if self.extended_nonce {
                unsafe {
                    // Increment counter in the state.
                    sodium_increment(
                        self.state.as_mut_ptr().add(KEYBYTES + LONG_NONCE_BYTES),
                        MESSAGE_COUNTER_BYTES,
                    );

                    // Hash state to get the key and nonce for this chunk.
                    hash_sha512(
                        hash_buf.as_mut_ptr(),
                        self.state.as_ptr(),
                        self.state.len() as c_ulonglong,
                    );
                }
                hash_buf
            } else {
                // Regular nonce: increment it.
                unsafe {
                    sodium_increment(self.state.as_mut_ptr().add(KEYBYTES), NONCE_BYTES);
                }
                self.state
            };

            let rc = unsafe {
                // NOTE: Decryption happens in-place.
                aes256gcm_decrypt(
                    chunk.buffer.as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    chunk.buffer.as_ptr(),
                    ciphertext_len as c_ulonglong,
                    adata.as_ptr(),
                    adata.len() as c_ulonglong,
                    key_and_nonce.as_ptr().add(KEYBYTES),
                    key_and_nonce.as_ptr(),
                )
            };
            if rc != 0 {
                return Err(MyError::DecryptionError("Invalid data".into()).into());
            }

            chunk.buffer.truncate(ciphertext_len - ABYTES);
            output.send(chunk)?;
        }
        Ok(())
    }
}
