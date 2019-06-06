
use crate::codec::{StreamCodec, MyError, Chunk, StreamConverter, ChunkConfig, StreamCodecConfig};
use crossbeam_channel::{Receiver, Sender};
use failure::{Error};
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

pub struct XChaCha20 {}

impl XChaCha20 {
    pub fn new() -> XChaCha20 {
        XChaCha20{}
    }
}


impl StreamCodec for XChaCha20 {
    fn get_config(&self) -> StreamCodecConfig {
        StreamCodecConfig {
            header_size: HEADERBYTES,
            key_size: KEYBYTES,
        }
    }

    fn start_encoding(&self, key: Vec<u8>) -> Result<(Vec<u8>, Box<StreamConverter>), Error> {
        let (converter, header) = XChaCha20Encoder::new(key)?;
        Ok((header, Box::new(converter)))
    }

    fn start_decoding(&self, key: Vec<u8>, header: Vec<u8>) -> Result<Box<StreamConverter>, Error> {
        Ok(Box::new(XChaCha20Decoder::new(key, header)?))
    }

}

pub struct XChaCha20Encoder {
    state: StreamState,
}

impl XChaCha20Encoder {
    fn new(key: Vec<u8>) -> Result<(XChaCha20Encoder, Vec<u8>), Error> {
        assert_eq!(key.len(), KEYBYTES);
        let mut header = vec![0u8; HEADERBYTES];
        let state: StreamState = unsafe {
            let mut state: StreamState = std::mem::zeroed();
            init_push(&mut state, header.as_mut_ptr(), key.as_ptr()); // NOTE: init_push always succeeds.
            state
        };
        Ok((XChaCha20Encoder{state}, header))
    }
}

impl StreamConverter for XChaCha20Encoder {
    fn get_chunk_config(&self) -> ChunkConfig {
        ChunkConfig {
            input_chunk_offset: 16,
            input_chunk_asize: 0,
            output_chunk_asize: ABYTES - 1,
        }
    }

    fn convert_blocking(&mut self, input: Receiver<Chunk>, output: Sender<Chunk>) -> Result<(), Error> {
        for mut chunk in input {
            const PREFIX_SIZE: usize = 1;
            const SUFFIX_SIZE: usize = ABYTES - PREFIX_SIZE;
            assert!(chunk.offset >= PREFIX_SIZE);

            let plaintext_len = chunk.buffer.len() - chunk.offset;
            chunk.buffer.resize(chunk.buffer.len() + SUFFIX_SIZE, 0);
            let tag = if chunk.is_last_chunk { TAG_FINAL } else { TAG_MESSAGE } as u8;

            unsafe {
                // NOTE: `stream_push` always succeeds.
                // NOTE: The buffer is encoded in-place. This is only possible due to the pointer shift
                // made by PREFIX_SIZE. (see function's internals at https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L147
                // and the fact that crypto_stream_chacha20_ietf_xor_ic can do encryption in-place: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20#usage)
                stream_push(
                    &mut self.state,
                    chunk.buffer.as_mut_ptr().offset((chunk.offset - PREFIX_SIZE) as isize),
                    std::ptr::null_mut(),
                    chunk.buffer.as_ptr().offset(chunk.offset as isize),
                    plaintext_len as c_ulonglong,
                    std::ptr::null(),
                    0 as c_ulonglong,
                    tag,
                );
            }
            chunk.offset -= PREFIX_SIZE;
            output.send(chunk)?;
        }
        Ok(())
    }
}

pub struct XChaCha20Decoder {
    state: StreamState,
}

impl XChaCha20Decoder {
    fn new(key: Vec<u8>, header: Vec<u8>) -> Result<XChaCha20Decoder, Error> {
        assert_eq!(key.len(), KEYBYTES);
        assert_eq!(header.len(), HEADERBYTES);

        let state: StreamState = unsafe {
            let mut state: StreamState = std::mem::zeroed();
            let rc = init_pull(&mut state, header.as_ptr(), key.as_ptr());
            if rc != 0 {
                return Err(MyError::InvalidHeader.into());
            }
            state
        };
        Ok(XChaCha20Decoder{state})
    }
}

impl StreamConverter for XChaCha20Decoder {
    fn get_chunk_config(&self) -> ChunkConfig {
        ChunkConfig {
            input_chunk_offset: 15,
            input_chunk_asize: ABYTES,
            output_chunk_asize: 0,
        }
    }

    fn convert_blocking(&mut self, input: Receiver<Chunk>, output: Sender<Chunk>) -> Result<(), Error> {
        for mut chunk in input {
            const PREFIX_SIZE: usize = 1;
            const SUFFIX_SIZE: usize = ABYTES - PREFIX_SIZE;
            let chunk_size = chunk.buffer.len() - chunk.offset;
            if chunk_size < ABYTES {
                return Err(MyError::DecryptionError.into());  // Chunk too small to be valid.
            }
            let mut tag: u8 = unsafe { std::mem::zeroed() };

            let rc = unsafe {
                // NOTE: The buffer is decoded in-place. This is only possible due to the pointer shift
                // made by PREFIX_SIZE. (see function's internals at https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L147
                // and the fact that crypto_stream_chacha20_ietf_xor_ic can do encryption in-place: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20#usage)
                stream_pull(
                    &mut self.state,
                    chunk.buffer.as_mut_ptr().offset((chunk.offset + PREFIX_SIZE) as isize),
                    std::ptr::null_mut(),
                    &mut tag,
                    chunk.buffer.as_ptr().offset(chunk.offset as isize),
                    chunk_size as c_ulonglong,
                    std::ptr::null(),
                    0 as c_ulonglong,
                )
            };
            if rc != 0 {
                return Err(MyError::DecryptionError.into());  // Invalid chunk.
            }
            if (tag == TAG_FINAL) != chunk.is_last_chunk {
                return Err(MyError::DecryptionError.into());  // Final chunk is not the last chunk.
            }

            chunk.buffer.truncate(chunk.buffer.len() - SUFFIX_SIZE);
            chunk.offset += PREFIX_SIZE;
            output.send(chunk)?;
        }
        Ok(())
    }
}

