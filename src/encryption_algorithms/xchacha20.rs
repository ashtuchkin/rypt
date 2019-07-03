use failure::Fallible;
use libsodium_sys::{
    crypto_secretstream_xchacha20poly1305_init_pull as init_pull,
    crypto_secretstream_xchacha20poly1305_init_push as init_push,
    crypto_secretstream_xchacha20poly1305_pull as stream_pull,
    crypto_secretstream_xchacha20poly1305_push as stream_push,
    crypto_secretstream_xchacha20poly1305_state as StreamState,
};

use crate::errors::MyError;
use crate::header::XChaCha20Poly1305Config;
use crate::types::{Chunk, ChunkConfig, StreamCodec, StreamCodecConfig, StreamConverter};

const ABYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;
const KEYBYTES: usize = libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;
const HEADERBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;
const TAG_MESSAGE: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8;
const TAG_FINAL: u8 = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8;

pub struct XChaCha20 {}

impl XChaCha20 {
    pub fn new(_config: &XChaCha20Poly1305Config) -> XChaCha20 {
        XChaCha20 {}
    }
}

impl StreamCodec for XChaCha20 {
    fn get_config(&self) -> StreamCodecConfig {
        StreamCodecConfig { key_size: KEYBYTES }
    }

    fn start_encoding(&self, key: &[u8]) -> Fallible<(Vec<u8>, Box<StreamConverter>)> {
        let (converter, header) = XChaCha20Encoder::new(key)?;
        Ok((header, Box::new(converter)))
    }

    fn start_decoding(&self, key: &[u8], header: &[u8]) -> Fallible<Box<StreamConverter>> {
        Ok(Box::new(XChaCha20Decoder::new(key, header)?))
    }
}

pub struct XChaCha20Encoder {
    state: StreamState,
}

impl XChaCha20Encoder {
    fn new(key: &[u8]) -> Fallible<(XChaCha20Encoder, Vec<u8>)> {
        assert_eq!(key.len(), KEYBYTES);
        let mut header = vec![0u8; HEADERBYTES];
        let state: StreamState = unsafe {
            let mut state: StreamState = std::mem::zeroed();
            let rc = init_push(&mut state, header.as_mut_ptr(), key.as_ptr());
            assert_eq!(rc, 0); // init_push should always succeed.
            state
        };
        Ok((XChaCha20Encoder { state }, header))
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

    fn convert_chunk(&mut self, mut chunk: Chunk) -> Fallible<Chunk> {
        const PREFIX_SIZE: usize = 1;
        const SUFFIX_SIZE: usize = ABYTES - PREFIX_SIZE;
        assert!(chunk.offset >= PREFIX_SIZE);

        let plaintext_len = chunk.buffer.len() - chunk.offset;
        chunk.buffer.resize(chunk.buffer.len() + SUFFIX_SIZE, 0);
        let tag: u8 = if chunk.is_last_chunk {
            TAG_FINAL
        } else {
            TAG_MESSAGE
        };
        let mut output_len: u64 = 0;
        let adata = chunk.authentication_data.take().unwrap_or_default();

        let rc = unsafe {
            // NOTE: The buffer is encoded in-place. This is only possible due to the pointer shift
            // made by PREFIX_SIZE. (see function's internals at https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L147
            // and the fact that crypto_stream_chacha20_ietf_xor_ic can do encryption in-place: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20#usage)
            stream_push(
                &mut self.state,
                chunk.buffer.as_mut_ptr().add(chunk.offset - PREFIX_SIZE),
                &mut output_len,
                chunk.buffer.as_ptr().add(chunk.offset),
                plaintext_len as u64,
                adata.as_ptr(),
                adata.len() as u64,
                tag,
            )
        };
        assert_eq!(rc, 0); // stream_push should always succeed.
        assert_eq!(output_len as usize, plaintext_len + ABYTES);

        chunk.offset -= PREFIX_SIZE;
        Ok(chunk)
    }
}

pub struct XChaCha20Decoder {
    state: StreamState,
}

impl XChaCha20Decoder {
    fn new(key: &[u8], header: &[u8]) -> Fallible<XChaCha20Decoder> {
        assert_eq!(key.len(), KEYBYTES);
        if header.len() != HEADERBYTES {
            return Err(MyError::InvalidHeader("Invalid XChacha20 header".into()).into());
        }

        let state: StreamState = unsafe {
            let mut state: StreamState = std::mem::zeroed();
            let rc = init_pull(&mut state, header.as_ptr(), key.as_ptr());
            if rc != 0 {
                return Err(MyError::InvalidHeader("Invalid XChacha20 header".into()).into());
            }
            state
        };
        Ok(XChaCha20Decoder { state })
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

    fn convert_chunk(&mut self, mut chunk: Chunk) -> Fallible<Chunk> {
        const PREFIX_SIZE: usize = 1;
        const SUFFIX_SIZE: usize = ABYTES - PREFIX_SIZE;
        let chunk_size = chunk.buffer.len() - chunk.offset;
        if chunk_size < ABYTES {
            return Err(MyError::DecryptionError("Chunk too small to be valid".into()).into());
        }
        let mut tag: u8 = 0;
        let mut output_len: u64 = 0;
        let adata = chunk.authentication_data.take().unwrap_or_default();

        let rc = unsafe {
            // NOTE: The buffer is decoded in-place. This is only possible due to the pointer shift
            // made by PREFIX_SIZE. (see function's internals at https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c#L147
            // and the fact that crypto_stream_chacha20_ietf_xor_ic can do encryption in-place: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20#usage)
            stream_pull(
                &mut self.state,
                chunk.buffer.as_mut_ptr().add(chunk.offset + PREFIX_SIZE),
                &mut output_len,
                &mut tag,
                chunk.buffer.as_ptr().add(chunk.offset),
                chunk_size as u64,
                adata.as_ptr(),
                adata.len() as u64,
            )
        };
        if rc != 0 {
            return Err(MyError::DecryptionError("Invalid data".into()).into());
        }
        if (tag == TAG_FINAL) != chunk.is_last_chunk {
            return Err(MyError::DecryptionError("Last chunk is not finalized".into()).into());
        }
        assert_eq!(output_len as usize, chunk_size - ABYTES);

        chunk.buffer.truncate(chunk.buffer.len() - SUFFIX_SIZE);
        chunk.offset += PREFIX_SIZE;
        Ok(chunk)
    }
}
