use std::convert::TryInto;

use failure::Fallible;

use crate::crypto::{
    AEADKey, AEADMac, AEADNonce, CryptoSystem, HashOutput, AEAD_MAC_LEN, AEAD_NONCE_LEN,
    HASH_OUTPUT_LEN,
};
use crate::types::{Chunk, ChunkConfig, StreamConverter};

const CHUNK_NONCE: &AEADNonce = b"rych\0\0\0\0\0\0\0\0"; // Zeros will be replaced with chunk_idx
const CHUNK_IDX_POS: usize = AEAD_NONCE_LEN - std::mem::size_of::<u64>(); // Put chunk index in the last 8 bytes.

pub struct CryptoSystemAEADCodec {
    cryptosys: Box<CryptoSystem>,
    payload_key: AEADKey,
    header_hash: HashOutput,
    is_encrypting: bool,
}

impl CryptoSystemAEADCodec {
    pub fn new(
        cryptosys: Box<CryptoSystem>,
        payload_key: &AEADKey,
        header_hash: &HashOutput,
        is_encrypting: bool,
    ) -> Box<StreamConverter + Send> {
        Box::new(CryptoSystemAEADCodec {
            cryptosys,
            payload_key: *payload_key,
            header_hash: *header_hash,
            is_encrypting,
        })
    }
}

impl StreamConverter for CryptoSystemAEADCodec {
    fn get_chunk_config(&self) -> ChunkConfig {
        ChunkConfig {
            input_chunk_asize: if self.is_encrypting { 0 } else { AEAD_MAC_LEN },
            output_chunk_asize: if self.is_encrypting { AEAD_MAC_LEN } else { 0 },
        }
    }

    fn convert_chunk(&mut self, mut chunk: Chunk) -> Fallible<Chunk> {
        let mut authed_data = [0u8; HASH_OUTPUT_LEN + 1];
        authed_data[..HASH_OUTPUT_LEN].copy_from_slice(&self.header_hash.into());
        authed_data[HASH_OUTPUT_LEN] = chunk.is_last_chunk as u8;

        let mut nonce: AEADNonce = *CHUNK_NONCE;
        nonce[CHUNK_IDX_POS..].copy_from_slice(&chunk.chunk_idx.to_le_bytes());

        if self.is_encrypting {
            chunk.buffer.resize(chunk.buffer.len() + AEAD_MAC_LEN, 0);
        }
        let message_len = chunk.buffer.len() - AEAD_MAC_LEN;
        let (message, mac) = chunk.buffer.split_at_mut(message_len);
        let mac: &mut AEADMac = mac.try_into().unwrap();

        if self.is_encrypting {
            self.cryptosys
                .aead_encrypt(message, &authed_data, &self.payload_key, &nonce, mac);
        } else {
            self.cryptosys
                .aead_decrypt(message, &authed_data, &self.payload_key, &nonce, mac)?;
        }
        if !self.is_encrypting {
            chunk.buffer.truncate(message_len);
        }
        Ok(chunk)
    }
}
