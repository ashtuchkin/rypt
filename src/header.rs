use std::convert::TryInto;
use std::io::{Read, Write};

use failure::Error;
use prost::{Message, Oneof};

use crate::errors::MyError;

pub const MAX_HEADER_LEN: usize = 1000000;
const FILE_SIGNATURE: &[u8] = b"enco";

#[derive(Clone, PartialEq, Message)]
pub struct SCryptSalsa208SHA256Config {
    #[prost(bytes, tag = "1")]
    pub salt: Vec<u8>,

    #[prost(uint64, tag = "2")]
    pub opslimit: u64,

    #[prost(uint64, tag = "3")]
    pub memlimit: u64,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum PasswordConfig {
    #[prost(message, tag = "4")]
    SCryptSalsa208SHA256(SCryptSalsa208SHA256Config),
}

#[derive(Clone, PartialEq, Message)]
pub struct AES256GCMConfig {
    #[prost(bool, tag = "1")]
    pub extended_nonce: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct XChaCha20Poly1305Config {}

#[derive(Clone, PartialEq, Oneof)]
pub enum EncodingAlgorithm {
    #[prost(message, tag = "1")]
    AES256GCM(AES256GCMConfig),

    #[prost(message, tag = "2")]
    XChaCha20Poly1305(XChaCha20Poly1305Config),
}

// Protobuf-encoded file header.
#[derive(Clone, PartialEq, Message)]
pub struct FileHeader {
    #[prost(oneof = "EncodingAlgorithm", tags = "1,2")]
    pub algorithm: Option<EncodingAlgorithm>,

    #[prost(uint64, tag = "3")]
    pub chunk_size: u64,

    #[prost(oneof = "PasswordConfig", tags = "4")]
    pub password_config: Option<PasswordConfig>,
}

impl FileHeader {
    pub fn read(reader: &mut Read) -> Result<(FileHeader, Vec<u8>), Error> {
        // 1. Get 8 bytes pre-header that contains file signature (4 ASCII chars 'enco') and header
        //    length (little endian u32).
        let mut preheader_buf = vec![0u8; FILE_SIGNATURE.len() + std::mem::size_of::<u32>()];
        reader.read_exact(&mut preheader_buf)?;
        if !preheader_buf.starts_with(FILE_SIGNATURE) {
            return Err(MyError::InvalidHeader("Invalid signature".into()).into());
        }

        let header_len = u32::from_le_bytes(preheader_buf[FILE_SIGNATURE.len()..].try_into()?) as usize;
        if header_len > MAX_HEADER_LEN {
            return Err(MyError::InvalidHeader("Header too large".into()).into());
        }

        // 2. Read full header into memory
        let mut header_buf = vec![0u8; header_len];
        reader.read_exact(&mut header_buf)?;

        // 3. Decode header protobuf.
        let file_header = FileHeader::decode(&header_buf).map_err(|e| MyError::InvalidHeaderProto(e))?;

        // Return both decoded file header and the original buffer; the latter will be authenticated
        // later. Note, we don't need to authenticate preheader.
        Ok((file_header, header_buf))
    }

    pub fn write(&self, writer: &mut Write) -> Result<Vec<u8>, Error> {
        // 1. Encode header into buf
        let header_len = self.encoded_len();
        if header_len > MAX_HEADER_LEN {
            return Err(MyError::EncodingError(header_len, MAX_HEADER_LEN).into());
        }

        let mut header_buf = Vec::new();
        self.encode(&mut header_buf)?;
        assert_eq!(header_buf.len(), header_len);

        // 2. Write file signature and header len
        let preheader_buf = [&FILE_SIGNATURE[..], &(header_len as u32).to_le_bytes()[..]].concat();
        writer.write_all(&preheader_buf)?;

        // 3. Write header.
        writer.write_all(&header_buf)?;
        Ok(header_buf)
    }
}
