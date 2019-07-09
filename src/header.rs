use std::convert::TryInto;
use std::io::{Read, Write};

use failure::Fallible;
use prost::Message;

use crate::errors::MyError;

include!(concat!(env!("OUT_DIR"), "/rypt.rs"));
pub use file_header::*;

const MAX_HEADER_LEN: usize = 1_000_000;
const FILE_SIGNATURE_LEN: usize = 4;
const FILE_SIGNATURE: &[u8; FILE_SIGNATURE_LEN] = b"rypt";
const FILE_ALIGNMENT: usize = 8;
const PREHEADER_LEN: usize = FILE_SIGNATURE_LEN + std::mem::size_of::<u32>();

fn align_len(len: usize, alignment: usize) -> usize {
    match len % alignment {
        0 => len,
        i => len + alignment - i,
    }
}

pub fn read_header(reader: &mut Read) -> Fallible<(FileHeader, Vec<u8>)> {
    // 1. Read constant-length pre-header with signature and block lengths
    let mut buffer = vec![0u8; PREHEADER_LEN];
    reader.read_exact(&mut buffer)?;

    // 1a. Check file signature
    if &buffer[..FILE_SIGNATURE_LEN] != FILE_SIGNATURE {
        return Err(MyError::InvalidHeader("Invalid signature".into()).into());
    }

    // 1b. Read header len, user data len and chunk len.
    let header_len = u32::from_le_bytes(buffer[FILE_SIGNATURE_LEN..].try_into()?) as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(MyError::InvalidHeader("Header is too large".into()).into());
    }
    let aligned_header_len = align_len(header_len, FILE_ALIGNMENT);

    // 2. Read header and user data in memory, aligning both to 8 bytes.
    buffer.resize(buffer.len() + aligned_header_len, 0);
    reader.read_exact(&mut buffer[PREHEADER_LEN..])?;

    // 3. Decode header.
    let file_header = FileHeader::decode(&buffer[PREHEADER_LEN..PREHEADER_LEN + header_len])
        .map_err(MyError::InvalidHeaderProto)?;

    // Note, we return everything we read so that we can authenticate it when encrypting.
    Ok((file_header, buffer))
}

pub fn write_header(writer: &mut Write, header: &FileHeader) -> Fallible<Vec<u8>> {
    // 1. Calculate the lengths
    let header_len = header.encoded_len();
    if header_len > MAX_HEADER_LEN {
        return Err(MyError::EncodingError(header_len, MAX_HEADER_LEN).into());
    }
    let aligned_header_len = align_len(header_len, FILE_ALIGNMENT);

    // 2. Fill in the preheader
    let mut buffer = vec![0u8; PREHEADER_LEN];
    buffer[..FILE_SIGNATURE_LEN].copy_from_slice(FILE_SIGNATURE);
    buffer[FILE_SIGNATURE_LEN..].copy_from_slice(&(header_len as u32).to_le_bytes());

    // 3. Serialize header
    header.encode(&mut buffer)?;
    buffer.resize(buffer.len() + (aligned_header_len - header_len), 0);
    assert_eq!(buffer.len(), PREHEADER_LEN + aligned_header_len);

    // 4. Write everything to the file.
    writer.write_all(&buffer)?;
    Ok(buffer)
}
