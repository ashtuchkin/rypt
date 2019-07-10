use std::convert::TryInto;
use std::io::{Read, Write};

use failure::Fallible;
use prost::Message;

use crate::errors::MyError;

// Include generated FileHeader protobuf definition file.
include!(concat!(env!("OUT_DIR"), "/rypt.rs"));
pub use file_header::*;

const MAX_HEADER_LEN: usize = 1_000_000;
const FILE_SIGNATURE_LEN: usize = 4;
const FILE_SIGNATURE: &[u8; FILE_SIGNATURE_LEN] = b"rypt";
const FILE_ALIGNMENT: usize = 8;
const PREHEADER_LEN: usize = FILE_SIGNATURE_LEN + std::mem::size_of::<u32>();

// Returns the number of bytes we need to add to `len` to make it divisible by `alignment`.
// Returned value will be in range 0..alignment-1.
#[inline]
fn padding_len(len: usize, alignment: usize) -> usize {
    match len % alignment {
        0 => 0,
        remainder => alignment - remainder,
    }
}

/*
File structure:
| Item                                             | Size         |
|--------------------------------------------------|--------------|
| File signature: ASCII 'rypt'                     | 4 bytes      |
| Header length, little-endian uint32              | 4 bytes      |
| Header protobuf                                  | header len   |
| N x Ciphertext chunk, aligned to 8 bytes         | (chunk_size + asize); last one may be smaller |

read_header reads everything until the first chunk; write_header writes it.
*/

pub fn read_header(reader: &mut Read) -> Fallible<(FileHeader, Vec<u8>)> {
    // 1. Read constant-length pre-header with signature and header length.
    let mut buffer = vec![0u8; PREHEADER_LEN];
    reader.read_exact(&mut buffer)?;

    // 1a. Check file signature
    if &buffer[..FILE_SIGNATURE_LEN] != FILE_SIGNATURE {
        return Err(MyError::InvalidHeader("Invalid signature".into()).into());
    }

    // 1b. Read header length and validate it.
    let header_len = u32::from_le_bytes(buffer[FILE_SIGNATURE_LEN..].try_into().unwrap()) as usize;
    if header_len == 0 {
        return Err(MyError::InvalidHeader("Header length is zero".into()).into());
    }
    if header_len > MAX_HEADER_LEN {
        return Err(MyError::InvalidHeader("Header is too large".into()).into());
    }
    let header_padding = padding_len(header_len, FILE_ALIGNMENT);

    // 2. Read header with padding into memory.
    buffer.resize(buffer.len() + header_len + header_padding, 0);
    reader.read_exact(&mut buffer[PREHEADER_LEN..])?;

    // 3. Decode and validate header.
    let header = FileHeader::decode(&buffer[PREHEADER_LEN..PREHEADER_LEN + header_len])
        .map_err(MyError::InvalidHeaderProto)?;
    validate_header(&header)?;

    // Note, we return everything we read so that we can authenticate it when encrypting.
    Ok((header, buffer))
}

pub fn write_header(writer: &mut Write, header: &FileHeader) -> Fallible<Vec<u8>> {
    // 0. Make sure the header is valid.
    validate_header(header)?;

    // 1. Calculate header length
    let header_len = header.encoded_len();
    if header_len > MAX_HEADER_LEN {
        return Err(MyError::EncodingError(header_len, MAX_HEADER_LEN).into());
    }
    let header_padding = padding_len(header_len, FILE_ALIGNMENT);

    // 2. Serialize pre-header
    let mut buffer = vec![0u8; PREHEADER_LEN];
    buffer[..FILE_SIGNATURE_LEN].copy_from_slice(FILE_SIGNATURE);
    buffer[FILE_SIGNATURE_LEN..].copy_from_slice(&(header_len as u32).to_le_bytes());

    // 3. Serialize header
    header.encode(&mut buffer)?; // This appends data to the buffer.
    buffer.resize(buffer.len() + header_padding, 0);
    assert_eq!(buffer.len(), PREHEADER_LEN + header_len + header_padding);

    // 4. Write everything to the file.
    writer.write_all(&buffer)?;
    Ok(buffer)
}

fn validate_header(header: &FileHeader) -> Fallible<()> {
    if header.encryption_algorithm == None {
        return Err(MyError::InvalidHeader("Encryption algorithm not set".into()).into());
    }

    if header.chunk_size == 0 {
        return Err(MyError::InvalidHeader("Chunk size must be non zero".into()).into());
    }

    Ok(())
}
