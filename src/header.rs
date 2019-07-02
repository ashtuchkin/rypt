use bytes::{Buf, BufMut};
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
const PREHEADER_LEN: usize =
    FILE_SIGNATURE_LEN + std::mem::size_of::<u32>() + 2 * std::mem::size_of::<u64>();

fn align_len(len: usize, alignment: usize) -> usize {
    match len % alignment {
        0 => len,
        i => len + alignment - i,
    }
}

pub enum UserdataState {
    None,
    Attached(std::ops::Range<usize>), // where in returned vector is the user data.
    Detached,
}

pub fn read_header(reader: &mut Read) -> Fallible<(FileHeader, Vec<u8>, UserdataState, usize)> {
    // 1. Read constant-length pre-header with signature and block lengths
    let mut buffer = vec![0u8; PREHEADER_LEN];
    reader.read_exact(&mut buffer)?;
    let mut cursor = std::io::Cursor::new(buffer.as_slice());

    // 1a. Check file signature
    let file_signature = &mut [0u8; FILE_SIGNATURE_LEN];
    cursor.copy_to_slice(file_signature);
    if file_signature != FILE_SIGNATURE {
        return Err(MyError::InvalidHeader("Invalid signature".into()).into());
    }

    // 1b. Read header len, user data len and chunk len.
    let header_len = cursor.get_u32_le() as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(MyError::InvalidHeader("Header is too large".into()).into());
    }
    let aligned_header_len = align_len(header_len, FILE_ALIGNMENT);
    let (userdata_len, userdata_state) = match cursor.get_u64_le() {
        0 => (0, UserdataState::None),
        std::u64::MAX => (0, UserdataState::Detached),
        len => {
            let len = len as usize;
            let start = PREHEADER_LEN + aligned_header_len;
            (len, UserdataState::Attached(start..start + len))
        }
    };
    let aligned_userdata_len = align_len(userdata_len, FILE_ALIGNMENT);
    let chunk_len = cursor.get_u64_le() as usize;
    assert_eq!(cursor.remaining(), 0);

    // 2. Read header and user data in memory, aligning both to 8 bytes.
    let header_and_userdata_len = aligned_header_len + aligned_userdata_len;
    buffer.resize(buffer.len() + header_and_userdata_len, 0);
    reader.read_exact(&mut buffer[PREHEADER_LEN..])?;

    // 3. Decode header.
    let file_header = FileHeader::decode(&buffer[PREHEADER_LEN..PREHEADER_LEN + header_len])
        .map_err(MyError::InvalidHeaderProto)?;

    // Note, we return everything we read so that we can authenticate it when encrypting.
    Ok((file_header, buffer, userdata_state, chunk_len))
}

pub fn write_header(
    writer: &mut Write,
    header: &FileHeader,
    userdata_state: UserdataState,
    userdata_vec: Option<&[u8]>,
    chunk_len: usize,
) -> Fallible<Vec<u8>> {
    // 1. Calculate the lengths
    let header_len = header.encoded_len();
    if header_len > MAX_HEADER_LEN {
        return Err(MyError::EncodingError(header_len, MAX_HEADER_LEN).into());
    }

    let aligned_header_len = align_len(header_len, FILE_ALIGNMENT);
    let (userdata_len, userdata): (u64, &[u8]) = match userdata_state {
        UserdataState::None => (0, &[]),
        UserdataState::Attached(range) => {
            let userdata = &userdata_vec.unwrap()[range];
            (userdata.len() as u64, userdata)
        }
        UserdataState::Detached => (std::u64::MAX, &[]),
    };
    let aligned_userdata_len = align_len(userdata.len(), FILE_ALIGNMENT);

    // 2. Fill in the preheader
    let mut buffer = vec![0u8; 0];
    buffer.put_slice(FILE_SIGNATURE);
    buffer.put_u32_le(header_len as u32);
    buffer.put_u64_le(userdata_len);
    buffer.put_u64_le(chunk_len as u64);
    assert_eq!(buffer.len(), PREHEADER_LEN);

    // 3. Serialize header
    header.encode(&mut buffer)?;
    buffer.resize(buffer.len() + (aligned_header_len - header_len), 0);
    assert_eq!(buffer.len(), PREHEADER_LEN + aligned_header_len);

    // 4. Add userdata
    buffer.put_slice(userdata);
    buffer.resize(buffer.len() + (aligned_userdata_len - userdata.len()), 0);
    assert_eq!(
        buffer.len(),
        PREHEADER_LEN + aligned_header_len + aligned_userdata_len
    );

    // 5. Write everything to the file.
    writer.write_all(&buffer)?;
    Ok(buffer)
}
