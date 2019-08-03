use std::convert::TryInto;
use std::io::{Read, Write};

use failure::{ensure, Fallible};

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

pub fn read_header(reader: &mut Read) -> Fallible<(Vec<u8>, usize)> {
    // 1. Read constant-length pre-header with file signature and header length.
    let mut pre_header = [0u8; PREHEADER_LEN];
    reader.read_exact(&mut pre_header)?;
    let (file_signature, header_len_bytes) = pre_header.split_at(FILE_SIGNATURE_LEN);

    // 1a. Check file signature
    ensure!(
        file_signature == FILE_SIGNATURE,
        "Invalid file signature (not a rypt file?)"
    );

    // 1b. Decode header length and validate it.
    let header_len = u32::from_le_bytes(header_len_bytes.try_into()?) as usize;
    ensure!(header_len > 0, "Header length is zero");
    ensure!(header_len <= MAX_HEADER_LEN, "Header is too large");
    let header_padding = padding_len(header_len, FILE_ALIGNMENT);

    // 2. Read serialized header with padding into memory.
    let mut buffer = vec![0u8; header_len + header_padding];
    reader.read_exact(&mut buffer)?;
    buffer.truncate(header_len); // Remove padding

    Ok((buffer, PREHEADER_LEN + header_len + header_padding))
}

pub fn write_header(writer: &mut Write, serialized_header: &[u8]) -> Fallible<()> {
    // 1. Check header length is not too large.
    let header_len = serialized_header.len();
    ensure!(
        header_len <= MAX_HEADER_LEN,
        "Header is too large ({} bytes, maximum allowed {} bytes)",
        header_len,
        MAX_HEADER_LEN
    );

    // 2. Write pre-header.
    let pre_header = [*FILE_SIGNATURE, (header_len as u32).to_le_bytes()].concat();
    assert_eq!(pre_header.len(), PREHEADER_LEN);
    writer.write_all(&pre_header)?;

    // 3. Write header.
    writer.write_all(&serialized_header)?;

    // 4. Write zero padding.
    let header_padding = padding_len(header_len, FILE_ALIGNMENT);
    if header_padding > 0 {
        let padding = [0u8; FILE_ALIGNMENT];
        writer.write_all(&padding[..header_padding])?;
    }

    Ok(())
}
