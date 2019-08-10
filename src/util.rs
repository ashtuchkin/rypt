use failure::{Fail, Fallible};
use prost::Message;
use std::time::Duration;

static SCALES: &[&str; 7] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

// E.g. 2 B, 3.54 KB
pub fn human_file_size(val: usize) -> String {
    let filled_bits = (0usize.leading_zeros() - val.leading_zeros()) as i32;
    let scale_idx = std::cmp::max(filled_bits - 1, 0) / 10; // each scale is 10 bits.
    let divider = 2.0f64.powi(scale_idx * 10);

    let places = if scale_idx == 0 { 0 } else { 2 };
    let scale = SCALES[(scale_idx as usize)];
    format!("{:.*} {}", places, (val as f64 / divider), scale)
}

pub fn human_duration(dur: Duration) -> String {
    let mut time = dur.as_secs();
    let secs = time % 60;
    time /= 60;
    let mins = time % 60;
    time /= 60;
    let hrs = time;
    if hrs > 0 {
        format!("{}:{:02}:{:02}", hrs, mins, secs)
    } else {
        format!("{}:{:02}", mins, secs)
    }
}

pub fn to_hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

pub const SHA512_OUTPUT_BYTES: usize = libsodium_sys::crypto_hash_sha512_BYTES as usize;
pub fn sha512(input: &[u8]) -> Vec<u8> {
    unsafe {
        let mut output = vec![0u8; SHA512_OUTPUT_BYTES];
        libsodium_sys::crypto_hash_sha512(output.as_mut_ptr(), input.as_ptr(), input.len() as u64);
        output
    }
}

// Inspired by https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md but use sha512 instead of keccak256
pub fn to_hex_string_checksummed(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let hex_string = to_hex_string(bytes);
    let hash_hex_string = to_hex_string(sha512(bytes));
    hex_string
        .chars()
        .zip(hash_hex_string.chars().cycle())
        .map(|(hex_char, hash_char)| {
            if hash_char >= '8' {
                hex_char.to_ascii_uppercase()
            } else {
                hex_char.to_ascii_lowercase()
            }
        })
        .collect()
}

#[derive(Fail, Debug, PartialEq)]
pub enum ParseHexError {
    #[fail(display = "Invalid character: {}", _0)]
    InvalidChar(char),

    #[fail(display = "Odd number of hex characters")]
    InvalidLength,

    #[fail(display = "Invalid checksum")]
    InvalidChecksum(Vec<u8>),
}

pub fn try_parse_hex_string(input_string: &str) -> Result<Vec<u8>, ParseHexError> {
    let mut acc = 0u8;
    let mut cnt = 0;
    let mut res = vec![];
    for ch in input_string.chars() {
        if cnt == 0 && ch.is_whitespace() {
            // allow whitespace between bytes
            continue;
        } else if let Some(val) = ch.to_digit(16) {
            acc = (acc << 4) + val as u8;
            cnt += 1;
            if cnt == 2 {
                res.push(acc);
                acc = 0u8;
                cnt = 0;
            }
        } else {
            return Err(ParseHexError::InvalidChar(ch));
        }
    }

    if cnt > 0 {
        return Err(ParseHexError::InvalidLength);
    }
    Ok(res)
}

pub fn try_parse_hex_string_checksummed(input_string: &str) -> Result<Vec<u8>, ParseHexError> {
    let bytes = try_parse_hex_string(input_string)?;
    let input_string_without_whitespace = input_string.replace(char::is_whitespace, "");
    if to_hex_string_checksummed(&bytes) != input_string_without_whitespace {
        Err(ParseHexError::InvalidChecksum(bytes))
    } else {
        Ok(bytes)
    }
}

#[inline]
pub fn serialize_proto<T: Message>(message: &T) -> Fallible<Vec<u8>> {
    let mut buf = vec![];
    message.encode(&mut buf)?;
    Ok(buf)
}

pub fn xor_vec(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());
    a.iter_mut().zip(b).for_each(|(a, b)| *a ^= *b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_file_size_test() {
        assert_eq!(human_file_size(0), "0 B");
        assert_eq!(human_file_size(30), "30 B");
        assert_eq!(human_file_size(512), "512 B");
        assert_eq!(human_file_size(1000), "1000 B");
        assert_eq!(human_file_size(1023), "1023 B");
        assert_eq!(human_file_size(1024), "1.00 KiB");
        assert_eq!(human_file_size(1100), "1.07 KiB");
        assert_eq!(human_file_size(10240), "10.00 KiB");
        assert_eq!(human_file_size(1024 * 1024), "1.00 MiB");
        assert_eq!(human_file_size(std::usize::MAX), "16.00 EiB");
    }

    #[test]
    fn to_hex_string_test() {
        assert_eq!(to_hex_string(b"123abcxyz"), "31323361626378797a");
        assert_eq!(to_hex_string(b""), "");

        assert_eq!(
            to_hex_string_checksummed(b"123abcxyz"),
            "31323361626378797A"
        );
        assert_eq!(
            to_hex_string_checksummed(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
            "FfFfffffFFFFFfffFF"
        );
        assert_eq!(to_hex_string_checksummed(b""), "");
    }

    #[test]
    fn parse_hex_test() -> Fallible<()> {
        assert_eq!(try_parse_hex_string("31323361626378797A")?, b"123abcxyz");
        assert_eq!(try_parse_hex_string("31 32 33")?, b"123");
        assert_eq!(try_parse_hex_string("")?, b"");
        assert_eq!(try_parse_hex_string("   ")?, b"");

        assert_eq!(try_parse_hex_string("a"), Err(ParseHexError::InvalidLength));
        assert_eq!(
            try_parse_hex_string("aq"),
            Err(ParseHexError::InvalidChar('q'))
        );
        assert_eq!(
            try_parse_hex_string("3 132 33"),
            Err(ParseHexError::InvalidChar(' '))
        );

        assert_eq!(
            try_parse_hex_string_checksummed("31323361626378797A")?,
            b"123abcxyz"
        );
        assert_eq!(
            try_parse_hex_string_checksummed(" 31 32 33 61  62 63 78 79 7A\n")?,
            b"123abcxyz"
        );
        assert_eq!(
            try_parse_hex_string_checksummed(" 31 32 33 61  62 63 78 79 7a\n"),
            Err(ParseHexError::InvalidChecksum(b"123abcxyz".to_vec()))
        );
        assert_eq!(
            try_parse_hex_string_checksummed("FfFfffffFFFFFfffFF")?,
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        );
        assert_eq!(
            try_parse_hex_string_checksummed("FfFfffffFFFFFfffFf"),
            Err(ParseHexError::InvalidChecksum(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff".to_vec()
            ))
        );

        Ok(())
    }
}
