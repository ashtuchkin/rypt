use failure::{bail, Fallible};
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

#[allow(dead_code)]
pub fn to_hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("")
}

#[test]
fn to_hex_string_test() {
    assert_eq!(to_hex_string(b"123abcxyz"), "31323361626378797A");
    assert_eq!(to_hex_string(b""), "");
}

pub fn try_parse_hex_string(input_string: &str) -> Fallible<Vec<u8>> {
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
            bail!("Invalid hex character: {}", ch);
        }
    }

    if cnt > 0 {
        bail!("Odd number of hex characters");
    }
    Ok(res)
}

#[test]
fn parse_hex_test() -> Fallible<()> {
    assert_eq!(try_parse_hex_string("31323361626378797A")?, b"123abcxyz");
    assert_eq!(try_parse_hex_string("31 32 33")?, b"123");
    assert_eq!(try_parse_hex_string("")?, b"");
    assert_eq!(try_parse_hex_string("   ")?, b"");

    assert!(try_parse_hex_string("a").is_err());
    assert!(try_parse_hex_string("aq").is_err());
    assert!(try_parse_hex_string("3 132 33").is_err());
    Ok(())
}

#[inline]
pub fn serialize_proto<T: Message>(message: &T) -> Fallible<Vec<u8>> {
    let mut buf = vec![];
    message.encode(&mut buf)?;
    Ok(buf)
}
