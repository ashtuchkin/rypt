

static SCALES: &[u8; 8] = b"KMGTPEZY";

// E.g. 2 B, 3.54 KB
pub fn human_file_size(val: usize) -> String {
    let filled_bits = (0usize.leading_zeros() - val.leading_zeros()) as i32;
    let scale_idx = std::cmp::max(filled_bits - 1, 0) / 10;  // each scale is 10 bits.
    let divider = 2.0f64.powi(scale_idx * 10);

    let (scale, places) = if scale_idx == 0 {
        (String::new(), 0)
    } else {
        (char::from(SCALES[(scale_idx as usize) - 1]).to_string(), 2)
    };
    format!("{:.*} {}B", places, (val as f64 / divider), scale)
}

#[test]
fn human_file_size_test() {
    assert_eq!(human_file_size(0), "0 B");
    assert_eq!(human_file_size(30), "30 B");
    assert_eq!(human_file_size(512), "512 B");
    assert_eq!(human_file_size(1000), "1000 B");
    assert_eq!(human_file_size(1023), "1023 B");
    assert_eq!(human_file_size(1024), "1.00 KB");
    assert_eq!(human_file_size(1100), "1.07 KB");
    assert_eq!(human_file_size(10240), "10.00 KB");
    assert_eq!(human_file_size(1024*1024), "1.00 MB");
    assert_eq!(human_file_size(std::usize::MAX), "16.00 EB");
}


#[allow(dead_code)]
pub fn to_hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter()
       .map(|b| format!("{:02X}", b))
       .collect::<Vec<String>>()
       .join("")
}

