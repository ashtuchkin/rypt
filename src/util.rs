

#[allow(dead_code)]
pub fn to_hex_string(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter()
       .map(|b| format!("{:02X}", b))
       .collect::<Vec<String>>()
       .join("")
}

