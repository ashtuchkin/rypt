use failure::Error;

use crate::encoding::{Aes256Gcm, XChaCha20};
use crate::types::{StreamCodec, KeyDerivationFunction};
use crate::errors::MyError;
use crate::header::{FileHeader, EncodingAlgorithm, AES256GCMConfig, XChaCha20Poly1305Config, PasswordConfig};
use crate::key_derivation::SCryptSalsa208SHA256;


pub fn header_from_command_line(algorithm: &Option<String>, chunk_size: &Option<usize>) -> Result<FileHeader, Error> {
    // Start with default values.
    let mut header = FileHeader {
        algorithm: Some(EncodingAlgorithm::XChaCha20Poly1305(XChaCha20Poly1305Config{})),
        chunk_size: 1 * 1024 * 1024,
        password_config: Some(PasswordConfig::SCryptSalsa208SHA256(SCryptSalsa208SHA256::default_config_random_seed())),
    };

    if let Some(algorithm) = algorithm {
        header.algorithm = match algorithm.as_str() {
            "xchacha20" => EncodingAlgorithm::XChaCha20Poly1305(XChaCha20Poly1305Config {}),
            "aes256gcm" => EncodingAlgorithm::AES256GCM(AES256GCMConfig {extended_nonce: false}),
            "aes256gcm-ext" => EncodingAlgorithm::AES256GCM(AES256GCMConfig {extended_nonce: false}),
            other_val => return Err(MyError::UnknownAlgorithm(other_val.to_string()).into()),
        }.into();
    }

    if let Some(chunk_size) = chunk_size {
        header.chunk_size = *chunk_size as u64;
    }

    Ok(header)
}

pub fn codec_from_header(file_header: &FileHeader) -> Result<Box<StreamCodec>, Error> {
    match &file_header.algorithm {
        None => Err(MyError::InvalidHeader("Unfilled algorithm data".into()).into()),
        Some(EncodingAlgorithm::XChaCha20Poly1305(_)) => Ok(Box::new(XChaCha20::new())),
        Some(EncodingAlgorithm::AES256GCM(config)) => Ok(Box::new(Aes256Gcm::new(config))),
    }
}

pub fn key_derivation_from_header(file_header: &FileHeader) -> Result<Box<KeyDerivationFunction>, Error> {
    match &file_header.password_config {
        None => Err(MyError::InvalidHeader("Unfilled key derivation data".into()).into()),
        Some(PasswordConfig::SCryptSalsa208SHA256(config)) =>
            Ok(Box::new(SCryptSalsa208SHA256::new(config)?)),
    }
}
