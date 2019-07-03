use failure::Fallible;

use crate::encryption_algorithms::{Aes256Gcm, XChaCha20};
use crate::errors::MyError;
use crate::header::{Aes256gcmConfig, EncryptionAlgorithm, FileHeader, PasswordDerivation};
use crate::key_derivation::SCryptSalsa208SHA256;
use crate::types::{KeyDerivationFunction, StreamCodec};

pub fn header_from_command_line(algorithm: &Option<String>) -> Fallible<FileHeader> {
    // Start with default values.
    let mut header = FileHeader {
        encryption_algorithm: Some(EncryptionAlgorithm::Xchacha20Poly1305(Default::default())),
        password_derivation: Some(PasswordDerivation::ScryptSalsa208Sha256(
            SCryptSalsa208SHA256::default_config_random_seed(),
        )),
        ..Default::default()
    };

    if let Some(algorithm) = algorithm {
        header.encryption_algorithm = match algorithm.as_str() {
            "xchacha20" => EncryptionAlgorithm::Xchacha20Poly1305(Default::default()),
            "aes256gcm" => EncryptionAlgorithm::Aes256Gcm(Aes256gcmConfig {
                extended_nonce: false,
            }),
            "aes256gcm-ext" => EncryptionAlgorithm::Aes256Gcm(Aes256gcmConfig {
                extended_nonce: false,
            }),
            other_val => return Err(MyError::UnknownAlgorithm(other_val.to_string()).into()),
        }
        .into();
    }

    Ok(header)
}

pub fn codec_from_header(file_header: &FileHeader) -> Fallible<Box<StreamCodec>> {
    match &file_header.encryption_algorithm {
        None => Err(MyError::InvalidHeader("Unfilled encryption algorithm".into()).into()),
        Some(EncryptionAlgorithm::Xchacha20Poly1305(config)) => {
            Ok(Box::new(XChaCha20::new(config)))
        }
        Some(EncryptionAlgorithm::Aes256Gcm(config)) => Ok(Box::new(Aes256Gcm::new(config))),
    }
}

pub fn key_derivation_from_header(
    file_header: &FileHeader,
) -> Fallible<Box<KeyDerivationFunction>> {
    match &file_header.password_derivation {
        None => Err(MyError::InvalidHeader("Unfilled key derivation data".into()).into()),
        Some(PasswordDerivation::ScryptSalsa208Sha256(config)) => {
            Ok(Box::new(SCryptSalsa208SHA256::new(config)?))
        }
    }
}
