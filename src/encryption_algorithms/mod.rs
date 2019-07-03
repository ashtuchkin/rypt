mod aes256_gcm;
mod xchacha20;

// Reexport the algorithms
pub use aes256_gcm::Aes256Gcm;
pub use xchacha20::XChaCha20;
