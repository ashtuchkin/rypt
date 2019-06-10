use failure::Fail;
use prost::DecodeError;

#[derive(Fail, Debug)]
pub enum MyError {
    #[fail(display = "Sodium library initialization error")]
    InitError(()),

    #[fail(display = "Password required")]
    PasswordRequired,

    #[fail(display = "Decryption Error: {}", _0)]
    DecryptionError(String),

    #[fail(display = "Invalid header: {}", _0)]
    InvalidHeader(String),

    #[fail(display = "Invalid header protobuf: {}", _0)]
    InvalidHeaderProto(#[cause] DecodeError),

    #[fail(display = "Thread Join Error")]
    ThreadJoinError,

    #[fail(display = "Unknown encoding algorithm: {}", _0)]
    UnknownAlgorithm(String),

    #[fail(display = "Encoding algorithm is unsupported by this CPU")]
    HardwareUnsupported,

    #[fail(display = "Header is too large ({} bytes, maximum allowed {} bytes)", _0, _1)]
    EncodingError(usize, usize),

    #[fail(display = "Failed to derive key from password (invalid parameters?)")]
    KeyDerivationError,
}
