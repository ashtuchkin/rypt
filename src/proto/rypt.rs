/// 'rypt' format file header. Note, the header itself is not encrypted (as its contents are needed for decryption),
/// but it is always authenticated via the AEAD encryption algorithm.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileHeader {
    /// File Format version; every backwards-incompatible change will result in increment here.
    /// Decryptors must reject version above the one they support.
    #[prost(enumeration="FormatVersion", tag="1")]
    pub version: i32,
    /// Public key for ephemeral keypair generated for this file.
    #[prost(bytes, tag="6")]
    pub ephemeral_pk: std::vec::Vec<u8>,
    /// Ways to decrypt this file.
    #[prost(message, repeated, tag="8")]
    pub recipients: ::std::vec::Vec<Recipient>,
    /// Encrypted 'EncryptedHeader' protobuf.
    #[prost(bytes, tag="9")]
    pub encrypted_header_data: std::vec::Vec<u8>,
    /// User-supplied additional non-encrypted data that will be authenticated together with the rest of
    /// the file. Optional.
    #[prost(bytes, tag="11")]
    pub associated_data: std::vec::Vec<u8>,
    /// Shamir Secret Sharing threshold - number of keys needed to decrypt this file.
    #[prost(uint64, tag="7")]
    pub key_threshold: u64,
    /// Which crypto algorithms to use and corresponding config. Required.
    #[prost(oneof="file_header::CryptoFamily", tags="2")]
    pub crypto_family: ::std::option::Option<file_header::CryptoFamily>,
}
pub mod file_header {
    /// Which crypto algorithms to use and corresponding config. Required.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CryptoFamily {
        /// ids 3, 4, 5 are reserved for future algorithms.
        #[prost(message, tag="2")]
        Libsodium(super::LibsodiumCryptoFamily),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibsodiumCryptoFamily {
    #[prost(enumeration="libsodium_crypto_family::AeadAlgorithm", tag="1")]
    pub aead_algorithm: i32,
}
pub mod libsodium_crypto_family {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum AeadAlgorithm {
        UnknownAlgorithm = 0,
        Chacha20poly1305 = 1,
        /// Potentially HMAC for non-encrypted but signed files.
        Aes256gcm = 2,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Recipient {
    ///bytes recipient_id = 2;  // Optional
    #[prost(bytes, tag="1")]
    pub encrypted_payload: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedHeader {
    #[prost(fixed64, tag="4")]
    pub plaintext_chunk_size: u64,
    #[prost(enumeration="SenderAuthType", tag="1")]
    pub sender_auth_type: i32,
    ///fixed32 repudiable_auth_count = 3;
    #[prost(bytes, tag="2")]
    pub sender_pk: std::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FormatVersion {
    UnknownFormat = 0,
    BasicEncryption = 1,
    SignedSender = 2,
    RepudiableSender = 3,
    SecretSharing = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SenderAuthType {
    UnknownSenderAuthType = 0,
    ///SIGNED = 2;
    ///REPUDIABLE = 3;
    Anonymous = 1,
}
