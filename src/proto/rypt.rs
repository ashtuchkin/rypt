/// 'rypt' format file header. Note, the header itself is not encrypted (as its contents are needed for decryption),
/// but it is always authenticated via the AEAD encryption algorithm.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileHeader {
    /// File Format version; every backwards-incompatible change will result in increment here.
    /// Decryptors must reject version above the one they support.
    #[prost(enumeration="FormatVersion", tag="1")]
    pub version: i32,
    /// Public key for the ephemeral keypair generated for this file.
    #[prost(bytes, tag="6")]
    pub ephemeral_pk: std::vec::Vec<u8>,
    /// Encrypted payload_key.
    #[prost(message, optional, tag="8")]
    pub payload_key: ::std::option::Option<CompositeKey>,
    /// Encrypted 'EncryptedHeader' protobuf.
    #[prost(bytes, tag="9")]
    pub encrypted_header_data: std::vec::Vec<u8>,
    /// User-supplied additional non-encrypted data that will be authenticated together with the rest of
    /// the file. Optional.
    #[prost(bytes, tag="11")]
    pub associated_data: std::vec::Vec<u8>,
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
/// CompositeKey is a data structure that can represent a wide range of key requirement setups, allowing complex
/// expressions like requiring "master_key OR ANY-2-OF(key1, key2, (key3a OR key3b))".
/// When trying to decrypt a file, CompositeKey is recursively evaluated given a set of Credentials (passwords,
/// private keys, etc), resulting in the payload key if successful.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompositeKey {
    /// Threshold defines how many key parts are required to recreate the payload key and how to do that:
    ///   * threshold = 1 (or default 0) - any one key part is sufficient ("OR" operation), just use any of them directly.
    ///   * threshold = N - all key parts are required ("AND" operation); to get the resulting key, do a bitwise-XOR.
    ///   * 1 < threshold < N - use Shamir's Secret Sharing scheme. NOTE: Currently N is limited to 255 in this case.
    /// NOTE: Total number of key parts N is not the same as key_parts.len() because EncryptedKeyParts can provide
    /// several key parts (see num_key_parts field)
    #[prost(uint64, tag="1")]
    pub threshold: u64,
    /// Key parts encrypted by Credentials. All key parts must have the same length.
    #[prost(message, repeated, tag="2")]
    pub key_parts: ::std::vec::Vec<EncryptedKeyParts>,
}
/// Key parts encrypted by Credentials. When evaluated, this structure results in 0, 1 or more key parts, depending on
/// how many Credentials matched and how many parts are included.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedKeyParts {
    /// How many key parts are included in the key data below. Default value of 0 is treated as 1.
    #[prost(uint64, tag="1")]
    pub num_key_parts: u64,
    /// Key data is N key parts concatenated, where N is given in 'parts_included' field above. All key parts must be
    /// the same size, so decoding is easy - just split the key data into N equal chunks.
    #[prost(oneof="encrypted_key_parts::KeyData", tags="2, 3")]
    pub key_data: ::std::option::Option<encrypted_key_parts::KeyData>,
}
pub mod encrypted_key_parts {
    /// Key data is N key parts concatenated, where N is given in 'parts_included' field above. All key parts must be
    /// the same size, so decoding is easy - just split the key data into N equal chunks.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum KeyData {
        /// Key data that is directly encrypted using one of the Credentials (using either AEAD or Box construction).
        #[prost(bytes, tag="2")]
        EncryptedKeyData(std::vec::Vec<u8>),
        /// Key data is the result of recursive CompositeKey evaluation.
        #[prost(message, tag="3")]
        CompositeKey(super::CompositeKey),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedHeader {
    /// Length in bytes of plaintext 'chunks' that we're encrypting and authenticating. The source file/stream
    /// has to be split into chunks to avoid having to read all the contents into memory. All chunks have the same
    /// length except the last one, which might be smaller.
    /// NOTE: Corresponding chunks in encrypted file are usually larger, to accommodate MAC codes. This additional size
    /// depends on the algorithm.
    #[prost(fixed64, tag="4")]
    pub plaintext_chunk_size: u64,
    #[prost(enumeration="SenderAuthType", tag="1")]
    pub sender_auth_type: i32,
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
