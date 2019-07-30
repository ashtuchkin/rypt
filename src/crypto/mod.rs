pub use crate::crypto::libsodium::AEADAlgorithm;
use crate::crypto::libsodium::LibSodiumCryptoSystem;
use failure::Fail;
use std::convert::TryInto;

mod libsodium;

/// CryptoSystem is a set of cryptographical primitives we use in Rypt to provide authenticated
/// encryption using either passwords, or public/private keys. All functions work with fixed-size
/// array arguments (i.e. `&[u8; 32]`) and not slices/vectors, for obvious benefits.  
///
/// NOTE, in current state, it's rather tightly coupled with libsodium implementation, mostly via
/// the input/output parameter lengths. It doesn't seem to be easy to decouple this, so we're
/// keeping it as is, until we introduce a second, non-libsodium implementation (which may never
/// happen btw).
///
/// The lengths are mostly straightforward, with the exception of a rather short AEAD_NONCE_LEN (12
/// bytes). The main reason to make it this size (and use ChaCha20-IETF algorithm instead of the
/// XChaCha20) is to keep the interface compatible with a much faster AES256-GCM algorithm.
/// The usual concerns about short nonce lengths are taken into account at the callsites - the
/// nonces are deterministic and use counters with different prefixes to ensure uniqueness.

macro_rules! define_named_bytes {
    ($type: ident, $len_name: ident, $len: expr) => {
        pub const $len_name: usize = $len;

        #[derive(Copy, Clone, PartialEq)]
        pub struct $type([u8; $len_name]);

        impl std::convert::From<[u8; $len_name]> for $type {
            #[inline]
            fn from(value: [u8; $len_name]) -> Self {
                $type { 0: value }
            }
        }

        impl std::convert::From<$type> for [u8; $len_name] {
            #[inline]
            fn from(val: $type) -> Self {
                val.0
            }
        }

        impl std::convert::TryFrom<&[u8]> for $type {
            type Error = std::array::TryFromSliceError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Ok($type {
                    0: value.try_into()?,
                })
            }
        }

        impl $type {
            pub unsafe fn zero() -> $type {
                $type {
                    0: std::mem::zeroed(),
                }
            }

            #[inline]
            pub fn to_vec(&self) -> Vec<u8> {
                self.0.to_vec()
            }

            //            pub fn copy_from_slice(&mut self, slice: &[u8]) {
            //                self.0.copy_from_slice(slice)
            //            }

            #[inline]
            pub unsafe fn as_ptr(&self) -> *const u8 {
                self.0.as_ptr()
            }

            #[inline]
            pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
                self.0.as_mut_ptr()
            }
        }
    };
}

define_named_bytes!(HashOutput, HASH_OUTPUT_LEN, 32);

pub const HMAC_OUTPUT_LEN: usize = 32;
pub type HMacOutput = [u8; HMAC_OUTPUT_LEN];

pub const HMAC_KEY_LEN: usize = 32;
pub type HMacKey = [u8; HMAC_KEY_LEN];

define_named_bytes!(AEADKey, AEAD_KEY_LEN, 32);

pub const AEAD_NONCE_LEN: usize = 12;
pub type AEADNonce = [u8; AEAD_NONCE_LEN];

pub const AEAD_MAC_LEN: usize = 16;
pub type AEADMac = [u8; AEAD_MAC_LEN];

pub const PUBLIC_KEY_LEN: usize = 32;
pub type PublicKey = [u8; PUBLIC_KEY_LEN];

pub const PRIVATE_KEY_LEN: usize = 64;
pub type PrivateKey = [u8; PRIVATE_KEY_LEN];

pub const BOX_NONCE_LEN: usize = 24;
pub type BoxNonce = [u8; BOX_NONCE_LEN];

pub const BOX_MAC_LEN: usize = 16;
pub type BoxMac = [u8; BOX_MAC_LEN];

pub const SIGNATURE_LEN: usize = 64;
pub type Signature = [u8; SIGNATURE_LEN];

pub const KDF_SALT_LEN: usize = 16;
pub type KdfSalt = [u8; KDF_SALT_LEN];

pub const KDF_OUTPUT_LEN: usize = 32;
pub type KdfOutput = [u8; KDF_OUTPUT_LEN];

#[derive(Copy, Clone, Debug, PartialEq, Fail)]
pub enum CryptoError {
    #[fail(display = "Invalid ciphertext")]
    InvalidCiphertext,

    #[fail(display = "Invalid public or private key")]
    InvalidPublicPrivateKeyPair,

    #[fail(display = "Invalid signature")]
    InvalidSignature,
}

#[derive(Copy, Clone, Debug, PartialEq, Fail)]
pub enum CryptoInstantiationError {
    #[fail(display = "Crypto library initialization error")]
    InitializationError,

    #[fail(display = "Unsupported hardware")]
    HardwareUnsupported,
}

pub trait CryptoSystem: Send {
    fn hash(&self, message: &[u8]) -> Box<HashOutput>;

    fn hmac(&self, message: &[u8], key: &HMacKey) -> Box<HMacOutput>;

    fn aead_keygen(&self) -> Box<AEADKey>;

    // Encrypt/decrypt in-place, in `message` argument; fills out `mac`
    fn aead_encrypt(
        &self,
        message: &mut [u8],
        additional_data: &[u8],
        key: &AEADKey,
        nonce: &AEADNonce,
        mac: &mut AEADMac,
    );

    fn aead_decrypt(
        &self,
        message: &mut [u8],
        additional_data: &[u8],
        key: &AEADKey,
        nonce: &AEADNonce,
        mac: &AEADMac,
    ) -> Result<(), CryptoError>;

    fn aead_max_message_size(&self) -> usize;

    // Box and Sign/Verify use the same public/private key pairs.
    fn generate_keypair(&self) -> (Box<PublicKey>, Box<PrivateKey>);

    // Encrypt/decrypt in-place, in `message` argument; fills out `mac` argument
    fn box_encrypt(
        &self,
        message: &mut [u8],
        public_key: &PublicKey,
        private_key: &PrivateKey,
        nonce: &BoxNonce,
        mac: &mut BoxMac,
    ) -> Result<(), CryptoError>;

    fn box_decrypt(
        &self,
        message: &mut [u8],
        public_key: &PublicKey,
        private_key: &PrivateKey,
        nonce: &BoxNonce,
        mac: &BoxMac,
    ) -> Result<(), CryptoError>;

    fn sign(&self, message: &[u8], private_key: &PrivateKey, signature: &mut Signature);

    fn verify(
        &self,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), CryptoError>;

    fn key_derivation(&self, password: &str, salt: &KdfSalt) -> Box<KdfOutput>;

    // ====  Helper functions based on the primitives above  =======================================

    fn aead_encrypt_easy(&self, plaintext: &[u8], key: &AEADKey, nonce: &AEADNonce) -> Vec<u8> {
        let mut ciphertext = vec![0u8; plaintext.len() + AEAD_MAC_LEN];
        let (message, mac) = ciphertext.split_at_mut(plaintext.len());
        message.copy_from_slice(plaintext);
        let additional_data = &[0u8; 0];
        self.aead_encrypt(
            message,
            additional_data,
            key,
            nonce,
            mac.try_into().unwrap(),
        );
        ciphertext
    }

    fn aead_decrypt_easy(
        &self,
        ciphertext: &[u8],
        key: &AEADKey,
        nonce: &AEADNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < AEAD_MAC_LEN {
            return Err(CryptoError::InvalidCiphertext);
        }
        let plaintext_len = ciphertext.len() - AEAD_MAC_LEN;
        let mut plaintext = vec![0u8; plaintext_len];
        plaintext.copy_from_slice(&ciphertext[..plaintext_len]);
        let mac: &AEADMac = ciphertext[plaintext_len..].try_into().unwrap();
        self.aead_decrypt(&mut plaintext, &[0u8; 0], key, nonce, mac)?;
        Ok(plaintext)
    }

    fn box_encrypt_easy(
        &self,
        plaintext: &[u8],
        public_key: &PublicKey,
        private_key: &PrivateKey,
        nonce: &BoxNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut ciphertext = vec![0u8; plaintext.len() + BOX_MAC_LEN];
        let (message, mac) = ciphertext.split_at_mut(plaintext.len());
        message.copy_from_slice(plaintext);
        self.box_encrypt(
            message,
            public_key,
            private_key,
            nonce,
            mac.try_into().unwrap(),
        )?;
        Ok(ciphertext)
    }

    fn box_decrypt_easy(
        &self,
        ciphertext: &[u8],
        public_key: &PublicKey,
        private_key: &PrivateKey,
        nonce: &BoxNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < BOX_MAC_LEN {
            return Err(CryptoError::InvalidCiphertext);
        }
        let plaintext_len = ciphertext.len() - BOX_MAC_LEN;
        let mut plaintext = vec![0u8; plaintext_len];
        plaintext.copy_from_slice(&ciphertext[..plaintext_len]);
        let mac: &AEADMac = ciphertext[plaintext_len..].try_into().unwrap();
        self.box_decrypt(&mut plaintext, public_key, private_key, nonce, mac)?;
        Ok(plaintext)
    }
}

pub fn instantiate_crypto_system(
    aead_algorithm: AEADAlgorithm,
) -> Result<Box<CryptoSystem>, CryptoInstantiationError> {
    Ok(Box::new(LibSodiumCryptoSystem::new(aead_algorithm)?))
}
