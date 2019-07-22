use crate::crypto::libsodium::AEADAlgorithm;
use failure::Fail;
use libsodium::LibSodiumCryptoSystem;
use std::convert::TryInto;
use std::mem::size_of;

mod libsodium;

pub type HashOutput = [u8; 32];
pub type HMacOutput = [u8; 32];
pub type HMacKey = [u8; 32];
pub type AEADKey = [u8; 32];
pub type AEADNonce = [u8; 12];
pub type AEADMac = [u8; 16];
pub type PublicKey = [u8; 32];
pub type PrivateKey = [u8; 64];
pub type BoxNonce = [u8; 24];
pub type BoxMac = [u8; 16];
pub type Signature = [u8; 64];
pub type KdfSalt = [u8; 16];
pub type KdfOutput = [u8; 32];

pub const AEAD_MAC_LEN: usize = size_of::<AEADMac>();
pub const BOX_MAC_LEN: usize = size_of::<BoxMac>();
pub const SIGNATURE_LEN: usize = size_of::<Signature>();

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

pub trait CryptoSystem {
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

pub fn instantiate_crypto_system() -> Result<Box<CryptoSystem>, CryptoInstantiationError> {
    Ok(Box::new(LibSodiumCryptoSystem::new(
        AEADAlgorithm::ChaCha20Poly1305Ietf,
    )?))
}
