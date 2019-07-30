use crate::crypto::{
    AEADKey, AEADMac, AEADNonce, BoxMac, BoxNonce, CryptoError, CryptoInstantiationError,
    CryptoSystem, HMacKey, HMacOutput, HashOutput, KdfOutput, KdfSalt, PrivateKey, PublicKey,
    Signature,
};
use libsodium_sys::{
    crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_NPUBBYTES,
    crypto_aead_aes256gcm_decrypt_detached, crypto_aead_aes256gcm_encrypt_detached,
    crypto_aead_aes256gcm_is_available, crypto_aead_aes256gcm_keygen,
    crypto_aead_aes256gcm_messagebytes_max, crypto_aead_chacha20poly1305_ietf_ABYTES,
    crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    crypto_aead_chacha20poly1305_ietf_encrypt_detached, crypto_aead_chacha20poly1305_ietf_keygen,
    crypto_aead_chacha20poly1305_ietf_messagebytes_max, crypto_auth, crypto_auth_BYTES,
    crypto_auth_KEYBYTES, crypto_box_BEFORENMBYTES, crypto_box_MACBYTES, crypto_box_NONCEBYTES,
    crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES, crypto_box_beforenm,
    crypto_box_detached_afternm, crypto_box_open_detached_afternm, crypto_hash, crypto_hash_BYTES,
    crypto_pwhash, crypto_pwhash_ALG_ARGON2ID13, crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_SALTBYTES, crypto_sign_BYTES,
    crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES, crypto_sign_detached,
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_keypair, crypto_sign_verify_detached, sodium_init, sodium_memzero,
};
use static_assertions::assert_eq_size;
use std::convert::TryFrom;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AEADAlgorithm {
    ChaCha20Poly1305Ietf = 1,
    AES256GCM = 2,
}

const ALL_AEAD_ALGORITHMS: &[AEADAlgorithm] = &[
    AEADAlgorithm::ChaCha20Poly1305Ietf,
    AEADAlgorithm::AES256GCM,
];

impl TryFrom<u64> for AEADAlgorithm {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        for &alg in ALL_AEAD_ALGORITHMS {
            if alg as u64 == value {
                return Ok(alg);
            }
        }
        Err(())
    }
}

pub struct LibSodiumCryptoSystem {
    aead_algorithm: AEADAlgorithm,
}

impl LibSodiumCryptoSystem {
    pub fn new(
        aead_algorithm: AEADAlgorithm,
    ) -> Result<LibSodiumCryptoSystem, CryptoInstantiationError> {
        if unsafe { sodium_init() } == -1 {
            return Err(CryptoInstantiationError::InitializationError);
        }

        if aead_algorithm == AEADAlgorithm::AES256GCM
            && unsafe { crypto_aead_aes256gcm_is_available() } == 0
        {
            return Err(CryptoInstantiationError::HardwareUnsupported);
        }

        Ok(LibSodiumCryptoSystem { aead_algorithm })
    }
}

impl CryptoSystem for LibSodiumCryptoSystem {
    fn hash(&self, message: &[u8]) -> Box<HashOutput> {
        let mut hash = [0u8; crypto_hash_BYTES as usize];

        unsafe {
            crypto_hash(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64);
        }

        // Return the first 32 bytes of the 64 byte SHA512 hash.
        let mut result: Box<HashOutput> = Default::default();
        let result_len = result.len();
        result.copy_from_slice(&hash[..result_len]);
        wipe_buf(&mut hash);
        result
    }

    fn hmac(&self, message: &[u8], key: &HMacKey) -> Box<HMacOutput> {
        assert_eq_size!(HMacKey, [u8; crypto_auth_KEYBYTES as usize]);
        assert_eq_size!(HMacOutput, [u8; crypto_auth_BYTES as usize]);
        let mut result: Box<HMacOutput> = Default::default();
        unsafe {
            crypto_auth(
                result.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
            );
        }
        result
    }

    fn aead_keygen(&self) -> Box<AEADKey> {
        match self.aead_algorithm {
            AEADAlgorithm::ChaCha20Poly1305Ietf => {
                let mut res = Box::new([0u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize]);
                unsafe {
                    crypto_aead_chacha20poly1305_ietf_keygen(res.as_mut_ptr());
                }
                res
            }
            AEADAlgorithm::AES256GCM => {
                let mut res = Box::new([0u8; crypto_aead_aes256gcm_KEYBYTES as usize]);
                unsafe {
                    crypto_aead_aes256gcm_keygen(res.as_mut_ptr());
                }
                res
            }
        }
    }

    // Encrypt/decrypt in-place, in `message` argument; fills out `mac`
    fn aead_encrypt(
        &self,
        message: &mut [u8],
        additional_data: &[u8],
        key: &AEADKey,
        nonce: &AEADNonce,
        mac: &mut AEADMac,
    ) {
        assert_eq_size!(
            AEADKey,
            [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize]
        );
        assert_eq_size!(
            AEADNonce,
            [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize]
        );
        assert_eq_size!(
            AEADMac,
            [u8; crypto_aead_chacha20poly1305_ietf_ABYTES as usize]
        );
        assert_eq_size!(AEADKey, [u8; crypto_aead_aes256gcm_KEYBYTES as usize]);
        assert_eq_size!(AEADNonce, [u8; crypto_aead_aes256gcm_NPUBBYTES as usize]);
        assert_eq_size!(AEADMac, [u8; crypto_aead_aes256gcm_ABYTES as usize]);

        match self.aead_algorithm {
            AEADAlgorithm::ChaCha20Poly1305Ietf => unsafe {
                crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                    message.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    std::ptr::null_mut(), // MAC len is guaranteed to be ABYTES
                    message.as_ptr(),
                    message.len() as u64,
                    additional_data.as_ptr(),
                    additional_data.len() as u64,
                    std::ptr::null(), // nsec: must be null
                    nonce.as_ptr(),
                    key.as_ptr(),
                );
            },
            AEADAlgorithm::AES256GCM => unsafe {
                crypto_aead_aes256gcm_encrypt_detached(
                    message.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    std::ptr::null_mut(), // MAC len is guaranteed to be ABYTES
                    message.as_ptr(),
                    message.len() as u64,
                    additional_data.as_ptr(),
                    additional_data.len() as u64,
                    std::ptr::null(), // nsec: must be null
                    nonce.as_ptr(),
                    key.as_ptr(),
                );
            },
        }
    }

    fn aead_decrypt(
        &self,
        message: &mut [u8],
        additional_data: &[u8],
        key: &AEADKey,
        nonce: &AEADNonce,
        mac: &AEADMac,
    ) -> Result<(), CryptoError> {
        // NOTE: key, nonce and mac lengths are asserted to be correct in aead_encrypt above.
        let res = match self.aead_algorithm {
            AEADAlgorithm::ChaCha20Poly1305Ietf => unsafe {
                crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                    message.as_mut_ptr(),
                    std::ptr::null_mut(), // nsec: must be null
                    message.as_ptr(),
                    message.len() as u64,
                    mac.as_ptr(),
                    additional_data.as_ptr(),
                    additional_data.len() as u64,
                    nonce.as_ptr(),
                    key.as_ptr(),
                )
            },
            AEADAlgorithm::AES256GCM => unsafe {
                crypto_aead_aes256gcm_decrypt_detached(
                    message.as_mut_ptr(),
                    std::ptr::null_mut(), // nsec: must be null
                    message.as_ptr(),
                    message.len() as u64,
                    mac.as_ptr(),
                    additional_data.as_ptr(),
                    additional_data.len() as u64,
                    nonce.as_ptr(),
                    key.as_ptr(),
                )
            },
        };

        if res != 0 {
            return Err(CryptoError::InvalidCiphertext);
        }
        Ok(())
    }

    fn aead_max_message_size(&self) -> usize {
        match self.aead_algorithm {
            AEADAlgorithm::ChaCha20Poly1305Ietf => unsafe {
                crypto_aead_chacha20poly1305_ietf_messagebytes_max()
            },
            AEADAlgorithm::AES256GCM => unsafe { crypto_aead_aes256gcm_messagebytes_max() },
        }
    }

    // Encrypt/decrypt in-place, in `message` argument; fills out `mac`
    fn box_encrypt(
        &self,
        message: &mut [u8],
        public_key: &PublicKey,
        private_key: &PrivateKey,
        nonce: &BoxNonce,
        mac: &mut BoxMac,
    ) -> Result<(), CryptoError> {
        // NOTE: Public/private key lengths are asserted to be correct in `box_beforenm` below.
        assert_eq_size!(BoxNonce, [u8; crypto_box_NONCEBYTES as usize]);
        assert_eq_size!(BoxMac, [u8; crypto_box_MACBYTES as usize]);

        let mut k: BoxBeforeNMKey = Default::default();
        box_beforenm(public_key, private_key, &mut k)?;

        unsafe {
            crypto_box_detached_afternm(
                message.as_mut_ptr(),
                mac.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                k.as_ptr(),
            );
        };
        wipe_buf(&mut k);
        Ok(())
    }

    fn box_decrypt(
        &self,
        message: &mut [u8],
        public_key: &PublicKey,
        private_key: &PrivateKey,
        nonce: &BoxNonce,
        mac: &BoxMac,
    ) -> Result<(), CryptoError> {
        // NOTE: public/private key, nonce and mac lengths are asserted to be correct above.

        let mut k: BoxBeforeNMKey = Default::default();
        box_beforenm(public_key, private_key, &mut k)?;

        let res = unsafe {
            crypto_box_open_detached_afternm(
                message.as_mut_ptr(),
                message.as_ptr(),
                mac.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                k.as_ptr(),
            )
        };
        wipe_buf(&mut k);
        if res != 0 {
            return Err(CryptoError::InvalidCiphertext);
        }
        Ok(())
    }

    fn generate_keypair(&self) -> (Box<PublicKey>, Box<PrivateKey>) {
        let mut public_key = Box::new([0u8; crypto_sign_PUBLICKEYBYTES as usize]);
        let mut private_key = Box::new([0u8; crypto_sign_SECRETKEYBYTES as usize]);

        unsafe {
            crypto_sign_keypair(public_key.as_mut_ptr(), private_key.as_mut_ptr());
        }
        (public_key, private_key)
    }

    fn sign(&self, message: &[u8], private_key: &PrivateKey, signature: &mut Signature) {
        assert_eq_size!(PrivateKey, [u8; crypto_sign_SECRETKEYBYTES as usize]);
        assert_eq_size!(PublicKey, [u8; crypto_sign_PUBLICKEYBYTES as usize]);
        assert_eq_size!(Signature, [u8; crypto_sign_BYTES as usize]);
        unsafe {
            crypto_sign_detached(
                signature.as_mut_ptr(),
                std::ptr::null_mut(),
                message.as_ptr(),
                message.len() as u64,
                private_key.as_ptr(),
            );
        }
    }
    fn verify(
        &self,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        // NOTE: signature and public/private key lengths are asserted to be correct above.
        let res = unsafe {
            crypto_sign_verify_detached(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                public_key.as_ptr(),
            )
        };
        if res != 0 {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }

    fn key_derivation(&self, password: &str, salt: &KdfSalt) -> Box<KdfOutput> {
        assert_eq_size!(KdfSalt, [u8; crypto_pwhash_SALTBYTES as usize]);
        let mut output: Box<KdfOutput> = Default::default();
        let password = password.as_bytes();

        let res = unsafe {
            crypto_pwhash(
                output.as_mut_ptr(),
                output.len() as u64,
                password.as_ptr() as *const i8,
                password.len() as u64,
                salt.as_ptr(),
                u64::from(crypto_pwhash_OPSLIMIT_INTERACTIVE),
                crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
                crypto_pwhash_ALG_ARGON2ID13 as i32,
            )
        };
        assert_eq!(res, 0);
        output
    }
}

type BoxBeforeNMKey = [u8; crypto_box_BEFORENMBYTES as usize];

fn box_beforenm(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    output: &mut BoxBeforeNMKey,
) -> Result<(), CryptoError> {
    // NOTE: We always use Ed25519 public/private keys outside this module. To get Curve25519 keys,
    // we always convert them first.
    assert_eq_size!(PrivateKey, [u8; crypto_sign_SECRETKEYBYTES as usize]);
    assert_eq_size!(PublicKey, [u8; crypto_sign_PUBLICKEYBYTES as usize]);

    let mut curve25519_pk = [0u8; crypto_box_PUBLICKEYBYTES as usize];
    let mut curve25519_sk = [0u8; crypto_box_SECRETKEYBYTES as usize];
    let res = unsafe {
        crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.as_mut_ptr(), public_key.as_ptr())
    };
    if res != 0 {
        return Err(CryptoError::InvalidPublicPrivateKeyPair);
    }

    let res = unsafe {
        crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.as_mut_ptr(), private_key.as_ptr())
    };
    if res != 0 {
        return Err(CryptoError::InvalidPublicPrivateKeyPair);
    }

    let res = unsafe {
        crypto_box_beforenm(
            output.as_mut_ptr(),
            curve25519_pk.as_ptr(),
            curve25519_sk.as_ptr(),
        )
    };
    if res != 0 {
        return Err(CryptoError::InvalidPublicPrivateKeyPair);
    }
    Ok(())
}

fn wipe_buf(buf: &mut [u8]) {
    unsafe {
        let len = buf.len();
        sodium_memzero(buf.as_mut_ptr() as *mut std::ffi::c_void, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AEAD_MAC_LEN, BOX_MAC_LEN, SIGNATURE_LEN};
    use failure::Fallible;
    use hex_literal::hex;

    #[test]
    fn test_hash_hmac() -> Fallible<()> {
        let cryptosys = LibSodiumCryptoSystem::new(AEADAlgorithm::ChaCha20Poly1305Ietf)?;

        // Test vectors for SHA512 hash (first 32 bytes)
        assert_eq!(
            *cryptosys.hash(b"abc"),
            hex!("ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a")
        );
        assert_eq!(
            *cryptosys.hash(b""),
            hex!("cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce")
        );

        // Test vectors for HMAC-SHA512256 (https://tools.ietf.org/html/rfc4231)
        assert_eq!(
            *cryptosys.hmac(
                b"Hi There",
                &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 000000000000000000000000")
            ),
            hex!("87aa7cdea5ef619d4ff0b4241a1d6cb0 2379f4e2ce4ec2787ad0b30545e17cde")
        );
        assert_eq!(
            *cryptosys.hmac(
                b"what do ya want for nothing?",
                b"Jefe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            ),
            hex!("164b7a7bfcf819e2e395fbe73b56e0a3 87bd64222e831fd610270cd7ea250554")
        );

        Ok(())
    }

    #[test]
    fn test_aead() -> Fallible<()> {
        for &algo in ALL_AEAD_ALGORITHMS {
            let cryptosys = LibSodiumCryptoSystem::new(algo)?;

            assert!(cryptosys.aead_max_message_size() > 1024 * 1024 * 1024);

            let plaintext = b"Secret payload";
            let additional_data = b"some data";

            let secret_key = &*cryptosys.aead_keygen();
            let nonce = b"rypt\0\0\0\0\0\0\0\0";

            let different_secret_key = &*cryptosys.aead_keygen();
            let different_nonce = b"rypt\0\0\0\0\0\0\0\x01";

            let mut mac = AEADMac::default();
            let mut message = vec![0u8; plaintext.len()];

            // Encrypt..
            message.copy_from_slice(plaintext);
            cryptosys.aead_encrypt(&mut message, additional_data, &secret_key, &nonce, &mut mac);

            // .. message must be encoded in-place and mac must be filled.
            assert_ne!(mac, AEADMac::default());
            assert_ne!(message, plaintext);
            let ciphertext = message.clone();

            // Check successful decryption works
            cryptosys.aead_decrypt(&mut message, additional_data, &secret_key, &nonce, &mac)?;
            assert_eq!(message, plaintext);

            // If decryption fails, message must be zeroed out.
            message.copy_from_slice(&ciphertext);
            let res = cryptosys.aead_decrypt(
                &mut message,
                additional_data,
                &different_secret_key,
                &nonce,
                &mac,
            );
            assert_eq!(res, Err(CryptoError::InvalidCiphertext));

            // Check decryption fails when Nonce does not match
            message.copy_from_slice(&ciphertext);
            let res = cryptosys.aead_decrypt(
                &mut message,
                additional_data,
                &secret_key,
                &different_nonce,
                &mac,
            );
            assert_eq!(res, Err(CryptoError::InvalidCiphertext));

            // Check decryption fails when Mac is invalid
            message.copy_from_slice(&ciphertext);
            let mut different_mac = mac;
            different_mac[0] ^= 1;
            let res = cryptosys.aead_decrypt(
                &mut message,
                additional_data,
                &secret_key,
                &nonce,
                &different_mac,
            );
            assert_eq!(res, Err(CryptoError::InvalidCiphertext));

            // Check decryption fails when authenticated data is different
            message.copy_from_slice(&ciphertext);
            let different_additional_data = b"different data";
            let res = cryptosys.aead_decrypt(
                &mut message,
                different_additional_data,
                &secret_key,
                &nonce,
                &mac,
            );
            assert_eq!(res, Err(CryptoError::InvalidCiphertext));
        }

        Ok(())
    }

    #[test]
    fn test_aead_easy() -> Fallible<()> {
        for &algo in ALL_AEAD_ALGORITHMS {
            let cryptosys = LibSodiumCryptoSystem::new(algo)?;

            let plaintext = b"Secret payload";
            let secret_key = &*cryptosys.aead_keygen();
            let nonce = b"rypt\0\0\0\0\0\0\0\0";

            let ciphertext = cryptosys.aead_encrypt_easy(plaintext, secret_key, nonce);
            let plaintext_res = cryptosys.aead_decrypt_easy(&ciphertext, secret_key, nonce)?;

            assert_eq!(plaintext_res, plaintext);

            let ciphertext_empty = cryptosys.aead_encrypt_easy(b"", secret_key, nonce);
            assert_eq!(ciphertext_empty.len(), AEAD_MAC_LEN);

            let plaintext_empty =
                cryptosys.aead_decrypt_easy(&ciphertext_empty, secret_key, nonce)?;
            assert_eq!(plaintext_empty, b"");
        }
        Ok(())
    }

    #[test]
    fn test_box() -> Fallible<()> {
        let cryptosys = LibSodiumCryptoSystem::new(AEADAlgorithm::ChaCha20Poly1305Ietf)?;

        let (alice_pk, alice_sk) = cryptosys.generate_keypair();
        let (bob_pk, bob_sk) = cryptosys.generate_keypair();

        let plaintext = b"Secret payload";
        let nonce = b"rypt\0\0\0\0\0\0\0\0rypt\0\0\0\0\0\0\0\0";
        let mut mac = BoxMac::default();
        let mut message = vec![0u8; plaintext.len()];

        // Encrypt a message from Alice to Bob
        message.copy_from_slice(plaintext);
        cryptosys.box_encrypt(&mut message, &bob_pk, &alice_sk, &nonce, &mut mac)?;

        assert_ne!(message, plaintext);
        assert_ne!(mac, BoxMac::default());
        let ciphertext = message.clone();

        // Bob decrypts it
        cryptosys.box_decrypt(&mut message, &alice_pk, &bob_sk, &nonce, &mac)?;
        assert_eq!(message, plaintext);

        // Alice should be able to decrypt it too.
        message.copy_from_slice(&ciphertext);
        cryptosys.box_decrypt(&mut message, &bob_pk, &alice_sk, &nonce, &mac)?;
        assert_eq!(message, plaintext);

        // Check decrypt fails if we use incorrect key
        message.copy_from_slice(&ciphertext);
        let (_, different_sk) = cryptosys.generate_keypair();
        let res = cryptosys.box_decrypt(&mut message, &alice_pk, &different_sk, &nonce, &mac);
        assert_eq!(res, Err(CryptoError::InvalidCiphertext));

        message.copy_from_slice(&ciphertext);
        let mut different_nonce = *nonce;
        different_nonce[0] ^= 1;
        let res = cryptosys.box_decrypt(&mut message, &alice_pk, &bob_sk, &different_nonce, &mac);
        assert_eq!(res, Err(CryptoError::InvalidCiphertext));

        message.copy_from_slice(&ciphertext);
        let mut different_mac = mac;
        different_mac[0] ^= 1;
        let res = cryptosys.box_decrypt(&mut message, &alice_pk, &bob_sk, &nonce, &different_mac);
        assert_eq!(res, Err(CryptoError::InvalidCiphertext));

        Ok(())
    }

    #[test]
    fn test_box_easy() -> Fallible<()> {
        let cryptosys = LibSodiumCryptoSystem::new(AEADAlgorithm::ChaCha20Poly1305Ietf)?;

        let (alice_pk, alice_sk) = cryptosys.generate_keypair();
        let (bob_pk, bob_sk) = cryptosys.generate_keypair();

        let plaintext = b"Secret payload";
        let nonce = b"rypt\0\0\0\0\0\0\0\0rypt\0\0\0\0\0\0\0\0";

        // Alice sends to Bob and Bob decrypts it.
        let ciphertext = cryptosys.box_encrypt_easy(plaintext, &bob_pk, &alice_sk, &nonce)?;
        let plaintext_res = cryptosys.box_decrypt_easy(&ciphertext, &alice_pk, &bob_sk, &nonce)?;
        assert_eq!(plaintext_res, plaintext);

        let ciphertext_empty = cryptosys.box_encrypt_easy(b"", &bob_pk, &alice_sk, &nonce)?;
        assert_eq!(ciphertext_empty.len(), BOX_MAC_LEN);

        let plaintext_empty =
            cryptosys.box_decrypt_easy(&ciphertext_empty, &alice_pk, &bob_sk, &nonce)?;
        assert_eq!(plaintext_empty, b"");
        Ok(())
    }

    #[test]
    fn test_signatures() -> Fallible<()> {
        let cryptosys = LibSodiumCryptoSystem::new(AEADAlgorithm::ChaCha20Poly1305Ietf)?;

        let (alice_pk, alice_sk) = cryptosys.generate_keypair();

        let plaintext = b"Secret payload";

        let mut signature = [0u8; SIGNATURE_LEN];
        cryptosys.sign(plaintext, &alice_sk, &mut signature);

        let res = cryptosys.verify(plaintext, &alice_pk, &signature);
        assert_eq!(res, Ok(()));

        signature[0] ^= 1;
        let res = cryptosys.verify(plaintext, &alice_pk, &signature);
        assert_eq!(res, Err(CryptoError::InvalidSignature));

        Ok(())
    }

    #[test]
    fn test_key_derivation() -> Fallible<()> {
        let cryptosys = LibSodiumCryptoSystem::new(AEADAlgorithm::ChaCha20Poly1305Ietf)?;

        let salt = b"kdfsalt\0\0\0\0\0\0\0\0\0";
        let secret_key = cryptosys.key_derivation("password", &salt);

        assert_ne!(*secret_key, KdfOutput::default());
        Ok(())
    }
}
