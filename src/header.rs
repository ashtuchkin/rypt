use std::cmp::max;
use std::convert::TryInto;
use std::mem::size_of;

use failure::{bail, ensure, err_msg, Fallible, ResultExt};
use prost::Message;
use rand::Rng;
use static_assertions::const_assert_eq;

use crate::commands::{DecryptOptions, EncryptOptions};
use crate::credentials::{ComplexCredential, Credential};
use crate::crypto::{
    instantiate_crypto_system, AEADAlgorithm, AEADKey, AEADNonce, BoxNonce, CryptoError,
    CryptoSystem, CryptoSystemRng, HMacKey, KdfSalt, PrivateKey, PublicKey, AEAD_MAC_LEN,
    AEAD_NONCE_LEN, BOX_MAC_LEN, BOX_NONCE_LEN, KDF_SALT_LEN,
};
use crate::header_io::{FILE_ALIGNMENT, MAX_HEADER_LEN};
use crate::proto::rypt::{
    encrypted_key_parts::KeyData, libsodium_crypto_family::AeadAlgorithm,
    rypt_file_header::CryptoFamily, CompositeKey, EncryptedKeyParts, LibsodiumCryptoFamily,
    ProtectedHeader, RyptFileHeader, SenderAuthType,
};
use crate::shamir::{self, SecretShareError};
use crate::stream_crypto::CryptoSystemAEADCodec;
use crate::stream_pipeline::StreamConverter;
use crate::util::{serialize_proto, xor_vec};

const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const DEFAULT_CHUNK_SIZE_UNCERTAINTY: usize = 4096;
const MAX_CHUNK_SIZE: usize = 1024 * 1024 * 1024;
const ENCRYPTED_HEADER_NONCE: &AEADNonce = b"rypt header\0";
const KDF_SALT_NONCE: &HMacKey = b"rypt kdf salt\0                  ";
const SYMMETRIC_SECRET_NONCE: &HMacKey = b"rypt symmetric secret\0          ";
const RECIPIENT_NONCE: &AEADNonce = b"ryptrecp\0\0\0\0"; // Zeros will be replaced with recip_idx
const RECIP_IDX_POS: usize = AEAD_NONCE_LEN - size_of::<u32>(); // Put recipient index in the last 4 bytes.
const RECIPIENT_BOX_NONCE: &BoxNonce = b"rypt recipient      \0\0\0\0"; // Zeros will be replaced with recip_idx
const RECIP_BOX_IDX_POS: usize = BOX_NONCE_LEN - size_of::<u32>(); // Put recipient index in the last 4 bytes.

/// Create CryptoFamily enum (protobuf) based on command line options.
fn cryptofamily_from_opts(opts: &EncryptOptions) -> Option<CryptoFamily> {
    Some(CryptoFamily::Libsodium(LibsodiumCryptoFamily {
        aead_algorithm: if opts.fast_aead_algorithm {
            AeadAlgorithm::Aes256gcm.into()
        } else {
            AeadAlgorithm::Chacha20poly1305.into()
        },
    }))
}

/// Instantiate a CryptoSystem based on protobuf definition (CryptoFamily enum)
fn cryptosys_from_proto(crypto_family: &Option<CryptoFamily>) -> Fallible<Box<dyn CryptoSystem>> {
    match crypto_family {
        Some(CryptoFamily::Libsodium(LibsodiumCryptoFamily { aead_algorithm })) => {
            let aead_algorithm = match AeadAlgorithm::from_i32(*aead_algorithm) {
                Some(AeadAlgorithm::Chacha20poly1305) => AEADAlgorithm::ChaCha20Poly1305Ietf,
                Some(AeadAlgorithm::Aes256gcm) => AEADAlgorithm::AES256GCM,
                _ => bail!("Unknown aead algorithm"),
            };
            Ok(instantiate_crypto_system(aead_algorithm)?)
        }
        _ => bail!("Unknown crypto_family"),
    }
}

fn recipient_secret_key(
    cryptosys: &dyn CryptoSystem,
    ephemeral_pk: &PublicKey,
    credential: &Credential,
) -> Box<AEADKey> {
    match credential {
        Credential::Password(password) => {
            let mut salt: KdfSalt = Default::default();
            salt.copy_from_slice(&cryptosys.hmac(&*ephemeral_pk, KDF_SALT_NONCE)[..KDF_SALT_LEN]);
            cryptosys.key_derivation(&password, &salt)
        }
        Credential::SymmetricKey(secret_key) => {
            let mut composed_key = ephemeral_pk.to_vec();
            composed_key.extend(secret_key);
            cryptosys.hmac(&composed_key, SYMMETRIC_SECRET_NONCE)
        }
        _ => panic!("Unexpected credential type"),
    }
}

fn recipient_secret_nonce(recipient_idx: usize) -> Box<AEADNonce> {
    let mut nonce = Box::new(*RECIPIENT_NONCE);
    nonce[RECIP_IDX_POS..].copy_from_slice(&(recipient_idx as u32).to_le_bytes());
    nonce
}

fn recipient_box_nonce(recipient_idx: usize) -> Box<BoxNonce> {
    let mut nonce = Box::new(*RECIPIENT_BOX_NONCE);
    nonce[RECIP_BOX_IDX_POS..].copy_from_slice(&(recipient_idx as u32).to_le_bytes());
    nonce
}

fn split_key_into_key_parts<R: rand::Rng + rand::CryptoRng>(
    key: &[u8],
    num_parts: usize,
    threshold: usize,
    rng: &mut R,
) -> Fallible<Vec<Vec<u8>>> {
    ensure!(threshold != 0, "Threshold can't be zero");
    ensure!(
        threshold <= num_parts,
        "Threshold can't be more than the number of credentials"
    );
    ensure!(
        key.len() * num_parts < MAX_HEADER_LEN,
        "Key requirement scheme requires too much space"
    );
    Ok(if threshold == 1 {
        // "OR" condition: all key parts are the same and equal to the key itself.
        vec![key.to_vec(); num_parts]
    } else if threshold == num_parts {
        // "AND" condition: all key parts are required; we use XOR operation to split them.
        let mut key_parts = vec![];
        let mut xor_part = key.to_vec();
        for _ in 0..num_parts - 1 {
            let mut v = vec![0u8; key.len()];
            rng.fill_bytes(&mut v);
            xor_vec(&mut xor_part, &v);
            key_parts.push(v);
        }
        key_parts.push(xor_part);
        key_parts
    } else {
        // M-out-of-N threshold: use Shamir's Secret Sharing.
        shamir::create_secret_shares(key, num_parts, threshold, rng)?
    })
}

// Use 0 instead of 1 for `num_key_parts` and `threshold` fields in protobufs because it has the
// same semantics, but saves space when serialized.
fn one_to_zero(val: usize) -> u64 {
    (if val == 1 { 0 } else { val } as u64)
}

fn encrypt_composite_key(
    cryptosys: &dyn CryptoSystem,
    ephemeral_pk: &PublicKey,
    ephemeral_sk: &PrivateKey,
    key: &[u8],
    cred: &ComplexCredential,
    key_idx: &mut usize,
) -> Fallible<CompositeKey> {
    let rng = &mut CryptoSystemRng::new(cryptosys);
    let mut key_parts: &[Vec<u8>] =
        &split_key_into_key_parts(key, cred.num_shares, cred.threshold, rng)?;

    let encrypted_key_parts = cred
        .sub_creds
        .iter()
        .map(|(num_shares, credential)| -> Fallible<EncryptedKeyParts> {
            let (key_part, new_key_parts) = key_parts.split_at(*num_shares);
            key_parts = new_key_parts;
            let key_part = key_part.concat();

            let key_data = match credential {
                Credential::Password(_) | Credential::SymmetricKey(_) => {
                    let secret_key = recipient_secret_key(&*cryptosys, &ephemeral_pk, credential);
                    let nonce = recipient_secret_nonce(*key_idx);
                    *key_idx += 1;

                    KeyData::EncryptedKeyData(cryptosys.aead_encrypt_easy(
                        &key_part,
                        &secret_key,
                        &nonce,
                    ))
                }
                Credential::PublicKey(public_key) => {
                    const_assert_eq!(AEAD_MAC_LEN, BOX_MAC_LEN);
                    let nonce = recipient_box_nonce(*key_idx);
                    *key_idx += 1;
                    KeyData::EncryptedKeyData(cryptosys.box_encrypt_easy(
                        &key_part,
                        public_key,
                        ephemeral_sk,
                        &nonce,
                    )?)
                }
                Credential::PrivateKey(_) => {
                    panic!("Unexpected private key when encoding");
                }
                Credential::Complex(cred) => KeyData::CompositeKey(encrypt_composite_key(
                    cryptosys,
                    ephemeral_pk,
                    ephemeral_sk,
                    &key_part,
                    cred,
                    key_idx,
                )?),
            };

            Ok(EncryptedKeyParts {
                num_key_parts: one_to_zero(*num_shares),
                key_data: Some(key_data),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompositeKey {
        threshold: one_to_zero(cred.threshold),
        key_parts: encrypted_key_parts,
    })
}

fn check_chunk_size(chunk_size: usize) -> Fallible<()> {
    ensure!(
        chunk_size <= MAX_CHUNK_SIZE,
        "Invalid chunk size: too large"
    );
    ensure!(
        chunk_size % FILE_ALIGNMENT == 0,
        "Invalid chunk size: not divisible by file alignment"
    );
    Ok(())
}

pub fn encrypt_header(
    opts: &EncryptOptions,
) -> Fallible<(Vec<u8>, Box<dyn StreamConverter>, usize)> {
    let crypto_family = cryptofamily_from_opts(&opts);
    let cryptosys = cryptosys_from_proto(&crypto_family)?;

    // Add some uncertainty to the chunk size, while keeping 8-byte alignment.
    let chunk_size = DEFAULT_CHUNK_SIZE - DEFAULT_CHUNK_SIZE_UNCERTAINTY
        + CryptoSystemRng::new(&*cryptosys)
            .gen_range(0, 2 * DEFAULT_CHUNK_SIZE_UNCERTAINTY / FILE_ALIGNMENT)
            * FILE_ALIGNMENT;
    check_chunk_size(chunk_size)?;

    let payload_key = cryptosys.aead_keygen();
    let (ephemeral_pk, ephemeral_sk) = cryptosys.generate_keypair();

    // Protected header data. Only Anonymous authentication is supported for now.
    let protected_header = ProtectedHeader {
        plaintext_chunk_size: chunk_size as u64,
        sender_auth_type: SenderAuthType::Anonymous.into(),
        sender_pk: ephemeral_pk.to_vec(),
    };

    let protected_header = cryptosys.aead_encrypt_easy(
        &serialize_proto(&protected_header)?,
        &payload_key,
        ENCRYPTED_HEADER_NONCE,
    );

    // Encrypt payload key
    let encrypted_payload_key = encrypt_composite_key(
        &*cryptosys,
        &ephemeral_pk,
        &ephemeral_sk,
        &*payload_key,
        &opts.credential,
        &mut 0,
    )?;

    // Gather all the data and create RyptFileHeader protobuf
    let header = RyptFileHeader {
        crypto_family,
        ephemeral_pk: ephemeral_pk.to_vec(),
        payload_key: Some(encrypted_payload_key),
        protected_header,
    };
    let serialized_header = serialize_proto(&header)?;
    let header_hash = cryptosys.hash(&serialized_header);

    let codec = Box::new(CryptoSystemAEADCodec::new(
        cryptosys,
        &payload_key,
        &header_hash,
        true,
    ));

    Ok((serialized_header, codec, chunk_size))
}

fn decryptor_from_credential<'a>(
    cryptosys: &'a dyn CryptoSystem,
    ephemeral_pk: &'a PublicKey,
    credential: &'a Credential,
) -> Box<dyn Fn(usize, &[u8]) -> Fallible<Option<Vec<u8>>> + 'a> {
    match credential {
        Credential::Password(_) | Credential::SymmetricKey(_) => {
            // Compute secret key for each credential only once, as it can be slow to derive it from password.
            let secret_key = recipient_secret_key(&*cryptosys, &ephemeral_pk, credential);

            Box::new(
                move |key_idx: usize, encrypted_key: &[u8]| -> Fallible<Option<Vec<u8>>> {
                    let nonce = recipient_secret_nonce(key_idx);
                    match cryptosys.aead_decrypt_easy(encrypted_key, &secret_key, &nonce) {
                        Ok(res) => Ok(Some(res)),
                        Err(CryptoError::InvalidCiphertext) => Ok(None),
                        Err(err) => Err(err.into()),
                    }
                },
            )
        }
        Credential::PublicKey(_) => {
            panic!("Unexpected public key when decoding");
        }
        Credential::PrivateKey(private_key) => Box::new(
            move |key_idx: usize, encrypted_key: &[u8]| -> Fallible<Option<Vec<u8>>> {
                let nonce = recipient_box_nonce(key_idx);
                match cryptosys.box_decrypt_easy(encrypted_key, ephemeral_pk, private_key, &nonce) {
                    Ok(res) => Ok(Some(res)),
                    Err(CryptoError::InvalidCiphertext) => Ok(None),
                    Err(err) => Err(err.into()),
                }
            },
        ),
        Credential::Complex(_) => {
            panic!("Unexpected complex key when decoding");
        }
    }
}

fn decrypt_key_parts<'a>(
    key_parts: &EncryptedKeyParts,
    decryptors: &[impl AsRef<dyn Fn(usize, &[u8]) -> Fallible<Option<Vec<u8>>> + 'a>],
    key_start_idx: &mut usize,
    key_part_start_idx: &mut usize,
) -> Fallible<Vec<(usize, Vec<u8>)>> {
    // 1. Try to decrypt key data using credentials (wrapped in decryptors)
    let keydata_opt = match &key_parts.key_data {
        Some(KeyData::EncryptedKeyData(simple_key)) => {
            let key_idx = *key_start_idx;
            *key_start_idx += 1;
            decryptors
                .iter()
                .find_map(|decryptor| decryptor.as_ref()(key_idx, simple_key).transpose())
                .transpose()?
        }
        Some(KeyData::CompositeKey(composite_key)) => {
            decrypt_composite_key(composite_key, decryptors, key_start_idx)?
        }
        None => bail!("Invalid composite key: no payload"),
    };

    // 2. Split the key data into key parts, as needed.
    let num_key_parts = max(key_parts.num_key_parts as usize, 1);
    let key_part_idx = *key_part_start_idx;
    *key_part_start_idx += num_key_parts;
    Ok(if let Some(key_data) = keydata_opt {
        if num_key_parts == 1 {
            vec![(key_part_idx, key_data)]
        } else {
            ensure!(
                key_data.len() % num_key_parts == 0,
                "Invalid key data length: can't be divided evenly into key parts"
            );
            let key_len = key_data.len() / num_key_parts;
            key_data
                .chunks_exact(key_len)
                .enumerate()
                .map(|(idx, key)| (idx + key_part_idx, key.to_vec()))
                .collect()
        }
    } else {
        vec![]
    })
}

fn decrypt_composite_key<'a>(
    composite_key: &CompositeKey,
    decryptors: &[impl AsRef<dyn Fn(usize, &[u8]) -> Fallible<Option<Vec<u8>>> + 'a>],
    start_key_idx: &mut usize,
) -> Fallible<Option<Vec<u8>>> {
    let mut num_key_parts = 0;

    // 1. Try to decrypt as many key parts as possible using our credentials (wrapped by decryptors)
    let mut decrypted_key_parts = vec![];
    for key_parts in &composite_key.key_parts {
        let mut valid_parts =
            decrypt_key_parts(key_parts, decryptors, start_key_idx, &mut num_key_parts)?;
        decrypted_key_parts.append(&mut valid_parts);
    }

    // 2. Try to reconstruct resulting key using threshold logic.
    let threshold = max(composite_key.threshold as usize, 1);
    if threshold == 1 {
        // "OR" operator - any of the key parts can be used directly as the key.
        Ok(decrypted_key_parts.into_iter().next().map(|(_, key)| key))
    } else if threshold == num_key_parts {
        // "AND" operator - all key parts must be present. To reconstruct the key we use XOR operation.
        if decrypted_key_parts.len() == threshold {
            let mut key = vec![0u8; decrypted_key_parts[0].1.len()];
            for (_, key_part) in decrypted_key_parts {
                xor_vec(&mut key, &key_part);
            }
            Ok(Some(key))
        } else {
            Ok(None)
        }
    } else {
        // N-out-of-M secret sharing case: Use Shamir's Secret sharing
        match shamir::recover_secret(&decrypted_key_parts, threshold) {
            Ok(key) => Ok(Some(key)),
            Err(SecretShareError::NotEnoughShares { .. }) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

pub fn decrypt_header(
    serialized_header: &[u8],
    opts: &DecryptOptions,
) -> Fallible<(Box<dyn StreamConverter>, usize)> {
    let header = RyptFileHeader::decode(serialized_header)
        .with_context(|e| format!("Invalid header protobuf: {}", e))?;

    let cryptosys = cryptosys_from_proto(&header.crypto_family)?;
    let ephemeral_pk: PublicKey = header.ephemeral_pk.as_slice().try_into()?;

    let payload_key = {
        let decryptors = opts
            .credentials
            .iter()
            .map(|cred| decryptor_from_credential(&*cryptosys, &ephemeral_pk, &cred))
            .collect::<Vec<_>>();

        let root_key = &header
            .payload_key
            .ok_or_else(|| err_msg("Invalid header: no payload key"))?;

        decrypt_composite_key(root_key, decryptors.as_slice(), &mut 0)?
            .ok_or_else(|| err_msg("Invalid or insufficient credentials"))?
    };

    let payload_key: AEADKey = payload_key.as_slice().try_into()?;

    let protected_header = cryptosys.aead_decrypt_easy(
        &header.protected_header,
        &payload_key,
        ENCRYPTED_HEADER_NONCE,
    )?;
    let protected_header: ProtectedHeader = ProtectedHeader::decode(&protected_header)
        .with_context(|e| format!("Invalid encrypted header protobuf: {}", e))?;

    let chunk_size = protected_header.plaintext_chunk_size as usize;
    check_chunk_size(chunk_size)?;

    // Check sender_auth_type, even though we only support anonymous.
    match SenderAuthType::from_i32(protected_header.sender_auth_type) {
        Some(SenderAuthType::Anonymous) => {
            ensure!(
                protected_header.sender_pk == header.ephemeral_pk,
                "Invalid encrypted header protobuf: wrong sender_pk"
            );
        }
        _ => {
            bail!("Unknown sender authentication type");
        }
    }

    let header_hash = cryptosys.hash(&serialized_header);
    let codec = Box::new(CryptoSystemAEADCodec::new(
        cryptosys,
        &payload_key,
        &header_hash,
        false,
    ));

    Ok((codec, chunk_size))
}
