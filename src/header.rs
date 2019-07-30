use std::convert::TryInto;
use std::mem::size_of;

use failure::{bail, ensure, err_msg, Fallible, ResultExt};
use prost::Message;

use crate::cli::{Credential, DecryptOptions, EncryptOptions};
use crate::crypto::{
    instantiate_crypto_system, AEADAlgorithm, AEADKey, AEADNonce, BoxNonce, CryptoSystem, HMacKey,
    KdfSalt, PrivateKey, PublicKey, AEAD_NONCE_LEN, BOX_NONCE_LEN, KDF_SALT_LEN,
};
use crate::proto::rypt::{
    file_header::CryptoFamily, libsodium_crypto_family::AeadAlgorithm, EncryptedHeader, FileHeader,
    FormatVersion, LibsodiumCryptoFamily, Recipient, RecipientPayload, SenderAuthType,
};
use crate::stream_crypto::CryptoSystemAEADCodec;
use crate::types::StreamConverter;
use crate::util::serialize_proto;

const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const ENCRYPTED_HEADER_NONCE: &AEADNonce = b"rypt header\0";
const KDF_SALT_NONCE: &HMacKey = b"rypt kdf salt\0                  ";
const SYMMETRIC_SECRET_NONCE: &HMacKey = b"rypt symmetric secret\0          ";
const RECIPIENT_NONCE: &AEADNonce = b"ryptrecp\0\0\0\0"; // Zeros will be replaced with recip_idx
const RECIP_IDX_POS: usize = AEAD_NONCE_LEN - size_of::<u32>(); // Put recipient index in the last 4 bytes.
const RECIPIENT_BOX_NONCE: &BoxNonce = b"rypt recipient      \0\0\0\0"; // Zeros will be replaced with recip_idx
const RECIP_BOX_IDX_POS: usize = BOX_NONCE_LEN - size_of::<u32>(); // Put recipient index in the last 4 bytes.
const COMPATIBILITY_VERSION: FormatVersion = FormatVersion::BasicEncryption;

/// Create CryptoFamily enum (protobuf) based on command line options.
fn cryptofamily_from_opts(opts: &EncryptOptions) -> Option<CryptoFamily> {
    Some(CryptoFamily::Libsodium(LibsodiumCryptoFamily {
        aead_algorithm: match opts.fast_aead_algorithm {
            false => AeadAlgorithm::Chacha20poly1305.into(),
            true => AeadAlgorithm::Aes256gcm.into(),
        },
    }))
}

/// Instantiate a CryptoSystem based on protobuf definition (CryptoFamily enum)
fn cryptosys_from_proto(crypto_family: &Option<CryptoFamily>) -> Fallible<Box<CryptoSystem>> {
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
    cryptosys: &CryptoSystem,
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

fn encrypt_payload_for_recipient(
    cryptosys: &CryptoSystem,
    ephemeral_pk: &PublicKey,
    ephemeral_sk: &PrivateKey,
    recipient_payload: &RecipientPayload,
    recipient_idx: usize,
    credential: &Credential,
) -> Recipient {
    let recipient_payload = serialize_proto(recipient_payload).unwrap();
    let encrypted_payload = match credential {
        Credential::Password(_) | Credential::SymmetricKey(_) => {
            let secret_key = recipient_secret_key(&*cryptosys, &ephemeral_pk, credential);
            let nonce = recipient_secret_nonce(recipient_idx);

            cryptosys.aead_encrypt_easy(&recipient_payload, &secret_key, &nonce)
        }
        Credential::PublicKey(public_key) => {
            let nonce = recipient_box_nonce(recipient_idx);
            cryptosys
                .box_encrypt_easy(&recipient_payload, public_key, ephemeral_sk, &nonce)
                .unwrap() // public key might be malformed; panic for now.
        }
        Credential::PrivateKey(_) => {
            panic!("Unexpected private key when encoding");
        }
    };
    Recipient { encrypted_payload }
}

pub fn encrypt_header(opts: &EncryptOptions) -> Fallible<(Vec<u8>, Box<StreamConverter>, usize)> {
    let version = FormatVersion::BasicEncryption.into();

    let crypto_family = cryptofamily_from_opts(&opts);
    let cryptosys = cryptosys_from_proto(&crypto_family)?;

    let chunk_size = DEFAULT_CHUNK_SIZE;
    ensure!(
        chunk_size <= cryptosys.aead_max_message_size(),
        "Chunk size too large - not supported by the encryption algorithm"
    );

    let payload_key = cryptosys.aead_keygen();
    let (ephemeral_pk, ephemeral_sk) = cryptosys.generate_keypair();

    // Encrypted header data
    let sender_auth_type = SenderAuthType::Anonymous;
    let sender_pk = PublicKey::default();
    let encrypted_header = EncryptedHeader {
        plaintext_chunk_size: chunk_size as u64,
        sender_auth_type: sender_auth_type.into(),
        sender_pk: sender_pk.to_vec(),
    };

    let encrypted_header_data = cryptosys.aead_encrypt_easy(
        &serialize_proto(&encrypted_header)?,
        &payload_key,
        ENCRYPTED_HEADER_NONCE,
    );

    // Recipients
    let recipient_payload = RecipientPayload {
        payload_key: payload_key.to_vec(),
    };
    let recipients = opts
        .credentials
        .iter()
        .enumerate()
        .map(|(recipient_idx, credential)| {
            encrypt_payload_for_recipient(
                &*cryptosys,
                &ephemeral_pk,
                &ephemeral_sk,
                &recipient_payload,
                recipient_idx,
                &credential,
            )
        })
        .collect::<Vec<_>>();

    // Gather all the data and create FileHeader
    let header = FileHeader {
        version,
        crypto_family,
        ephemeral_pk: ephemeral_pk.to_vec(),
        recipients,
        encrypted_header_data,
        associated_data: opts.associated_data.clone(),
    };
    let serialized_header = serialize_proto(&header)?;
    let header_hash = cryptosys.hash(&serialized_header);

    let codec = CryptoSystemAEADCodec::new(cryptosys, &payload_key, &header_hash, true);

    Ok((serialized_header, codec, chunk_size))
}

fn decrypt_payload_for_recipient(
    cryptosys: &CryptoSystem,
    ephemeral_pk: &PublicKey,
    encrypted_recipients: &[Recipient],
    credential: &Credential,
) -> Option<RecipientPayload> {
    // Compute secret key for each credential only once, as it can be slow to derive it from password.
    let secret_key = match credential {
        Credential::Password(_) | Credential::SymmetricKey(_) => {
            recipient_secret_key(&*cryptosys, &ephemeral_pk, credential)
        }
        _ => Box::new(AEADKey::default()),
    };

    encrypted_recipients
        .into_iter()
        .enumerate()
        .find_map(|(recipient_idx, recipient)| match credential {
            Credential::Password(_) | Credential::SymmetricKey(_) => {
                let nonce = recipient_secret_nonce(recipient_idx);
                cryptosys
                    .aead_decrypt_easy(&recipient.encrypted_payload, &secret_key, &nonce)
                    .ok()
            }
            Credential::PublicKey(_) => {
                panic!("Unexpected public key when decoding");
            }
            Credential::PrivateKey(private_key) => {
                let nonce = recipient_box_nonce(recipient_idx);
                cryptosys
                    .box_decrypt_easy(
                        &recipient.encrypted_payload,
                        ephemeral_pk,
                        private_key,
                        &nonce,
                    )
                    .ok()
            }
        })
        .and_then(|buf| RecipientPayload::decode(buf).ok())
}

pub fn decrypt_header(
    serialized_header: &[u8],
    opts: &DecryptOptions,
) -> Fallible<(Box<StreamConverter>, usize)> {
    let header: FileHeader = FileHeader::decode(serialized_header)
        .with_context(|e| format!("Invalid header protobuf: {}", e))?;

    ensure!(
        header.version <= COMPATIBILITY_VERSION.into(),
        "Can't decrypt this file - it's too new."
    );

    let cryptosys = cryptosys_from_proto(&header.crypto_family)?;
    let ephemeral_pk: PublicKey = header.ephemeral_pk.as_slice().try_into()?;

    let recipient_payloads = opts
        .credentials
        .iter()
        .filter_map(|credential| {
            decrypt_payload_for_recipient(
                &*cryptosys,
                &ephemeral_pk,
                &header.recipients,
                credential,
            )
        })
        .collect::<Vec<_>>();

    let recipient_payload = recipient_payloads
        .first()
        .ok_or_else(|| err_msg("Invalid credentials"))?;
    let payload_key: AEADKey = recipient_payload.payload_key.as_slice().try_into()?;

    let encrypted_header_buf = cryptosys.aead_decrypt_easy(
        &header.encrypted_header_data,
        &payload_key,
        ENCRYPTED_HEADER_NONCE,
    )?;
    let encrypted_header: EncryptedHeader = EncryptedHeader::decode(&encrypted_header_buf)
        .with_context(|e| format!("Invalid encrypted header protobuf: {}", e))?;

    let chunk_size = encrypted_header.plaintext_chunk_size as usize;
    ensure!(
        chunk_size <= cryptosys.aead_max_message_size(),
        "Chunk size too large - not supported by the encryption algorithm"
    );

    let header_hash = cryptosys.hash(&serialized_header);
    let codec = CryptoSystemAEADCodec::new(cryptosys, &payload_key, &header_hash, false);

    Ok((codec, chunk_size))
}
