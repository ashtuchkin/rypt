use std::convert::TryInto;
use std::mem::size_of;

use failure::{bail, ensure, err_msg, Fallible, ResultExt};
use prost::Message;

use crate::cli::Options;
use crate::crypto::{
    instantiate_crypto_system, AEADAlgorithm, AEADKey, AEADNonce, CryptoSystem, HMacKey, KdfSalt,
    PublicKey, AEAD_NONCE_LEN, KDF_SALT_LEN,
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
const COMPATIBILITY_VERSION: FormatVersion = FormatVersion::BasicEncryption;

/// Create CryptoFamily enum (protobuf) based on command line options.
fn cryptofamily_from_opts(opts: &Options) -> Option<CryptoFamily> {
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

fn recip_secret_key_from_password(
    cryptosys: &CryptoSystem,
    password: &str,
    ephemeral_pk: &PublicKey,
) -> Box<AEADKey> {
    let mut salt: KdfSalt = Default::default();
    salt.copy_from_slice(&cryptosys.hmac(&*ephemeral_pk, KDF_SALT_NONCE)[..KDF_SALT_LEN]);
    cryptosys.key_derivation(&password, &salt)
}

fn recip_secret_key_from_symmetric_key(
    cryptosys: &CryptoSystem,
    symmetric_key: &AEADKey,
    ephemeral_pk: &PublicKey,
) -> Box<AEADKey> {
    let mut composed_key = ephemeral_pk.to_vec();
    composed_key.extend(symmetric_key);
    cryptosys.hmac(&composed_key, SYMMETRIC_SECRET_NONCE)
}

pub fn encrypt_header(opts: &Options) -> Fallible<(Vec<u8>, Box<StreamConverter>, usize)> {
    let version = FormatVersion::BasicEncryption.into();

    let crypto_family = cryptofamily_from_opts(&opts);
    let cryptosys = cryptosys_from_proto(&crypto_family)?;

    let chunk_size = DEFAULT_CHUNK_SIZE;
    ensure!(
        chunk_size <= cryptosys.aead_max_message_size(),
        "Chunk size too large - not supported by the encryption algorithm"
    );

    let payload_key = cryptosys.aead_keygen();
    let (ephemeral_pk, _ephemeral_sk) = cryptosys.generate_keypair();

    // Encrypted header data
    let sender_auth_type = SenderAuthType::Anonymous;
    let sender_pk = PublicKey::default();
    let encrypted_header = EncryptedHeader {
        plaintext_chunk_size: chunk_size as u64,
        sender_auth_type: sender_auth_type.into(),
        sender_pk: sender_pk.to_vec(),
    };

    let encrypted_header_data = cryptosys.aead_encrypt_easy(
        &serialize_proto(encrypted_header)?,
        &payload_key,
        ENCRYPTED_HEADER_NONCE,
    );

    // Recipients: only password or secret key for now.
    let recipient_idx: u32 = 0;
    let recipient_payload = RecipientPayload {
        payload_key: payload_key.to_vec(),
    };
    let mut recipient_nonce: AEADNonce = *RECIPIENT_NONCE;
    recipient_nonce[RECIP_IDX_POS..].copy_from_slice(&recipient_idx.to_le_bytes());

    let recip_secret_key = if let Some(password) = &opts.password {
        recip_secret_key_from_password(&*cryptosys, &password, &ephemeral_pk)
    } else if let Some(secret_key) = &opts.secret_key {
        recip_secret_key_from_symmetric_key(&*cryptosys, &secret_key, &ephemeral_pk)
    } else {
        unimplemented!();
    };

    let encrypted_payload = cryptosys.aead_encrypt_easy(
        &serialize_proto(recipient_payload)?,
        &recip_secret_key,
        &recipient_nonce,
    );

    let recipients = vec![Recipient { encrypted_payload }];

    let header = FileHeader {
        version,
        crypto_family,
        ephemeral_pk: ephemeral_pk.to_vec(),
        recipients,
        encrypted_header_data,
        associated_data: opts.associated_data.clone(),
    };
    let serialized_header = serialize_proto(header)?;
    let header_hash = cryptosys.hash(&serialized_header);

    let codec = CryptoSystemAEADCodec::new(cryptosys, *payload_key, *header_hash, true);

    Ok((serialized_header, codec, chunk_size))
}

pub fn decrypt_header(
    serialized_header: &[u8],
    opts: &Options,
) -> Fallible<(Box<StreamConverter>, usize)> {
    let header: FileHeader = FileHeader::decode(serialized_header)
        .with_context(|e| format!("Invalid header protobuf: {}", e))?;

    ensure!(
        header.version <= COMPATIBILITY_VERSION.into(),
        "Can't decrypt this file - it's too new."
    );

    let cryptosys = cryptosys_from_proto(&header.crypto_family)?;
    let ephemeral_pk: PublicKey = header.ephemeral_pk.as_slice().try_into()?;

    let recip_secret_key = if let Some(password) = &opts.password {
        recip_secret_key_from_password(&*cryptosys, &password, &ephemeral_pk)
    } else if let Some(secret_key) = &opts.secret_key {
        recip_secret_key_from_symmetric_key(&*cryptosys, &secret_key, &ephemeral_pk)
    } else {
        unimplemented!();
    };

    let mut payload_key: Option<AEADKey> = None;
    for (recipient_idx, recipient) in header.recipients.iter().enumerate() {
        // Try to decrypt all recipients.
        let mut recipient_nonce: AEADNonce = *RECIPIENT_NONCE;
        recipient_nonce[RECIP_IDX_POS..].copy_from_slice(&(recipient_idx as u32).to_le_bytes());

        if let Ok(serialized_recipient) = cryptosys.aead_decrypt_easy(
            &recipient.encrypted_payload,
            &recip_secret_key,
            &recipient_nonce,
        ) {
            let recip_payload: RecipientPayload = RecipientPayload::decode(serialized_recipient)
                .with_context(|e| format!("Invalid recipient protobuf: {}", e))?;
            payload_key = Some(recip_payload.payload_key.as_slice().try_into()?);
            break;
        }
    }

    let payload_key = payload_key.ok_or_else(|| err_msg("Invalid credentials"))?;

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
    let codec = CryptoSystemAEADCodec::new(cryptosys, payload_key, *header_hash, false);

    Ok((codec, chunk_size))
}
