use failure::{Fallible, ResultExt};
use std::io::Write;

use crate::commands::KeyPairOutputStreams;
use crate::crypto::{PRIVATE_KEY_LEN, PUBLIC_KEY_LEN};
use crate::errors::CompositeError;
use crate::ui::UI;
use crate::{crypto, util};

pub fn generate_key_pair_files(streams: Vec<KeyPairOutputStreams>, ui: &dyn UI) -> Fallible<()> {
    let cryptosys = crypto::instantiate_crypto_system(Default::default())?;
    let total_num = streams.len();
    let mut errors = vec![];

    for (file_idx, streams) in streams.into_iter().enumerate() {
        let KeyPairOutputStreams {
            public_key_stream,
            private_key_stream,
        } = streams;

        // Generate the key pair
        // We use hex encoding for both public and private keys. "\n" is added to make it easier to
        // concat several public/private key files.
        // For public keys, we additionally use checksumming via lowercase/uppercase hex letters
        // to provide some feedback about invalid key.
        // For private keys, we use the fact that they include public keys as the second half.
        // To make it convenient to manually extract public key from private, we checksum private
        // and public parts separately. After that, users can use the second half (last 64
        // characters) of the private key directly as a public key.
        let (public_key, private_key) = cryptosys.generate_keypair();

        // Ensure private key really includes public key at the end.
        let (real_private_key, public_part_of_private_key) =
            private_key.split_at(PRIVATE_KEY_LEN - PUBLIC_KEY_LEN);
        assert_eq!(&*public_key, public_part_of_private_key);

        let public_key = util::to_hex_string_checksummed(*public_key) + "\n";
        let private_key = util::to_hex_string_checksummed(real_private_key) + &public_key;

        // Get the paths before opening the streams
        let private_key_path = private_key_stream.path().to_string_lossy().to_string();
        let public_key_path = public_key_stream
            .as_ref()
            .map(|s| s.path().to_string_lossy().to_string())
            .unwrap_or_default();

        // Print the header
        ui.println(0, &format!("Keypair {}/{}:", file_idx + 1, total_num))?;
        ui.println(0, &format!("    Public key: {}", public_key.trim()))?;

        let res = (|| -> Fallible<()> {
            // Write the public key, if required
            if let Some(public_key_stream) = public_key_stream {
                ui.println(0, &format!("    Public key file: {}", public_key_path))?;
                public_key_stream
                    .open()?
                    .write_all(public_key.as_bytes())
                    .with_context(|e| format!("Error writing to '{}': {}", public_key_path, e))?;
            }

            // Write the private key
            ui.println(0, &format!("    Private key file: {}", private_key_path))?;
            private_key_stream
                .open()?
                .write_all(private_key.as_bytes())
                .with_context(|e| format!("Error writing to '{}': {}", private_key_path, e))?;
            Ok(())
        })();

        // If we can't write one of the files, report the error and continue.
        if let Err(err) = res {
            ui.print_error(&err)?;
            errors.push(err);
        }
        ui.println(0, "")?;
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(CompositeError { errors }.into())
    }
}
