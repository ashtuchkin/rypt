use failure::{Fallible, ResultExt};
use std::io::Write;

use crate::cli::{BasicUI, KeyPairOutputStreams};
use crate::{crypto, util};

pub fn generate_key_pair_files(streams: Vec<KeyPairOutputStreams>, ui: &BasicUI) -> Fallible<()> {
    let cryptosys = crypto::instantiate_crypto_system(Default::default())?;
    let total_num = streams.len();
    for (file_idx, streams) in streams.into_iter().enumerate() {
        let KeyPairOutputStreams {
            public_key_stream,
            private_key_stream,
        } = streams;
        let (public_key, private_key) = cryptosys.generate_keypair();
        let mut public_key_hex = util::to_hex_string_checksummed(*public_key);
        let mut private_key_hex = util::to_hex_string(&*private_key as &[u8]);

        // Add carriage return to make it easier to concat several public/private key files
        public_key_hex.push('\n');
        private_key_hex.push('\n');

        // Print verbose message if needed
        let private_key_path = private_key_stream.path().to_string_lossy().to_string();
        let public_key_path = public_key_stream
            .as_ref()
            .map(|s| s.path().to_string_lossy().to_string());

        if ui.will_print(1) {
            let s = [
                format!("Generating keypair [{}/{}]:\n", file_idx + 1, total_num),
                format!("    Public key: {}\n", public_key_hex.trim()),
                public_key_path
                    .as_ref()
                    .map(|path| format!("    Public key file:  {}\n", path))
                    .unwrap_or_default(),
                format!("    Private key file: {}\n\n", private_key_path),
            ]
            .concat();
            ui.print(1, s)?;
        }

        // Write private key
        private_key_stream
            .open()?
            .write_all(private_key_hex.as_bytes())
            .with_context(|e| format!("{}: {}", private_key_path, e))?;

        // Write public key if needed
        if let Some(public_key_stream) = public_key_stream {
            public_key_stream
                .open()?
                .write_all(public_key_hex.as_bytes())
                .with_context(|e| format!("{}: {}", public_key_path.unwrap(), e))?;
        }
    }
    Ok(())
}
