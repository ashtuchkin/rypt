use failure::{Fallible, ResultExt};

use crate::cli::KeyPairPaths;
use crate::{crypto, util, Writer};

pub fn generate_key_pair_files(
    paths: Vec<KeyPairPaths>,
    verbose: i32,
    stderr: &mut Writer,
) -> Fallible<()> {
    let cryptosys = crypto::instantiate_crypto_system(Default::default())?;
    let total_num = paths.len();
    for (file_idx, paths) in paths.into_iter().enumerate() {
        let KeyPairPaths {
            public_key_path,
            private_key_path,
        } = paths;
        let (public_key, private_key) = cryptosys.generate_keypair();
        let mut public_key_hex = util::to_hex_string_checksummed(*public_key);
        let mut private_key_hex = util::to_hex_string(&*private_key as &[u8]);

        // Add carriage return to make it easier to concat several public/private key files
        public_key_hex.push('\n');
        private_key_hex.push('\n');

        // Print verbose message if needed
        let private_key_path_str = private_key_path.path().to_string_lossy().into_owned();
        if verbose > 0 {
            writeln!(
                stderr,
                "Generating keypair [{}/{}]:",
                file_idx + 1,
                total_num
            )?;
            writeln!(stderr, "    Public key: {}", public_key_hex.trim())?;
            if let Some(public_key_path) = &public_key_path {
                let public_key_path_str = public_key_path.to_string_lossy();
                writeln!(stderr, "    Public key file:  {}", public_key_path_str)?;
            }
            writeln!(stderr, "    Private key file: {}", private_key_path_str)?;
            writeln!(stderr)?;
        }

        // Write private key
        private_key_path
            .open()?
            .write_all(private_key_hex.as_bytes())
            .with_context(|e| format!("{}: {}", private_key_path_str, e))?;

        // Write public key if needed
        if let Some(public_key_path) = &public_key_path {
            let public_key_path_str = public_key_path.to_string_lossy();
            std::fs::write(public_key_path, public_key_hex)
                .with_context(|e| format!("{}: {}", public_key_path_str, e))?;
        }
    }
    Ok(())
}
