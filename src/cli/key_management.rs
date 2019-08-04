use failure::{ensure, Fallible};
use getopts::Matches;
use std::path::PathBuf;

use crate::cli::KeyPairPaths;
use crate::io_streams::OutputStream;
use crate::RuntimeEnvironment;

pub fn get_keypair_paths(
    matches: &Matches,
    env: &RuntimeEnvironment,
) -> Fallible<Vec<KeyPairPaths>> {
    ensure!(
        !matches.free.is_empty(),
        "Please provide private key filename(s), or '-' to use stdout"
    );
    Ok(if &matches.free == &["-"] {
        vec![KeyPairPaths {
            private_key_path: OutputStream::Stdout {
                writer: env.stdout.replace(Box::new(std::io::sink())),
            },
            public_key_path: None,
        }]
    } else {
        ensure!(
            matches.free.iter().all(|p| p != "-"),
            "Can't output private key to stdout in when also generating keys to files."
        );
        matches
            .free
            .iter()
            .map(PathBuf::from)
            .map(|private_key_path| {
                let public_key_path = private_key_path.with_extension("pub");
                KeyPairPaths {
                    private_key_path: OutputStream::File {
                        path: private_key_path,
                    },
                    public_key_path: Some(public_key_path),
                }
            })
            .collect()
    })
}
