use failure::{ensure, Fallible};
use getopts::Matches;
use std::path::PathBuf;

use crate::commands::KeyPairOutputStreams;
use crate::io_streams::OutputStream;
use crate::WriterFactory;

pub fn get_keypair_streams(
    matches: &Matches,
    open_stdout: WriterFactory,
) -> Fallible<Vec<KeyPairOutputStreams>> {
    ensure!(
        !matches.free.is_empty(),
        "Please provide private key filename(s), or '-' to use stdout"
    );
    Ok(if matches.free == ["-"] {
        vec![KeyPairOutputStreams {
            public_key_stream: None,
            private_key_stream: OutputStream::Stdout { open_stdout },
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
                KeyPairOutputStreams {
                    private_key_stream: OutputStream::File {
                        path: private_key_path,
                    },
                    public_key_stream: Some(OutputStream::File {
                        path: public_key_path,
                    }),
                }
            })
            .collect()
    })
}
