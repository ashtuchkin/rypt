use failure::{ensure, err_msg, Fallible};
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
    let mut open_stdout_opt = Some(open_stdout);
    let mut result = vec![];
    for path in &matches.free {
        let private_key_path = PathBuf::from(path);
        if private_key_path.to_str() == Some("-") {
            let open_stdout = open_stdout_opt
                .take()
                .ok_or_else(|| err_msg("Can't output two or more private keys to stdout."))?;

            result.push(KeyPairOutputStreams {
                public_key_stream: None,
                private_key_stream: OutputStream::Stdout { open_stdout },
            });
        } else {
            let public_key_path = private_key_path.with_extension("pub");
            result.push(KeyPairOutputStreams {
                private_key_stream: OutputStream::File {
                    path: private_key_path,
                },
                public_key_stream: Some(OutputStream::File {
                    path: public_key_path,
                }),
            });
        }
    }
    Ok(result)
}
