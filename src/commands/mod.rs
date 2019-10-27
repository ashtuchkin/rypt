use crate::commands::crypt::crypt_streams;
use crate::commands::gen_keys::generate_key_pair_files;
use crate::commands::help::{print_help, print_version};
use crate::credentials::{ComplexCredential, Credential};
use crate::io_streams::{InputOutputStream, OutputStream};
use crate::ui::UI;
use failure::Fallible;

mod crypt;
mod gen_keys;
mod help;

#[derive(Debug)]
pub enum Command {
    CryptStreams(Vec<InputOutputStream>, CryptOptions, CryptDirectionOpts),
    GenerateKeyPair(GenerateKeyPairOptions),
    Help(OutputStream),
    Version(OutputStream),
}

#[derive(Debug)]
pub struct EncryptOptions {
    pub credential: ComplexCredential,
    pub fast_aead_algorithm: bool,
}

#[derive(Debug)]
pub struct DecryptOptions {
    pub credentials: Vec<Credential>,
}

#[derive(Debug)]
pub enum CryptDirectionOpts {
    Encrypt(EncryptOptions),
    Decrypt(DecryptOptions),
}

#[derive(Debug)]
pub enum InputCleanupPolicy {
    KeepFiles,
    DeleteFiles,
    PromptUser,
}

#[derive(Debug)]
pub struct CryptOptions {
    // Whether we keep or delete input files after successful encryption/decryption.
    pub input_cleanup_policy: InputCleanupPolicy,

    // '-f' flag is given, so we should relax our checks.
    pub force: bool,
}

#[derive(Debug)]
pub struct KeyPairOutputStreams {
    pub public_key_stream: Option<OutputStream>,
    pub private_key_stream: OutputStream,
}

#[derive(Debug)]
pub struct GenerateKeyPairOptions {
    pub streams: Vec<KeyPairOutputStreams>,
    pub force: bool,
}

pub fn run_command(command: Command, ui: &dyn UI) -> Fallible<()> {
    match command {
        Command::CryptStreams(streams, opts, direction) => {
            crypt_streams(streams, &opts, &direction, ui)
        }
        Command::GenerateKeyPair(opts) => generate_key_pair_files(opts, ui),
        Command::Help(output) => print_help(output, ui.program_name()),
        Command::Version(output) => print_version(output),
    }
}
