use crate::cli::options::{
    define_common_options, define_credential_combinator_options, define_credential_options,
    define_crypt_options, define_mode_options,
};
use crate::crypto::LibSodiumCryptoSystem;
use crate::io_streams::OutputStream;
use crate::{PKG_NAME, PKG_VERSION};
use failure::Fallible;
use getopts::Options;

fn opt_usage(define_options: impl Fn(&mut Options)) -> String {
    let mut opts = Options::new();
    define_options(&mut opts);
    opts.usage_with_format(|opts| opts.collect::<Vec<_>>().join("\n"))
}

pub fn print_help(output: OutputStream, program_name: &str) -> Fallible<()> {
    let mut stdout = output.open()?;
    writeln!(
        stdout,
        "\
Usage: {program_name} [OPTION].. [FILE]..
Encrypt/decrypt FILE-s using passwords and/or public keys. 

Commands (use one):
{command_opts}

Common flags:
{common_opts}

Encryption/decryption options:
{crypt_opts}

Credentials:
{credential_opts}

Credential combinators (encryption only, advanced):
{credential_combinator_opts}

With no FILE, or when FILE is '-', read standard input. Use '-s' to write to standard output.

Home page and documentation: <https://github.com/ashtuchkin/rypt>",
        program_name = program_name,
        command_opts = opt_usage(define_mode_options),
        common_opts = opt_usage(define_common_options),
        crypt_opts = opt_usage(define_crypt_options),
        credential_opts = opt_usage(define_credential_options),
        credential_combinator_opts = opt_usage(define_credential_combinator_options)
    )?;
    Ok(())
}

pub fn print_version(output: OutputStream) -> Fallible<()> {
    let mut stdout = output.open()?;
    writeln!(stdout, "{} {}", PKG_NAME, PKG_VERSION)?;
    writeln!(stdout, "libsodium {}", LibSodiumCryptoSystem::version())?;
    Ok(())
}
