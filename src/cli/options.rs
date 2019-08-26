use crate::cli::credentials::define_credential_options;
use crate::cli::DEFAULT_FILE_SUFFIX;
use getopts::Options;

pub fn define_options() -> Options {
    let mut options = Options::new();

    // Modes / subcommands
    options
        .optflag("e", "encrypt", "encrypt files (default)")
        .optflag("d", "decrypt", "decrypt files")
        .optflag("g", "generate-keypair", "generate public/private key pair")
        .optflag("h", "help", "display this short help")
        .optflag("V", "version", "display version");

    // Common flags
    options
        .optflagmulti(
            "v",
            "verbose",
            "be verbose; specify twice for even more verbosity",
        )
        .optflagmulti("q", "quiet", "be quiet; skip unnecessary messages");

    // Credential options
    options = define_credential_options(options);

    // Encryption/decryption flags
    options
        .optflag(
            "",
            "fast",
            "use a different encryption algorithm (AES256-GCM) that is faster, but supported only on newer x86 processors",
        )
        .optflag(
            "k",
            "keep-input-files",
            "don't delete original files on successful operation",
        )
        .optflag(
            "",
            "delete-input-files",
            "delete original files on successful operation",
        )
        .optflag(
            "s",
            "stdout",
            "write to standard output",
        )
        .optopt(
            "S",
            "suffix",
            &format!(
                "encrypted file suffix, defaults to \".{}\"",
                DEFAULT_FILE_SUFFIX
            ),
            ".suf",
        );
    options
}
