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

    // Credentials
    options
        .optopt(
            "",
            "prompt-passwords",
            "request N password(s) interactively from stdin; any one of them can decrypt the files",
            "N",
        )
        .optmulti(
            "",
            "password-file",
            "read password(s) from the file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "symmetric-key",
            "read 32-byte hex symmetric secret key(s) from the file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "public-key",
            "read public key(s) from the file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "public-key-text",
            "provide public key (64 hex chars) as a command line argument",
            "PUBLIC_KEY",
        )
        .optmulti(
            "",
            "private-key",
            "read private key(s) from the file, one per line",
            "FILENAME",
        );

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
        .optflag(
            "",
            "skip-checksum-check",
            "don't check public keys for validity",
        )
        .optopt(
            "", "threshold", "Number of keys required to decrypt the file", "NUM_KEYS"
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
