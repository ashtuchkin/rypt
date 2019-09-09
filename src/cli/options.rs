use crate::cli::DEFAULT_FILE_SUFFIX;
use getopts::Options;

// Modes of operation / subcommands
pub fn define_mode_options(options: &mut Options) {
    options
        .optflag("e", "encrypt", "encrypt files (default)")
        .optflag("d", "decrypt", "decrypt files")
        .optflag("g", "gen-keypair", "generate public/private key pair(s)")
        .optflag("h", "help", "display this short help")
        .optflag("V", "version", "display version");
}

// Common flags
pub fn define_common_options(options: &mut Options) {
    options
        .optflagmulti(
            "v",
            "verbose",
            "be more verbose; specify twice for even more verbosity",
        )
        .optflagmulti(
            "q",
            "quiet",
            "suppress messages and warnings; specify twice to skip error messages as well",
        )
        .optflag(
            "f",
            "force",
            "make sanity checks warnings instead of errors",
        );
}

// Encryption/decryption flags
pub fn define_crypt_options(options: &mut Options) {
    options
        .optflag(
            "",
            "fast",
            "use a faster encryption algorithm that is only supported on newer x86 processors (AES256-GCM)",
        )
        .optflag(
            "K",
            "keep-inputs",
            "keep original files on successful operation (specify to avoid prompt at the end)",
        )
        .optflag(
            "D",
            "discard-inputs",
            "delete original files on successful operation",
        )
        .optflag(
            "s",
            "stream",
            "streaming mode: single stream, non-file inputs allowed, writes to standard output; \
             enabled by default if no inputs or '-' is specified",
        )
        .optopt(
            "S",
            "suffix",
            &format!(
                "encrypted files suffix; default is \".{}\"",
                DEFAULT_FILE_SUFFIX
            ),
            "SUFFIX",
        );
}

// Credentials
pub fn define_credential_options(options: &mut Options) {
    options
        .optflagmulti(
            "p",
            "password",
            "prompt for one password interactively; specify several times for multiple passwords; \
             default if no other credentials provided",
        )
        .optmulti(
            "",
            "password-named",
            "prompt for a password identified by name (e.g. 'Master password'); name is only used \
             for prompt, not saved",
            "PASSWORD_NAME",
        )
        .optmulti(
            "",
            "password-file",
            "read password(s) from a file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "public-key",
            "(encryption only) read public key(s) from a file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "public-key-text",
            "(encryption only) read public key directly as a command line argument",
            "PUBLIC_KEY",
        )
        .optmulti(
            "",
            "private-key",
            "(decryption only) read private key(s) from a file, one per line",
            "FILENAME",
        )
        .optmulti(
            "",
            "symmetric-key",
            "(advanced) read 32-byte hex symmetric secret key(s) from a file, one per line",
            "FILENAME",
        );
}

// Credential combinators
pub fn define_credential_combinator_options(options: &mut Options) {
    options
        .optmulti(
            "t",
            "key-threshold",
            "number of keys/passwords required to decrypt the file or the current group; default is 1",
            "NUM_KEYS",
        )
        .optflagmulti(
            "a",
            "require-all-keys",
            "require all keys to decrypt the file or the current group",
        )
        .optmulti(
            "",
            "key-shares",
            "(very advanced) number of key shares provided by the following key; default is 1",
            "NUM_SHARES",
        )
        .optflagmulti("(", "start-group", "start a group of keys")
        .optflagmulti(")", "end-group", "end a group of keys");
}

pub fn define_all_options() -> Options {
    let mut opts = Options::new();
    define_mode_options(&mut opts);
    define_common_options(&mut opts);
    define_crypt_options(&mut opts);
    define_credential_options(&mut opts);
    define_credential_combinator_options(&mut opts);
    opts
}
