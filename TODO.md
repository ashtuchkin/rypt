# P0
 * Cleanup README, INTERNALS, TODO, header.proto, header.rs to prepare for publishing
   * Explain file mode/stream mode
   * Add gifs that show how command works
   * Add info about composite keys to INTERNALS
   * Crypto details, performance, usage, arguments.
   * "Access Structure"
 * Set up basic packaging, see nice overview here https://rust-lang-nursery.github.io/cli-wg/tutorial/packaging.html
   https://github.com/japaric/trust
 * Cleanup cargo.toml and publish to cargo.
 * Publish to /r/rust, hacker news.
 
# P1
 * Allow giving explicit output file name(s) on command line. Plus, maybe, different output folder. 
 * Handle panics gracefully, redirecting users to report bugs.
 * Weak password warning, using zxcvbn. Can be reentered by pressing 'Enter' on password verify.
 * Add CLI commands to set and show non-encrypted authenticated data, with or without password.
   * Potentially ask for password after reading header, to show password hint.
 * Add CLI commands to extract and use key parts, to avoid sharing private key when using Shamir.
 * Print Access Structure and additional algorithm details on encryption with -v flag.
 * Progress should show "Elapsed" when the file is finished (ETA is irrelevant there).
 * Progress should be shown for the whole operation (estimate total size) - requires InputStream creators to read 
   metadata (which might be a good thing anyway)
 * Sender signature and repudiable verification
 * Copy attributes from the replaced file (owner, group, perms, access/mod times)
 * Harden against information leaks:
   * Avoid leaking information about file length by adding random padding, likely in the beginning. ~1 kb to 1 mb or 3%
   * Pad encrypted header to 1kb?
 * Review how we keep secret keys in memory and clean it up (see sodium_mlock/sodium_munlock and sodium_memzero)
   * E.g. maybe use crypto_aead_aes256gcm_beforenm to create state from key and then forget it?
     https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm/aes-gcm_with_precomputation
 * Review error messages to be precise about what really happened (i.e. include file name).
 * Add benchmarking
 * Use MUSL for wider linux support

# P2
 * Write a blog post about pipelining and compare it to a naive serial solution.
 * Adjustable chunk size (via command line args)
 * Initially write to an invisible tempfile in the same directory (using either tempfile crate or O_TMPFILE), then
   atomically make it visible.
 * Check for entropy in the beginning and add warning (see https://libsodium.gitbook.io/doc/usage#sodium_init-stalling-on-linux)
 * Support progress bar on Windows earlier than 10 (see comment in terminal.rs)
 * Support generating several private keys to stdout
 
# Undecided / maybe
 * CLI: Add color.
 * Private keys format:
   * Include a way to password-protect?
   * Remove or separate the public key?
   * Maybe use BIP39 Mnemonic phrase as the private key. See https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki       
     * This includes the password protection. We'd need to store public key too in that case (otherwise it'll require
       a password when encrypting and no way to check it).
     * We can also choose the strength: 128-256 bits using 12-24 words.
     * Requires wordlist, bit writer, pbkdf2 with hmac-sha512 (not included in libsodium)
     * https://github.com/maciejhirsz/tiny-bip39  (See https://github.com/infincia/bip39-rs/issues/21)
 * Support folder encryption natively
 * Multithreaded encryption - possible now, but not sure if needed.
 * Migrate to async reading/writing and futures, plus write a post about that too.
 * Switch to a different Protobuf library which supports Zero-copy mode, to allow larger authenticated data
   (see https://github.com/danburkert/prost/issues/134).
 * Implement passing password via environment variable?: maybe not password, but private key & params.
    * This does not work for decrypt - needs params from the files.
    * Need to do something like ssh-agent? 
 * Support detached authenticated data (stored somewhere else).
 * Adjustable file flush timeout / size (via command line args).
 * Supporting repudiable mode with several recipients will require an encrypted tag per recipient for every
   chunk. We'll need to extend format for that.
   (will need payload key; ephemeral public key; encrypted sender public key; authentication tag will be encrypted
    with session key generated from (sender, recipient) tuple - we want to authenticate every chunk)
 * Supporting also signed mode (signcryption) - requires similar fields as above. No need for per-recipient tag for
   every chunk. http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html
   Encrypt -> Sign; Encryption should include Sender's public key in plaintext. We probably can sign just the AEAD tag
   (this would reduce the message size to 128 bit), but in that case additional auth data must include header hash.
   Signcryption only makes sense if the recipient password/public key is shared; in this case any recipient that owns
   a shared key can create a repudiable/anonymous message like it's from the sender. In this case authentication becomes
   meaningless, only signing the message makes sense.

# Code improvement
 * Support "warnings" (e.g. when skipping file) and exit with exit code = 2 if any. 

 * Make BasicUI more testable by supplying `set_stdin_echo` from RuntimeEnvironment.
      
 * Maybe Rename Writer -> OwnedWrite?

 * In get_input_output_streams, try to get metadata for both input and output files to check their existence/filesize/any errors. 
 
 * Introduce EncryptionProfile, as an interface between header processing and data encryption pipeline. 
   Include crypto system, payload key, header hash, chunk size?; Separately SignatureProfile. Macs, signature private key.
 * Rename header.rs to something more appropriate (credentials?)
 * Unit Tests!
 * Move add_extension and remove_extension to utils and use them in tests and key generation.
 * Avoid switching on the algorithm in LibSodiumCryptoSystem - do it once.
 * Investigate why build-time deps like 'tar' are getting into release build through libsodium-sys
   https://github.com/sodiumoxide/sodiumoxide/blob/master/libsodium-sys/Cargo.toml