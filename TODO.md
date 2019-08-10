# P0
 * CLI: Ask to delete files at the end
   * Only if terminal attached; otherwise don't delete
   * Command line flags to skip the question: -k, --keep-original-files; -r, --remove-original-files
 * CLI: Add ability to create complex key schemes (major selling point)
 * CLI: Create consistent verbose/quiet rules
   * Default to rather verbose if in terminal; further verbose should print details of algorithms, etc
 * CLI: Polish help and messages
   * Explain file mode/stream mode
 * CLI: Exit code should signify error if at least one file fails.
 * CLI: Don't accept empty password.
 * Finalize 'version' field handling
 * Review header size limitation
 * Check carefully decoding path, with the assumption that attacker changes it.
   * Assert all decoded payload keys are same 
 * Input/output file management:
    *   copy attributes from the replaced file (owner, group, perms, access/mod times)
    * Warning and skip if: symlink, non-file, multiple hardlinks
    * '-f' - overwrite the destination file
 * Tests
    * Review the code and cover most sensitive areas.
    * Test password handling
    * If target file already exists, error and skip.
    * delete the output file on error or if interrupted (ctrl-c)
    * warning and skip if already has extension, doesn't have supported ext
    * '-k, --keep' - keep the original file
    * '-c, --stdout, --to-stdout' - write to stdout; implies -k
 * Cleanup README, INTERNALS, TODO, header.proto, header.rs to prepare for publishing
   * Explain file mode/stream mode
   * Add gifs that show how command works
   * Add info about composite keys to INTERNALS
   * Crypto details, performance, usage, arguments.
 * Set up basic packaging, see nice overview here https://rust-lang-nursery.github.io/cli-wg/tutorial/packaging.html
   https://github.com/japaric/trust
 * Publish to /r/rust, hacker news.
 
# P1
 * Show whether AES256 is supported on this platform in --version command.
 * Handle panics gracefully, redirecting users to report bugs.
 * Weak password warning, using zxcvbn. Can be reentered by pressing 'Enter' on password verify.
 * Add CLI commands to set and show non-encrypted authenticated data, with or without password.
   * Potentially ask for password after reading header, to show password hint.
 * Add CLI commands to extract and use key parts, to avoid sharing private key when using Shamir.
 * Progress should be shown for the whole operation (estimate total size) - requires InputStream creators to read 
   metadata (which might be a good thing anyway)
 * Sender signature and repudiable verification
 * Harden against information leaks:
   * Version might be tricky - it leaks potentially secret info about file. 
   * Avoid leaking information about file length by adding random padding, likely in the beginning. ~1 kb to 1 mb or 3%
   * Randomize chunk length
   * Pad encrypted header to 1kb?
 * Review how we keep secret keys in memory and clean it up (see sodium_mlock/sodium_munlock and sodium_memzero)
   * E.g. maybe use crypto_aead_aes256gcm_beforenm to create state from key and then forget it?
     https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm/aes-gcm_with_precomputation
 * Review error messages to be precise about what really happened (i.e. include file name).
 * Add benchmarking
 * Use MUSL for wider linux support
 * Add Windows support

# P2
 * Write a blog post about pipelining and compare it to a naive serial solution.
 * Adjustable chunk size (via command line args)
 * Initially write to an invisible tempfile in the same directory (using either tempfile crate or O_TMPFILE), then
   atomically make it visible.
 * Check for entropy in the beginning and add warning (see https://libsodium.gitbook.io/doc/usage#sodium_init-stalling-on-linux)
 
# Undecided / maybe
 * CLI: Add color.
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
 * Consume RuntimeEnvironment in command line parsing, only provide streams in Command struct
 * main.rs should not print error msgs, only status codes
 * Introduce EncryptionProfile, as an interface between header processing and data encryption pipeline. 
   Include crypto system, payload key, header hash, chunk size?; Separately SignatureProfile. Macs, signature private key.
 * Convert InputOutputStream to tuple (InputStream, OutputStream)
 * Have stderr & verbose as a single concept to pass around, maybe logging?
 * Move cleanup functions to InputStream/OutputStream and then apply them both.
 * Rename header.rs to something more appropriate (credentials?)
 * Unit Tests!
 * Kill types.rs and move its contents probably to stream_pipeline
 * Move add_extension and remove_extension to utils and use them in tests and key generation.
 * Avoid switching on the algorithm in LibSodiumCryptoSystem - do it once.
 * Investigate why build-time deps like 'tar' are getting into release build through libsodium-sys
   https://github.com/sodiumoxide/sodiumoxide/blob/master/libsodium-sys/Cargo.toml