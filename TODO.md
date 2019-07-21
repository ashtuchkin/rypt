# P0
 * Read password from stdin
    * Twice for encrypt, once for decrypt
 * Add Argon as a key derivation function crypto_pwhash_argon2id
 * Support Public Key derivation:
    * Command line arguments providing receiver public key (required) and my private key (optional)
       * Plus, a command line mode to generate private/public key pair.
    * Encryption: 
       * If only receiver public key given, use 'seal' construct, else regular box construct.
       * If using regular box construct, store sender's public key unless `--no-store-my-public-key` is given. 
    * Decryption:
       * Just my private key is required, unless we skipped storing sender public key.
 * Review our nonce extension algorithm vs crypto_core_hchacha20 https://libsodium.gitbook.io/doc/key_derivation#nonce-extension
 * Cleanup AES256 algorithm nonce stuff - it's too complicated and unsafe.
 * Add finalization to AES256GCM - otherwise attacker can truncate the file and get a correct output.
 * Adjust XChaCha20Poly1305 chunks to be 8-bytes aligned.
 * Finalize basic command line usage: '-e, --encrypt', '-d, decrypt' 
    * If encrypt/decrypt successful, replace file 
    *   copy attributes from the replaced file (owner, group, perms, access/mod times)
    * If target file already exists, error and skip.
    * Warning and skip if: symlink; already has extension, doesn't have supported ext
    * delete the output file on error or if interrupted (ctrl-c)
    * '-k, --keep' - keep the original file
    * '-f' - overwrite the destination file
    * '-c, --stdout, --to-stdout' - write to stdout; implies -k
 * Errors: tell which chunk failed.
 * Create a readme
 * Publish to /r/rust, hacker news.
 * Review how OpenGPG allows several ways to decrypt, including both several public key recipients and a password
   https://security.stackexchange.com/a/162001
 * Review OpenGPG public/private key formats https://tools.ietf.org/html/rfc4880#section-5.5
   Or, maybe PEM/DER format (PEM = base64 DER + ---BEGIN CERTIFICATE----); ASN.1
   https://docs.rs/simple_asn1/0.4.0/simple_asn1/
 * Review public/private key infrastructure compatibility with other systems (PGP, Keybase)
   * Keybase has its own payload format: saltpack https://saltpack.org/encryption-format-v2
 
# P1
 * Add external authenticated data + ability to get it, with or without password.
 * Review how we keep secret keys in memory and clean it up (see sodium_mlock/sodium_munlock and sodium_memzero)
   * E.g. maybe use crypto_aead_aes256gcm_beforenm to create state from key and then forget it?
     https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm/aes-gcm_with_precomputation
 * Review error messages to be precise about what really happened (i.e. include file name).
 * Create functionality to see all supported algorithms and whether they are available in hardware
   (use registry and crypto_aead_aes256gcm_is_available)  
 * Add benchmarking
 * Use MUSL for wider linux support
 * Add Windows support
 * Extend README.md: Crypto details, performance, usage, arguments. 

# P2
 * Write a blog post about pipelining and compare it to a naive serial solution.
 * Adjustable chunk size (via command line args)
 * Initially write to an invisible tempfile in the same directory (using either tempfile crate or O_TMPFILE), then
   atomically make it visible.
 * Check for entropy in the beginning and add warning (see https://libsodium.gitbook.io/doc/usage#sodium_init-stalling-on-linux)
 * Support multithreading for supporting encoders (might be hard to share the state).
 * Migrate to async reading/writing and futures, plus write a post about that too.
 
# Undecided / maybe
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
   
