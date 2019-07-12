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
 
# P1
 * Add external authenticated data + ability to get it, with or without password.
 * Review how we keep secret keys in memory and clean it up (see sodium_mlock/sodium_munlock and sodium_memzero)
   * E.g. maybe use crypto_aead_aes256gcm_beforenm to create state from key and then forget it?
     https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm/aes-gcm_with_precomputation
 * Review error messages to be precise about what really happened (i.e. include file name).
 * Create functionality to see all supported algorithms and whether they are available in hardware
   (use registry and crypto_aead_aes256gcm_is_available)  
 * Add benchmarking

# P2
 * Write a blog post about pipelining and compare it to a naive serial solution.
 * Adjustable chunk size (via command line args)
 * Check for entropy and add warning (see https://libsodium.gitbook.io/doc/usage#sodium_init-stalling-on-linux)
 * Support multithreading for supporting encoders (might be hard to share the state).
 * Migrate to async reading/writing and futures, plus write a post about that too.
 
# Undecided / maybe
 * Initially write to an invisible tempfile in the same directory (using either tempfile crate or O_TMPFILE), then
   atomically make it visible.
 * Switch to a different Protobuf library which supports Zero-copy mode, to allow larger authenticated data
   (see https://github.com/danburkert/prost/issues/134).
 * Implement passing password via environment variable?: maybe not password, but private key & params.
    * This does not work for decrypt - needs params from the files.
    * Need to do something like ssh-agent? 
 * Support detached authenticated data (stored somewhere else).
 * Adjustable file flush timeout / size (via command line args). 
