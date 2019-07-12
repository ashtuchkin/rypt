# Command line ergonomics
 * Regular file(s):
   `rypt <file> <file> <file>`   # Encrypt files, will ask for password twice, then write encrypted files with .rypt extension.
   `rypt -d <file> <file>`       # Decrypt files, will ask for password once, remove .rypt extension.
   * Input: 
     * Regular files, no hardlinks (checking metadata.nlink == 1; std::os::unix::fs::MetadataExt)
      * By default writes a sibling file with the same name + suffix.
      * Copies the same user/group, permissions, modified timestamps. 
      * ?? removes original file on success (Question: wipe the file?; Question: ask user to delete it?; Question: only after all files been encoded?); 
      * removes new file on failure.
   * Skips all the other filetypes (folders, symlinks, char/block devices, sockets), with reference to pipe mode.
 * Pipe mode (-S):
   * Only one input is allowed. Output is always to stdout.
   * Input: stdin ("-"), files, named pipes (fifo/process substitution), char devices, potentially through symlinks.
   * Default if stdin is the input (or no files provided).
   * Bail if input or stdout are terminals.
   * Bail if stdin input requested + password interactive mode
 * Ways to provide password/key:
   * Secret key directly: --secret-key-file=filename  (file must contain 32 bytes binary key)
   * Password: 1) interactive mode via stdin/stdout, 2) -P, --password-file=filename
   * Private key / Public key: --recipient-public-key=filename, --my-private-key=filename; 
     --sender-public-key=filename (on decryption)
 * Encrypt a folder and other creative pipe usages:
   `tar c <folder> | xz | rypt -P password.txt | aws s3 cp - s3://mybucket/archive.xz.rypt`
   `rypt -S <(tar c . | xz) > archive.xz.rypt`  # will ask password interactively
 * User authenticated data:
   * Only one file supported, or pipe mode.
   * `rypt --public-data="ABC" input_file`  - Include public info string to the file when encrypting
   * `rypt --public-data-file=public_file.txt input_file`  - Include public info file contents to the file when encrypting
   
   * `rypt --get-public-data input_file.rypt`  - print public info data to stdout (requires password/secret key)
   * `rypt --get-public-data-unauthenticated input_file.rypt`  - print public info data to stdout (no password, unchecked)
   * `rypt -d -v input_file.rypt` - will print first line (80 chars) of public data when decoding, if it's not binary.
   
 * BAD IDEA: Provide password/private key through the env variables:
   * Command asks for password and runs provided program / pipe with given password in environment variable.
   * env vars do leak private key and seed (i.e. files can be decoded), but don't leak the password.
   * Note you can see all env vars of the processes you own (and only you) in `/proc/<pid>/environ` (https://security.stackexchange.com/a/14009)
   `rypt-pass -- tar cf output.tar.rypt --use-compress-program rypt <folder> `
 * No need for env var support: "--password-file=<(echo $ABC)" would do. 
   Same for command line arg: "--password-file=<(echo password)"; it will also not show up in htop.


# File structure

| Item                                             | Size         |
|--------------------------------------------------|--------------| 
| File signature: ASCII 'rypt'                     | 4 bytes      |
| Header length, little-endian uint32              | 4 bytes      |
| Header protobuf                                  | header len   |
| N x Ciphertext chunk, aligned to 8 bytes         | (chunk_size + asize); last one may be smaller |

Chunks are provided as-is to the encoding/decoding algorithms.

# Authentication
 * Everything from the beginning of the file up to the first chunk data.
 * If user authenticated data is detached, replace it with the length and contents, just like if it's not detached.
 * If AEAD algorithm does not provide a built-in way to tag the final chunk, an additional rule is used:
   * Append 1 byte tag to the end of the authenticated data with the value of 0 if the chunk not final, 1 if final.
   * If resulting value is a single byte 0 (i.e. no original authentication data and the chunk is not final), then 
     replace it with empty authentication data (for performance).
   * This would fail the last chunk authentication if the file is truncated.
   ----
   * Alternative: Use Nonce: for final chunk, set highest bit of message counter.
 

# Algorithm-specific changes from libsodium
 * XChacha20Poly1305 adds 7 bytes random prefix to align ciphertext and plaintext blocks. Final chunk has TAG_FINAL.
 * AES256-GCM stores it's nonce in encryption header. Changes:
    * It uses nonce extension to 192 bit, using 
        https://libsodium.gitbook.io/doc/key_derivation#nonce-extension
        (per_chunk_private_key || per_chunk_nonce) = SHA512(original private key || extended nonce || message #).
      In this case encryption header is 192 bit (24 bytes) and a random value can be comfortably used. 
      This extension can be disabled in header protobuf for compatibility.
    * As the algorithm does not provided built-in tagging for final chunk, use the algorithm described above. 

https://crypto.stackexchange.com/questions/53104/is-it-safe-to-store-both-the-aes-related-data-and-the-pbkdf2-related-data-excep?rq=1

# Public key algorithms
Core algorithms: 
  * Key exchange: X25519 (ECDH over Curve25519, see https://libsodium.gitbook.io/doc/advanced/scalar_multiplication)
    * Private key: random 32 bytes; (or crypto_hash_sha512 of seed)
    * Public key: 32 bytes, calculated as `crypto_scalarmult_curve25519_base(private_key)`
    * Shared secret: 32 bytes, `crypto_scalarmult_curve25519(pk, sk)`. For security it's recommended to hash it (see below)
  
Libsodium recommended algorithms:
  * Authenticated encryption (crypto_box_easy):
        K = crypto_core_hchacha20(crypto_scalarmult_curve25519(pk, sk))  (beforenm)
        crypto_secretbox_xsalsa20poly1305(K)  (afternm) or crypto_secretbox_xchacha20poly1305_detached (mac prepended)
    
  * Sealed boxes (crypto_box_seal):
        Generate pk1, sk1 using crypto_box_keypair
        nonce = crypto_generichash(pk1 || pk)   (BLAKE2b)  - avoid storing nonce explicitly.
        c = pk1 || crypto_box_easy(msg, pk, sk1, nonce)
        
  * Session key exchange (crypto_kx_client_session_keys):
        rx || tx = BLAKE2B-512(crypto_scalarmult_curve25519(client_sk, server_pk) || client_pk || server_pk)

Questions and decisions:
  * For 'sealed box' operation, do we use 1) `crypto_box_seal` for each chunk, or 2) key exchange algorithm to create 
    secret key, then any regular AEAD algorithm?
    * PRO `crypto_box_seal`: libsodium-recommended and a bit more compatible with other programs using libsodium.
    * PRO key exchange + AEAD: Don't need to store per-chunk public keys; faster; supports authenticated data; can use
      other algorithms like AES256-GCM; much more shared code with password-based encryption; we can keep the same 
      structure and just use public keys as a key derivation algorithm.
    Decision: 2) Use key exchange + regular AEAD algorithm.

  * For 'authenticated encryption' operation, use 1) `crypto_box_curve25519xchacha20poly1305_easy_afternm`, 2) 
    key exchange with `crypto_secretstream_*`, or 3) key exchange with any regular AEAD algorithm?
    * PROs/CONs - same as above. 
    * Decision: 3) Key exchange + regular AEAD algorithm.
    
  * For key exchange, use 1) KX interface like `crypto_kx_client_session_keys` or 2) implement `crypto_box_easy` algorithm
    (`crypto_core_hchacha20(crypto_scalarmult(pk, sk))`, or call `crypto_box_curve25519xsalsa20poly1305_beforenm`)
    * PRO 1): easy to use; recommended by libsodium; does not rely on internals.
    * CON 1): session keys are different than what we're trying to do here.
    * PRO 2): marginally faster.
    Decision: 1) Use `crypto_kx_client_session_keys`/`crypto_kx_server_session_keys`
  
  * When sender provides private key when encrypting, do we store corresponding public key in the file? 1) No, 2) Yes
    * PRO 1) don't store: increased privacy for sender.
    * PRO 2) store: Easy to check who encrypted this file, like a "From" field; when decrypting, receiver's private key 
      is enough - no need to supply sender's public key.
    Decision: Default to 2) Yes; provide command line option for 1).

  * What format do we use for private & public keys? 1) binary, 2) base64, 3) hex, 4) auto.
    Decision: ?

# Testing executable
TODO: Test using more common methods - actually running the executable
 * std::process only allows piping File to stdin, or going the spawn-write-wait path
   (https://doc.rust-lang.org/std/process/struct.Stdio.html)
   * No way to create anon pipe in std, although std uses it internally, though libc::pipe
     (https://github.com/rust-lang/rust/blob/master/src/libstd/sys/unix/pipe.rs)
   * nix crate provides pipe2 https://docs.rs/nix/0.14.1/nix/unistd/fn.pipe2.html
   * tempfile crate - provides tempfile() function that can be used to pipe into stdin.
   -> Decided to go with tempfile route and standard lib functions.
 * Process execution helpers:
   * duct crate https://docs.rs/duct/0.12.0/duct/struct.Expression.html
     - does not allow providing string as stdin, otherwise convenient with cmd!("name", "arg1", "arg2")
   -> Decided to just use standard lib functions; same convenience with a helper or two.
 * Test cmd helpers:
   https://docs.rs/assert_cmd/0.11.1/assert_cmd/
     adds cargo_bin to run the project binary -> reimplemented
     supplies buffer to stdin -> reimplemented
     assertions on output via `predicates` crate - not good. 
 * Good: will not need to rewrite when we do async.
 * Problem: need to control is_tty (see libc::isatty(stream.as_raw_fd()) == 1 )
   * Either need to add ENV variables , or create pseudo-tty
     * create pseudo-tty with 'nix' crate: use http://man7.org/linux/man-pages/man3/posix_openpt.3.html  (or openpty)
     -> Easier and safer to do ENV variables like MOCK_IS_TTY=stdin,stdout  

# Releases
Current plan is to use GitHub releases for distribution.
Travis CI can build the software for all major platforms and then upload it to Github. See:
  * https://docs.travis-ci.com/user/deployment/releases/
  * https://docs.travis-ci.com/user/encryption-keys/  - to avoid storing github tokens in the raw.
  * https://docs.travis-ci.com/user/reference/overview/ - environment reference (linux, mac, windows)

Inspiration: https://medium.com/@kevinkreuzer/the-way-to-fully-automated-releases-in-open-source-projects-44c015f38fd6