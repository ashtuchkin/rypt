# Scratchpad
Note, a lot of the information here is stale. Don't rely on it for anything.

## Command line ergonomics
 * Regular file(s):
   `rypt <file> <file> <file>`   # Encrypt files, will ask for password twice, then write encrypted files with .rypt extension.
   `rypt -d <file> <file>`       # Decrypt files, will ask for password once, remove .rypt extension.
   * Input: 
     * Regular files, no hardlinks (checking metadata.nlink == 1; std::os::unix::fs::MetadataExt)
      * By default writes a sibling file with the same name + suffix.
      * Copies the same user/group, permissions, modified timestamps. 
      * ?? removes original file on success (Question: wipe the file?; Question: ask user to delete it?; Question: only after all files been encoded?); 
      * removes new file on failure.
   * Skips all the other filetypes (folders, symlinks, char/block devices, sockets), with reference to streaming mode.
 * Streaming mode (-s):
   * Only one input is allowed. Output is always to stdout.
   * Input: stdin ("-"), files, named pipes (fifo/process substitution), char devices, potentially through symlinks.
   * Default if stdin is the input (or no files provided).
   * Bail if encrypted data goes from/to a TTY.
   * Allow if stdin input requested + password interactive mode
 * Ways to provide passwords/keys:
   * Password: 1) -p interactive prompt via stdin/stderr, 2) --password-file=filename
   * Symmetric key: --symmetric-key=filename  (file must contain 32 bytes hex keys, one per line)
   * Private key / Public key: --public-key=filename,  --private-key=filename
     --public-key-text=b8604b483a8c215447afacfc82762411df698b76f8539fb74a8b3d48e9ec3f26
   * Future: sender private key: --sign-private-key=filename, --repudiable
 * Encrypt a folder and other creative pipe usages:
   `tar c <folder> | xz | rypt --password-file password.txt | aws s3 cp - s3://mybucket/archive.xz.rypt`
   `rypt -s <(tar c . | xz) > archive.xz.rypt`  # will ask password interactively
 * Future: User authenticated data:
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
   * Workaround: "--password-file=<(echo $ABC)" would do. 
     Same for command line arg: "--password-file=<(echo password)"; it will also not show up in htop.

 * Verbose/quiet rules:
   * Exit code: 0 if success, 1 if at least one error. In the future, 2 if at least one warning.
   * Verbosity: 
     * -2 => Don't print anything; No interactive prompts allowed.
     * -1 => Show only errors and warnings; Password prompts allowed, but not the other prompts
     * 0 (no -v or -q given) => treat as 1 if stderr is TTY, -1 otherwise 
     * 1 => All messages, including warnings, enough for basic usage without reading manual.
       * Direction
       * All input / output files
     * 2 => Include Access Structure visualization, algorithms chosen. 
     * (potentially in the future) 3 => Logs for initializing the library, opening files, encrypting chunks.
   * Progress bar is enabled when printing i/o file names and stderr is tty.
     * Not permanent - we should have 1 line per file, not 3. Maybe keep one at the end.
     * Only show when conversion takes > 2 sec
   * When encoding from stdin / decoding to stdout - don't use progress bar.
   * Errors/warnings format:
     `./rypt: Error: Private keys should not be passed in when encrypting (pass -f to force)` 
     `./rypt: Warning: Private keys should not be passed in when encrypting (forced)`
     `./rypt: Error creating 'target/abc': File exists (os error 17) (pass -f to force)` 
     `./rypt: Invalid or insufficient credentials`
      


## Public key infrastructure compatibility
 * PGP: Armored OpenPGP binary packets ("BEGIN PGP PRIVATE KEY BLOCK" / "BEGIN PGP PUBLIC KEY BLOCK")
    * Keybase provides it, e.g. https://keybase.io/as/pgp_keys.asc
    * Can be converted to ssh keys, see openpgp2ssh
    * OpenPGP binary packets described in https://tools.ietf.org/html/rfc4880.
      ECDSA with NIST curves extensions https://tools.ietf.org/html/rfc6637
      EdDSA extension https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04 
 * SSH keys (OpenSSH supports Ed25519 since 6.5) E.g. https://medium.com/risan/upgrade-your-ssh-key-to-ed25519-c6e8d60d3c54
    * Github provides it, e.g. https://github.com/ashtuchkin.keys
    * ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
    * Would need to decode public key and private key formats (potentially with password) https://stackoverflow.com/a/12750816/325300
      public key format: "<type> <base64 payload> <comment>", payload is a concatenation of uint32-len-prefixed strings:
        ssh-ed25519:
          * "ssh-ed25519" (0x0b size),
          * the key itself (0x20 size).
        ecdsa-sha2-nistp256 (from https://coolaj86.com/articles/the-ssh-public-key-format/):
          * "ecdsa-sha2-nistp256" (0x13 size)
          * "nistp256" (0x08 size)
          * the key itself (0x41)
            * always 0x04 byte - means we're storing key in uncompressed format - both x and y coordinates are given
            * x coordinate (32 bytes)
            * y coordinate (32 bytes)
      private key format: 
        OpenSSH has its own proprietary format "-----BEGIN OPENSSH PRIVATE KEY-----"
            * see https://coolaj86.com/articles/the-openssh-private-key-format/
        Older OpenSSH and OpenSSL use Armored DER/ASN.1 (x.509) ("BEGIN RSA PRIVATE KEY" / "BEGIN EC PRIVATE KEY")
            * https://coolaj86.com/articles/openssh-vs-openssl-key-formats/
            * https://lapo.it/asn1js/  - online ASN.1 decoder
    * ssh-agent integration?
 * Keybase has it's own format: https://saltpack.org/encryption-format-v2

<--
## OpenSSH private key (no password):

6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00  # Magic string "openssh-key-v1\0"
00 00 00 04 | 6e 6f 6e 65   # Ciphername: "none" 
00 00 00 04 | 6e 6f 6e 65   # KdfName: "none"
00 00 00 00   # Kdf params, empty string
00 00 00 01   # Number of keys, only 1 is supported.
00 00 00 33    # Public key in SSH format:  
   00 00 00 0b | 73 73 68 2d 65 64 32 35 35 31 39                 # "ssh-ed25519" 
   00 00 00 20 | b8 60 4b 48 3a 8c 21 54 47 af ac fc 82 76 24 11  
                 df 69 8b 76 f8 53 9f b7 4a 8b 3d 48 e9 ec 3f 26  # public key 
00 00 00 98    # Private key, including padding to cipher block size or 8
   71 5c bf bc   # Two random uint32-s, checked to be equal.
   71 5c bf bc 
   00 00 00 0b | 73 73 68 2d 65 64 32 35 35 31 39                 # "ssh-ed25519" again
   00 00 00 20 | b8 60 4b 48 3a 8c 21 54 47 af ac fc 82 76 24 11  # public key again 
                 df 69 8b 76 f8 53 9f b7 4a 8b 3d 48 e9 ec 3f 26  
   00 00 00 40 | 68 22 05 28 d0 4c 46 29 e8 04 e7 2c 3a ec 30 b2  # ed25519 private key (32 bytes seed, 32 bytes public key)
                 7b c4 f6 7b a6 b2 5d ad 4f d2 2b 4a a5 d5 23 43 
                 b8 60 4b 48 3a 8c 21 54 47 af ac fc 82 76 24 11 
                 df 69 8b 76 f8 53 9f b7 4a 8b 3d 48 e9 ec 3f 26   
   00 00 00 0e | 61 73 68 74 75 63 68 6b 69 6e 40 6d 62 70        # comment:  ashtuchkin@mbp 
   01 02 03 04 05 06 07  # Deterministic padding to 8 bytes

NOTE: Actual private key is 32 bytes seed, starting from offset 0xA1. From these, everything else can be recovered.

## OpenSSH private key (with password):

6f 70 65 6e 73 73 68 2d  6b 65 79 2d 76 31 00    # Magic string "openssh-key-v1\0"
00 00 00 0a | 61 65 73 32 35 36 2d 63 74 72   # Ciphername: aes256-ctr
00 00 00 06 | 62 63 72 79 70 74  # Kdfname: bcrypt
00 00 00 18 |  # Kdf params for bcrypt
    00 00 00 10 | 1c 2f ed 68 19 65 53 32 58 56 5f ac df 1c cd 47   # Salt
    00 00 00 10  # Rounds
00 00 00 01   # Num keys
00 00 00 33   # Public key
   00 00 00 0b | 73 73 68 2d 65 64 32 35 35 31 39   # "ssh-ed25519"
   00 00 00 20 | d7 8f 68 7a 94 c2 a5 b3 5a d1 f0 9b 68 1d d4 00 
                 32 81 2d d9 72 44 32 20 ad 87 31 81 6a e8 4c 32 
00 00 00 a0  # Encrypted private key. Note, we derive both cipher key and iv from kdf (request key_len + iv_len bytes).
   c7 2f 83 f6 83 93 6c a0 2f 51 10 b9 90 61 ec ef
   7c 03 03 2b be 1a 24 73 f4 a2 b0 9d e3 23 fb 81 
   b6 2e 9d 24 29 dd a5 4b f9 29 ab cb e4 ba 02 31 
   a3 1c e2 e1 9b c9 e4 2e a4 0b c9 42 79 6e 17 da 
   fd b0 5d c6 e5 69 8d a1 11 ae a8 c4 7c 7d 1c 75 
   cf 19 a6 00 17 bc 75 75 fb e3 88 5d c5 9d d2 91 
   6f c4 fe ba 07 f1 e3 79 72 18 9f 7e bd eb 52 ff 
   16 30 40 fa d3 0c 1a a1 7f cc 42 11 03 c6 33 f1 
   c7 da 07 fd f8 3f c0 5e 8a 41 dd 77 38 64 0f 4b 
   2a 52 f2 dd 38 8b 3d 68 5b dd f7 44 a3 f7 3a 85

Encrypted len must be an even number of cipher blocks (16 for aes256-ctr).
If cipher has auth, then it'll follow here. aes256-ctr doesn't.
Should be no trailing data
-->

## Public/private key encoding
Looks like base58 (https://docs.rs/bs58) is the most widely used markdown-safe encoding. base62 from saltpack is okayish
but requires writing custom codec.  

Hex/base16 (64 chars):
b8604b483a8c215447afacfc82762411df698b76f8539fb74a8b3d48e9ec3f26

base64 (43 chars):
uGBLSDqMIVRHr6z8gnYkEd9pi3b4U5+3Sos9SOnsPyY

base62 (43 chars):
hiiXIt98RAEEgNgwYxlKMdDpTH2iisR6qaPYOcpTbbK

base58 (44 chars):
DQjBQLprbJdxA6sUkSSWWGN6TVBHgLXP5a967fZtTdnd

Would be nice to be: 
 * As simple as possible
 * Be markdown and copy/paste compatible (so that it's easy to publish)
 * Protected against typos (checksum?) we can use mixed-case checksum https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
   in our case: hex(hash(data)), then uppercase each char where hex char >=8
 * Easily identified ("vanity" prefix)?

It's nice that in Ed25519 private key contains public key, so they can be matched manually.


## Shamir secret sharing
Looks like a basic Shamir scheme over Gf(256) is the most straightforward. We'll use standard polynomial (same as in 
e.g. AES algorithms). Good description here https://tools.ietf.org/id/draft-mcgrew-tss-03.html

There are a couple crates out there that are relevant, but not 100% fit:
 * https://github.com/snipsco/rust-threshold-secret-sharing - advanced & fast, but requires prime field, not Gf(256).
 * https://github.com/amousa11/libss - close, but needlessly randomizes each byte's X coordinate, doubling the number of 
    bytes to store. `combine` does not check number of shares. Non-array-based Gf(256) field multiplication.
    Good: uses quickcheck. barycentric lagrange might be interesting.
 * https://github.com/Nebulosus/shamir - close, but unmaintained, works with strings instead of byte arrays, plus I think
   there's a bug on line 89. Gf256 implementation is sufficiently basic, with arrays.
 * https://github.com/SpinResearch/RustySecrets - close, but adds unneeded cruft like base64-encoding, protobufs and 
    signatures. Good Gf256 implementation.


## Authentication (old)
 * Everything from the beginning of the file up to the first chunk data.
 * If user authenticated data is detached, replace it with the length and contents, just like if it's not detached.
 * If AEAD algorithm does not provide a built-in way to tag the final chunk, an additional rule is used:
   * Append 1 byte tag to the end of the authenticated data with the value of 0 if the chunk not final, 1 if final.
   * If resulting value is a single byte 0 (i.e. no original authentication data and the chunk is not final), then 
     replace it with empty authentication data (for performance).
   * This would fail the last chunk authentication if the file is truncated.
   ----
   * Alternative: Use Nonce: for final chunk, set highest bit of message counter.

## Algorithm-specific changes from libsodium (old)
 * XChacha20Poly1305 adds 7 bytes random prefix to align ciphertext and plaintext blocks. Final chunk has TAG_FINAL.
 * AES256-GCM stores it's nonce in encryption header. Changes:
    * It uses nonce extension to 192 bit, using 
        https://libsodium.gitbook.io/doc/key_derivation#nonce-extension
        (per_chunk_private_key || per_chunk_nonce) = SHA512(original private key || extended nonce || message #).
      In this case encryption header is 192 bit (24 bytes) and a random value can be comfortably used. 
      This extension can be disabled in header protobuf for compatibility.
    * As the algorithm does not provided built-in tagging for final chunk, use the algorithm described above. 

https://crypto.stackexchange.com/questions/53104/is-it-safe-to-store-both-the-aes-related-data-and-the-pbkdf2-related-data-excep?rq=1

## Public key algorithms
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

## Testing executable
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

## Releases
Current plan is to use GitHub releases for distribution.
Travis CI can build the software for all major platforms and then upload it to Github. See:
  * https://docs.travis-ci.com/user/deployment/releases/
  * https://docs.travis-ci.com/user/encryption-keys/  - to avoid storing github tokens in the raw.
  * https://docs.travis-ci.com/user/reference/overview/ - environment reference (linux, mac, windows)

Inspiration: https://medium.com/@kevinkreuzer/the-way-to-fully-automated-releases-in-open-source-projects-44c015f38fd6

## PGP problems
https://crypto.stackexchange.com/a/12355

Format: https://tools.ietf.org/html/rfc4880

## Readme improvements
 * Several modes to authenticate sender: signed, repudiable, anonymous. 



