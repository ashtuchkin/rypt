

Command line ergonomics:
 * Regular file(s):
   `rypt <file> <file> <file>`   # Encrypt files, will ask for password twice, then write encrypted files with .rypt extension.
   `rypt -d <file> <file>`       # Decrypt files, will ask for password once, remove .rypt extension.
   * Input: 
     * Regular files, no hardlinks (checking metadata.st_nlink == 1)
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


File structure:

| Item                                             | Size         |
|--------------------------------------------------|--------------| 
| File signature: ASCII 'rypt'                     | 4 bytes      |
| Header length, little-endian uint32              | 4 bytes      |
| User authenticated data len, little-endian uint64, 0 if not provided, maxint64 if detached  | 8 bytes      |
| Ciphertext chunk size, little-endian uint64      | 8 bytes      |
| Header protobuf                                  | header len (aligned to 8 bytes) |
| User authenticated data                          | auth data len (aligned to 8 bytes) |
| N x Ciphertext chunk                             | min(chunk_size, remaining size) |

Question: why not prepend each chunk with its size & the final tag? That would allow easier & safer decoding, as we would
detect appending of garbage to the end of the file.

Chunks are provided as-is to the encoding/decoding algorithms.
Authentication:
 * Everything from the beginning of the file up to, but not including the first chunk data.
 * If user authenticated data is detached, replace it with the length and contents, just like if it's not detached.
 * If AEAD algorithm does not provide a built-in way to tag the final chunk, an additional rule is used:
   * Append 1 byte tag to the end of the authenticated data with the value of 0 if the chunk not final, 1 if final.
   * If resulting value is a single byte 0 (i.e. no original authentication data and the chunk is not final), then 
     replace it with empty authentication data (for performance).
   * This would fail the last chunk authentication if the file is truncated.
   ----
   * Alternative: Use Nonce: for final chunk, set highest bit of message counter.
 

Algorithm-specific changes:
 * XChacha20Poly1305 adds 7 bytes random prefix to align ciphertext and plaintext blocks. Final chunk has TAG_FINAL.
 * AES256-GCM stores it's nonce in encryption header. Changes:
    * It uses nonce extension to 192 bit, using 
        https://libsodium.gitbook.io/doc/key_derivation#nonce-extension
        (per_chunk_private_key || per_chunk_nonce) = SHA512(original private key || extended nonce || message #).
      In this case encryption header is 192 bit (24 bytes) and a random value can be comfortably used. 
      This extension can be disabled in header protobuf for compatibility.
    * As the algorithm does not provided built-in tagging for final chunk, use the algorithm described above. 

https://crypto.stackexchange.com/questions/53104/is-it-safe-to-store-both-the-aes-related-data-and-the-pbkdf2-related-data-excep?rq=1
