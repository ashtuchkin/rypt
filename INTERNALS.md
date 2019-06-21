

Command line ergonomics:
 * Regular files:
   `rypt <file> <file> <file>`   # Encrypt files, will ask for password twice, then write encrypted files with .rypt extension.
   `rypt -d <file> <file>`       # Decrypt files, will ask for password once, remove .rypt extension.
   * Skips invalid files and folders; No symlinks, files with hardlinks.
   * Sets the same user/group, permissions, timestamps.
 * Ways to provide password:
   * Password: 1) Stdin/stdout, 2) Command line (unsafe), 3) Env var, 4) File 
   * Hex key: 1) Command line (unsafe), 2) File, 3) Env var
 * Encrypt folder and other creative pipe usages:
   `tar c <folder> | rypt -p password_file | aws s3 cp - s3://mybucket/encoded_file.rypt`
 * Using with tar:
   (TODO: check password entry works with stdin/out)
   `tar cf output.tar.rypt --use-compress-program "rypt -p password_file" <folder>` to encrypt; 
   `tar xf output.tar.rypt --use-compress-program "rypt -p password_file"` to decrypt
 * Provide password/private key through the env variables:
   * Command asks for password and runs provided program / pipe with given password in environment variable.
   * env vars do leak private key and seed (i.e. files can be decoded), but don't leak the password.
   * Note you can see all env vars of the processes you own (and only you) in `/proc/<pid>/environ` (https://security.stackexchange.com/a/14009)
   `rypt-pass -- tar cf output.tar.rypt --use-compress-program rypt <folder> `


File structure:
!! All fields except the first two are padded to 8 bytes, including data chunks.

| Item                                             | Size         |
|--------------------------------------------------|--------------| 
| File signature and version: ASCII 'enc1'         | 4 bytes      |
| Header length, little-endian uint32              | 4 bytes      |
| Header protobuf                                  | header len   |
| Encryption header                                | (algorithm dependent) |
| User authenticated data len, little-endian uint64, 0 if not provided, maxint64 if detached  | 8 bytes      |
| User authenticated data                          | auth data len|
| Ciphertext chunk size, little-endian uint64      | 8 bytes      |
| Ciphertext chunk x N                             | min(chunk_len, remaining size) |

Chunks are provided as-is to the encoding/decoding algorithms.
Authentication:
 * Everything from the beginning of the file up to, but not including the first chunk data.
 * If user authenticated data is detached, replace it with the length and contents, just like if it's not detached.
 * If AEAD algorithm does not provide a built-in way to tag the final chunk, an additional rule is used:
   * Append 1 byte tag to the end of the authenticated data with the value of 0 if the chunk not final, 1 if final.
   * If resulting value is a single byte 0 (i.e. no original authentication data and the chunk is not final), then 
     replace it with empty authentication data (for performance).
   * This would fail the last chunk authentication if the file is truncated.
 

Algorithm-specific changes:
 * XChacha20Poly1305 adds 7 bytes random prefix to align ciphertext and plaintext blocks. Final chunk has TAG_FINAL.
 * AES256-GCM stores it's nonce in encryption header. Changes:
    * It uses nonce extension to 192 bit, using 
        (per_chunk_private_key || per_chunk_nonce) = SHA512(original private key || extended nonce || message #).
      In this case encryption header is 192 bit (24 bytes) and a random value can be comfortably used. 
      This extension can be disabled in header protobuf for compatibility.
    * As the algorithm does not provided built-in tagging for final chunk, use the algorithm described above. 

