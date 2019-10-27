<!-- TODO: build badges -->

# Rypt: versatile command-line encryption tool
 * Encrypt/decrypt files and streams using passwords, public/private key pairs and complex combinations of these.
 * Uses modern cryptographic primitives provided by [libsodium](https://libsodium.gitbook.io/doc/).  
 * Written in [Rust](https://www.rust-lang.org/), efficient and memory-safe programming language.
 * 100% Authenticated Encryption: any change to encrypted files would make them invalid.
 * Offline, standalone tool that does not depend on any commercial services / clouds.
 * Supports advanced use cases like multiple passwords/public keys, [key threshold schemes](https://en.wikipedia.org/wiki/Secret_sharing) and more.
 * Fast. ~1.1 Gb/s on a 2013 MacBook using AES256-GCM algorithm. Usually I/O bandwidth is the limiting factor.
 * Easy to use at both beginner and advanced level (see examples below).
 * Lightweight: ~1 Mb binary size; <10 Mb memory used (except as required by password derivation functions).
 * Operating System Support: x86 Linux, MacOS, Windows.
 * Open source, MIT license.

## Examples
```bash
$ # Basic use case: encrypt/decrypt file with a password
$ rypt secret-interview.mp4 
Enter password: 
Confirm password: 

secret-interview.mp4 -> secret-interview.mp4.rypt (1/1)
   100.0 %       1.46 GiB     310.18 MiB/s   ETA  0:00s

Remove original file(s)? [y/N]: y

$ rypt -d secret-interview.mp4.rypt 
Enter password: 

secret-interview.mp4.rypt -> secret-interview.mp4 (1/1)
   100.0 %       1.46 GiB     320.48 MiB/s   ETA  0:00s

Remove original file(s)? [y/N]: y

$ # Advanced examples: generate public/private key pair
$ rypt -g recipient-key
Keypair 1/1:
    Public key: 8bF9648A4C7705E3276795901819Dfe734fa62Df587CF7dB27a17D6FD0d5012c
    Public key file: recipient-key.pub
    Private key file: recipient-key

$ # Upload a public-key-encrypted compressed archive to S3
$ tar c . | xz | rypt --public-key recipient-key.pub | aws s3 cp - s3://mybucket/archive.xz.rypt

$ # Then download it, decrypt and unpack
$ aws s3 cp s3://mybucket/archive.xz.rypt - | rypt -d --private-key recipient-key | xz -d | tar x

$ # More advanced examples: encrypt a note from stdin using an any-2-out-of-3 passwords threshold scheme
$ rypt -p -p -p --key-threshold 2 > encrypted.rypt
Enter password: 
Confirm password: 

Enter password: 
Confirm password: 

Enter password: 
Confirm password: 

(stdin) -> (stdout) (1/1)
This is a secret message.
^D
$ ./rypt -d -p -p -s encrypted.rypt
Enter password: 

Enter password: 

encrypted.rypt -> (stdout) (1/1)
This is a secret message.

```

## Installation
### Download binary
See the [Releases](https://github.com/ashtuchkin/rypt/releases) section.

### From source
 1. Install Rust: https://www.rust-lang.org/tools/install
 2. `cargo install rypt`

## Why not use existing tools?
 * PGP: Large installation; cumbersome (--symmetric?); old algorithms (AES128 in CFB mode); slow (TODO: numbers); no proper password derivation, no full-file authentication.
 * OpenSSL: too low-level; TODO.
 * Keybase: No password-based encryption, depends on having an account at a commercial service; TODO.
 * Archivers like zip, 7z, winrar: old algorithms, not stream-friendly, no public key crypto; TODO.

