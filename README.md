<!-- TODO: build badges -->

⚠️⚠️⚠️ **This tool is not ready to use in production yet. Please wait until version 1.0.** ⚠️⚠️⚠️


# Rypt: command line encryption tool
 * Encrypt/decrypt files and streams using password or a public/private key pair(s).
 * Secure, modern cryptographic defaults. Hard to screw up (see details below).
 * Based on [libsodium](https://libsodium.gitbook.io/doc/), industry-standard cryptographic primitive library.
 * Written in [Rust](https://www.rust-lang.org/), efficient and memory-safe programming language.
 * Tamper-resistant / authenticated encryption: any change to encrypted files would make them invalid.
 * Standalone tool: does not depend on any commercial services / clouds.
 * Supports advanced use cases like multiple recipients, passwords, [(t, n)-threshold scheme](https://en.wikipedia.org/wiki/Secret_sharing).
 * Fast. ~1.1 Gb/s on my 2013 MacBook using AES256-GCM algorithm. Usually hard drive speed is the limiting factor.
 * Easy to use at both beginner and advanced level (see examples below).
 * Lightweight: <1 Mb binary; <10 Mb memory used when encrypting/decrypting (unless required by password derivation functions).
 * Operating System Support: GNU/Linux, MacOS. Windows support is planned. See "Installation" section below for details.
 * Open source. License: MIT.

## Examples
```bash
$ rypt my-secret-file.txt
NOTE: Original file will be deleted after a succesful encryption. Pass -k to keep it.
Enter password: *******
Enter password again: *******

Encrypting my-secret-file.txt -> my-secret-file.txt.rypt (1/1)
   100.0 %       1.12 MiB

$ rypt -d my-secret-file.txt.rypt
NOTE: Encrypted file will be deleted after a succesful decryption. Pass -k to keep it.
Enter password: *******

Decrypting my-secret-file.txt.rypt -> my-secret-file.txt (1/1)
   100.0 %       1.12 MiB

# Advanced use case: upload a public-key-encrypted compressed archive to S3
$ tar c . | xz | rypt --recipient recipent-key.pub | aws s3 cp - s3://mybucket/archive.xz.rypt


```

## Installation
Download the latest binary in the [Releases](https://github.com/ashtuchkin/rypt/releases) section.


## Why not use existing tools?
 * PGP: Large installation; cumbersome (--symmetric?); old algorithms (AES128 in CFB mode); slow (TODO: numbers); no proper password derivation, no full-file authentication.
 * OpenSSL: too low-level; TODO.
 * Keybase: No password-based encryption, depends on having an account at a commercial service; TODO.
 * Archivers like zip, 7z, winrar: old algorithms, not stream-friendly, no public key crypto; TODO.

