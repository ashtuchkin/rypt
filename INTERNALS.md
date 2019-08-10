# File structure
Assumptions:
 * Actual data is always encrypted using a per-file random 256 bit "payload key".
   * This means we can and will use hardcoded nonces, as the key can be treated as unique.
 * All chunks are the same size except, potentially, the last one.
 * Encrypted data must be indistinguishable from random bytes. Only header is tractable if you don't
   have the right credentials.

## Cryptography base operations
 * HASH(M) -> H  (H: 32 bytes)
 * HMAC(M, K) -> MAC  (K: 32 bytes, MAC: 32 bytes)
 * SECRETBOX(M, A, K, N) -> C + MAC | UNSECRETBOX(C + MAC, A, K, N) -> M   (K: 32 bytes, N: 12 bytes, MAC: 16 bytes)
 * BOX(M, PK, SK, N) -> C + MAC     | UNBOX(C + MAC, SK, PK, N) -> M   | BOX_KEYPAIR() -> (PK, SK)   (SK/PK: 32 bytes, N: 24 bytes, MAC: 16 bytes)
 * SIGN(M, SK) -> S                 | SIGN_VERIFY(M, S, PK) -> Bool   (SK/PK: 32 bytes, S: 64 bytes)
 * KDF(P, Salt) -> S   (Salt: 16 bytes, S: Any)

## High-level file structure

| Item                                             | Size         |
|--------------------------------------------------|--------------| 
| File signature: ASCII 'rypt'                     | 4 bytes      |
| Header length, little-endian uint32              | 4 bytes      |
| Header protobuf, padded to 8N bytes              | header len + padding |
| N x Ciphertext chunk                             | (chunk_size; last one may be smaller |

## Header 
 
PayloadKey = RANDOM(32 bytes)
EphemeralPK, EphemeralSK = BOX_KEYPAIR()

Header protobuf contents:
 * Format compatibility version (counter)
 * Which set of algorithms to use for key derivation and checks.
 * Which AEAD algorithm to use for the payload. If we'd want just to sign in the future, this can be NULL.
 * EphemeralPK
 * KeyThreshold
 * Recipients array. All public key recipients are listed first. For each recipient:
   * Recipient identification: Optional(RecipientPK)
   * Encrypted payload key.
      Nonce = PAD(16, "rypt recipient") | RecipientIdx
      Payload: PayloadKey or ShamirSecretShare
      If symmetric:
        SecretKey = HMAC(EphemeralPK|SymmetricSecret, K=PAD(32, "rypt symmetric secret"))
        SECRETBOX(M=Payload, K=SecretKey, N=Nonce)
      If password:
        SecretKey = KDF(Password, Salt=HMAC(EphemeralPK, K=PAD(32, "rypt kdf salt")))
        SECRETBOX(M=Payload, K=SecretKey, N=Nonce)
      If public key:
        BOX(M=Payload, PK=RecipientPK, SK=EphemeralSK, N=Nonce)
 * Encrypted header info:
   SECRETBOX(K=PayloadKey, N=PAD(24, "rypt encrypted header"))  
     * SenderAuthType = one byte, ANONYMOUS=1, REPUDIABLE=2, SIGNED=3
     * SenderPK (if ANONYMOUS, then Zeros)
     * AuthCnt: uint32le, if REPUDIABLE, then number of authenticators (=public keys), else 0 
     * Plaintext chunk size
 * Associated public authenticated data

HeaderHash = HASH(Header)

if SenderAuthentication == REPUDIABLE, for all public key recipients:
  M = BOX(HeaderHash, RecipientPK[i], SenderSK, N=PAD(16, "rypt auth mac") | RecipientIdx)
  MAC[j] = HASH(M)

## Chunk
ChunkIdx = uint64le, starting with 0 
FinalFlagByte = 0x01 if final, else 0x00)
 
AEAD Encrypted chunk (K=PayloadKey, N="rypt"|ChunkIdx, A=(HeaderHash|FinalFlagByte))
   * If SenderAuthentication == REPUDIABLE: Per-recipient authentication tags
       M = "rypt authentication tag\0"|HeaderHash|ChunkIdx|FinalFlagByte|HASH(Plaintext)
       AuthTag[i] = HMAC(M, K=MAC[i])
   * If SenderAuthentication == SIGNED: Sender signature
       M = "rypt encrypted signature\0"|HeaderHash|ChunkIdx|FinalFlagByte|HASH(Plaintext)
       Signature = SIGN(M, SenderSecretKey)
   * Plaintext 
 

 
## Format extensibility
 * Signature-only usage: AEAD algorithm can be replaced with just HMAC 

