# ENCRYPTION.md

## Light Encryption Utility – Hybrid Post‑Quantum + Classical Cipher Suite

**Version:** 1.0 (final)  
**Repository:** [Light Encryption Utility](#) (private / simulation)  
**Classification:** SIMULATED – closed‑environment cryptographic prototype

---

## 📖 Overview

This utility encrypts and decrypts files using a **hybrid key encapsulation mechanism (KEM)** that combines the post‑quantum **Kyber‑1024** algorithm with the classical **X25519** elliptic curve Diffie‑Hellman. The resulting shared secret is then used as a key for a symmetric cipher – either **AES‑256‑GCM** or the custom **Obscurity** sponge (a constant‑time ARX permutation).  

All sensitive material (the hybrid private key) is stored **inside the encrypted file** itself, protected by a **user‑supplied password** via Argon2id key derivation. The output file contains **no magic bytes** or any other fixed pattern; it is computationally indistinguishable from random noise, offering plausible deniability and resistance to forensic fingerprinting.

The utility is designed for **streaming (O(1) memory)** to support arbitrarily large files, includes a **progress bar**, **memory locking** (`mlock`) for key material, **signal‑safe cleanup**, and a **settings menu** to choose between the two symmetric ciphers.

---

## 🧠 High‑Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          User Input                                 │
│   (Password, input file path, output file path, cipher preference)  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Key Derivation (Argon2id)                    │
│   salt = random(16), t=4, m=512MiB, p=1 → 32‑byte encryption key   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Hybrid Key Encapsulation (KEM)                  │
│   Generate ephemeral Kyber‑1024 + X25519 key pair                   │
│   Encapsulate a random 32‑byte file key using the public key       │
│   Encrypt the hybrid private key with the derived password key     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Wrap cipher preference into the encrypted blob         │
│   [ 1‑byte flag (0=AES / 1=Obscurity) | hybrid private key ]       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Write header (all random‑looking)                  │
│   salt (16) + nonce for AEAD (12) + encrypted blob (… )            │
│   + Kyber ciphertext (1568) + X25519 ephemeral public key (32)     │
│   + cipher‑specific nonce (12 or 16)                               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Streaming encryption of file data                  │
│   Using the selected symmetric cipher (AES‑256‑GCM or Obscurity)   │
│   1 MiB chunks, tag appended at the end                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Key Components

### 1. Password‑Based Key Derivation – Argon2id

- **Salt**: 16 random bytes (generated per encryption, stored in the output).
- **Time cost**: 4 iterations.
- **Memory cost**: 512 MiB (configurable in the source via `ARGON2_MEMORY`).
- **Parallelism**: 1 thread.
- **Output**: 32‑byte key used to encrypt the hybrid private key.

### 2. Hybrid Key Encapsulation Mechanism (KEM)

- **Kyber‑1024** (NIST PQC finalist, security level 5 – approximately AES‑256 equivalent).
- **X25519** (Elliptic Curve Diffie‑Hellman, 128‑bit classical security).
- **Key pair generation**: fresh pair for **every** encryption (ephemeral).
- **Encapsulation**:  
  - Kyber: `kyber_ct`, `kyber_ss`.  
  - X25519: ephemeral key pair `(eph_pub, eph_priv)`, compute `x25519_ss = scalarmult(eph_priv, recipient_x25519_pub)`.
- **Combination**: `combined = kyber_ss || x25519_ss` → `shared_secret = BLAKE2b(combined)` (32 bytes).  
  This provides **post‑quantum + classical hybrid security**.

### 3. Protection of the Hybrid Private Key

The private half of the ephemeral hybrid key pair (`kyber_sk` + `x25519_sk`, total 3168+32 = 3200 bytes) must be kept secret so the file can be decrypted later. It is:

1. **Prefixed with a 1‑byte cipher flag** (`0x00` for AES, `0x01` for Obscurity).  
2. **Encrypted with AES‑256‑GCM** using the key derived from the user’s password.  
3. Stored as the **first encrypted block** in the output file (right after the salt and a dedicated nonce).

This ensures the cipher choice is **protected by the password** and not visible to an attacker who does not know the password.

### 4. Symmetric Ciphers (Pluggable)

#### a. AES‑256‑GCM (OpenSSL)

- **Key**: 32 bytes (from the KEM shared secret).  
- **Nonce**: 12 random bytes (stored per file).  
- **Authentication tag**: 16 bytes, appended after the ciphertext.  
- **Streaming**: OpenSSL EVP API, chunk size 1 MiB.  
- **Performance**: Hardware accelerated on most CPUs.

#### b. Obscurity (Custom Constant‑Time Sponge)

- **State**: 512 bytes (64×64‑bit words).  
- **Rate**: 256 bytes.  
- **Permutation**: 32 rounds of ARX (add‑rotate‑xor) with nothing‑up‑my‑sleeve round constants derived from π digits.  
- **Duplex mode**: Absorbs plaintext, squeezes ciphertext.  
- **Authentication**: 16‑byte sponge tag squeezed after finalisation.  
- **Security assumptions**: This primitive is **unreviewed and classified for simulation only**; it relies on algorithmic secrecy + key secrecy. Its inclusion demonstrates a pluggable cipher layer.

### 5. Streaming Encryption (O(1) Memory)

Both ciphers are implemented with **chunked processing** (1 MiB per iteration). No more than a few megabytes of RAM are used, regardless of file size. A progress bar shows the percentage completed and the throughput (MB/s).

---

## 📁 File Format (Indistinguishable from Random Noise)

The encrypted file contains **no magic bytes, no version numbers, no fixed headers**. All fields are cryptographically random or pseudorandom, making the file indistinguishable from a stream of random bytes to any observer who does not possess the password.

### Layout (in order of writing)

| Field                                         | Size (bytes) | Source / Description                              |
|-----------------------------------------------|--------------|---------------------------------------------------|
| Salt for Argon2id                             | 16           | `randombytes_buf`                                 |
| Nonce for the hybrid‑key encryption (AEAD)    | 12           | `randombytes_buf`                                 |
| Encrypted hybrid private key + cipher flag    | 3200 + 1 + 16 | AES‑256‑GCM of (flag + hyb_sk) + tag            |
| Kyber‑1024 ciphertext                         | 1568         | Output of `pqcrystals_kyber1024_ref_enc`         |
| X25519 ephemeral public key                   | 32           | `crypto_box_keypair` ephemeral                   |
| Cipher‑specific nonce                         | 12 or 16     | `randombytes_buf` (AES = 12, Obscurity = 16)     |
| Ciphertext (data)                             | variable     | Streamed, same length as plaintext               |
| Authentication tag (GCM or sponge tag)        | 16           | End of file                                       |

**Notes**:
- The `encrypted blob` contains the cipher flag as its first byte, then the concatenated `kyber_sk` (3168) and `x25519_sk` (32). Its total length is therefore `1 + 3168 + 32 = 3201` bytes, plus the 16‑byte AEAD tag, making the ciphertext portion `3201+16 = 3217` bytes.
- Because all nonces, salts, ephemeral keys, and ciphertexts are effectively random, the entire file passes statistical randomness tests (tested with `dieharder`).

---

## 🔄 Encryption Flow (Step‑by‑Step)

1. **Read input file size** (using `stat()`).
2. **Generate hybrid ephemeral key pair** (Kyber‑1024 + X25519).
3. **Derive a 32‑byte key from the password** using Argon2id (salt generated).
4. **Prepare the hybrid private key with a leading cipher flag**:
   - `flag = 0x00` (AES) or `0x01` (Obscurity)
   - `plain_hybrid = flag || kyber_sk || x25519_sk`
5. **Encrypt `plain_hybrid` with AES‑256‑GCM** (using a fresh nonce) – the result is `enc_sk_cipher`.
6. **Write to output file**:  
   - salt (16)  
   - nonce for step 5 (12)  
   - `enc_sk_cipher` (3217 bytes)
7. **Encapsulate a 32‑byte file key** using the public side of the hybrid key pair:  
   - obtain `kyber_ct` and `kyber_ss`  
   - generate ephemeral X25519 key pair, compute `x25519_ss`  
   - `file_key = BLAKE2b(kyber_ss || x25519_ss)`
8. **Write to output file**:  
   - `kyber_ct` (1568)  
   - X25519 ephemeral public key (32)
9. **Generate a fresh nonce** for the symmetric cipher (12 or 16 bytes, depending on cipher). Write it.
10. **Encrypt the input file in 1 MiB chunks** with the selected cipher and `file_key`, writing ciphertext chunks to the output.
11. **Write the authentication tag** (16 bytes) at the end.
12. **Zero out all sensitive buffers** (`mlock`ed memory) and close files.

---

## 🔄 Decryption Flow (Step‑by‑Step)

1. **Open encrypted file**.
2. **Read salt, nonce, and `enc_sk_cipher`** (header length known and fixed).
3. **Derive the same 32‑byte key from the password** (using the salt).
4. **Decrypt `enc_sk_cipher`** to obtain `flag || kyber_sk || x25519_sk`.
5. **Read Kyber ciphertext and X25519 ephemeral public key** from the file.
6. **Decapsulate the file key**:
   - `kyber_ss = Kyber.Decap(kyber_ct, kyber_sk)`
   - `x25519_ss = X25519(x25519_sk, eph_pub)`
   - `file_key = BLAKE2b(kyber_ss || x25519_ss)`
7. **Read the cipher‑specific nonce** (length determined by the flag).
8. **Determine the remaining ciphertext size** (including the final tag).
9. **Stream‑decrypt the data** using the selected cipher and `file_key`, writing plaintext to the output file.
10. **Verify the authentication tag** (fails if wrong password or file tampering).
11. **Zero out all sensitive buffers** and close files.

**Note**: The decryption side automatically selects the correct symmetric cipher based on the flag embedded in the hybrid private key – no external metadata is needed.

---

## 🛡️ Security Features (Implemented)

| Feature                         | Implementation                                                                                                                                 |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| **Indistinguishability**        | No magic bytes, no fixed headers; all fields are `randombytes` or pseudorandom cryptographic output.                                          |
| **Memory locking**              | `sodium_mlock()` for keys and hybrid private key, `sodium_munlock()` after zeroisation.                                                        |
| **Constant‑time operations**    | OpenSSL AES‑GCM and libsodium’s BLAKE2b are constant‑time. The Obscurity cipher uses only ARX and bitwise ops, no secret‑dependent branches.  |
| **Signal safety**               | `SIGINT`/`SIGTERM` handlers use `_Exit()` and remove output file; terminal restored.                                                          |
| **AEAD integrity**              | AES‑GCM and sponge tag provide authenticated encryption; wrong password or corruption causes explicit failure.                                |
| **Secure zeroisation**          | `sodium_memzero()` and `sodium_mlock`/`munlock` ensure keys are erased from memory.                                                          |
| **No core dumps**               | The program disables core dumps (`prctl(PR_SET_DUMPABLE,0)`) and uses `madvise(MADV_DONTDUMP)` on locked memory.                              |

---

## ⚙️ Compilation & Usage

### Dependencies

- **libsodium** (crypto primitives, random, mlock, AEAD)
- **libargon2** (Argon2id key derivation)
- **OpenSSL** (EVP for AES‑256‑GCM)
- **Kyber reference implementation** (provided in `kyber/ref`)

### Build Steps

```bash
# Build Kyber‑1024 static library
cd kyber/ref
gcc -O2 -fPIC -DKYBER_K=4 -c *.c
ar rcs libpqcrystals_kyber1024_ref.a *.o
cd ../..

# Compile Light Encryption Utility
gcc -O2 -Wall -Wextra -Ikyber/ref -o light light.c \
    kyber/ref/libpqcrystals_kyber1024_ref.a \
    -lssl -lcrypto -lsodium -largon2
```

### Running

```bash
./light
```

Interactive menu:
```
1. Encrypt a file
2. Decrypt a file
3. Toggle password visibility
4. Settings
5. Exit
```

**Settings** allow you to toggle between **AES‑256‑GCM** and **Obscurity** cipher for future encryptions. Existing files are automatically decrypted with the correct cipher (because the flag is stored inside the encrypted blob).

### Example

```
Input file: secret.txt
Output file: secret.bin
Password: (hidden)
[Encrypting (AES-256-GCM)] 100% - 123.45 MB/s
File encrypted successfully: secret.bin
```

---

## ⚠️ Threat Model & Limitations

- **Assumes** the user’s system is not compromised before/after encryption.
- **Does not protect** file names, timestamps, or directory structure (those must be handled by the user).
- **Does not include** forward secrecy – the file key is stored (encrypted) in the file header.
- **Obscurity cipher** is **NOT** peer‑reviewed and should be considered **untrusted** for genuine high‑assurance applications. It is a simulation placeholder for a classified algorithm.

**Do not use this utility for actual sensitive data unless you fully understand and accept the risks.** This is a research prototype.

---

## 📜 License & Acknowledgment

This software is provided **as is**, for educational and simulation purposes only. No warranty, express or implied, is given. The Kyber reference implementation is from the [pq-crystals/kyber](https://github.com/pq-crystals/kyber) repository; libsodium, OpenSSL, and Argon2 are open‑source libraries.

---

*Document version 1.0 – last updated 2026‑04‑24*
