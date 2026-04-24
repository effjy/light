# 🔐 Light Encryption Utility
> *Hybrid Post-Quantum KEM • Streaming AEAD • Suite A‑Style Simulation*  
> *Shining a little light… with a touch of Obscurity. 😉*

---

## ⚠️ Research & Simulation Disclaimer
**Light is a cryptographic research simulation**, not a production-ready tool for real-world sensitive data. It models the engineering characteristics of classified cryptographic systems (e.g., NSA Suite A), where:
- 🔒 Security intentionally relies on **both key secrecy and algorithmic secrecy**.
- 📜 Kerckhoffs's Principle is **not applied** to the custom `Obscurity` cipher.
- 📦 Output is designed to be **computationally indistinguishable from random noise** (zero magic bytes, uniform entropy).
- 🧪 Intended for **educational, closed-environment prototyping, and cryptographic agility research**.

---

## 🛡️ Threat Model & Security Features
| Feature | Implementation |
|---------|----------------|
| **Confidentiality & Integrity** | AES-256-GCM or custom Obscurity sponge cipher + 128-bit authentication tag |
| **Post-Quantum Key Transport** | Hybrid Kyber-1024 + X25519 KEM with BLAKE2b key derivation |
| **Password Wrapping** | Argon2id (`t=4`, `m=512 MiB`, `p=1`) + AES-256-GCM |
| **Memory Security** | `sodium_mlock()`, `sodium_memzero()`, secure wipe chains, zero swap leakage |
| **Forensic OpSec** | Signal-safe `SIGINT`/`SIGTERM` handler, auto-removes partial outputs, terminal echo restoration |
| **Large File Support** | O(1) memory streaming (1 MiB chunks), `fseeko`/`ftello` for >2 GiB files |
| **Zero Metadata Leakage** | No headers, magic bytes, or version tags. Cipher choice encrypted inside password blob |

---

## 🏗️ Cryptographic Architecture
```
┌─────────────────────────────────────────────────────────────┐
│  Encrypted File (Indistinguishable from Random Noise)       │
├─────────────┬──────────┬──────────────────┬─────────────────┤
│ Salt (16B)  │ Nonce(12)│ Key Blob (AES-GCM)│ KEM Ciphertexts │
│ (Argon2)    │ (Key Wr.)│ + Cipher Flag(1B)│ (Kyber+X25519)  │
├─────────────┴──────────┴──────────────────┴─────────────────┤
│ Cipher Nonce (12/16B) │ Streaming Ciphertext │ Auth Tag (16B)│
└─────────────────────────────────────────────────────────────┘
```
### 🔑 Key Design Notes
- **Auto-Detect Cipher**: A 1-bit flag (`0x00` = AES, `0x01` = Obscurity) is prepended to the hybrid secret key before password encryption. Decryption automatically selects the correct stream cipher without external configuration.
- **Constant-Time Dispatch**: Function pointer routing prevents timing side-channels that could leak cipher selection.
- **Safe I/O**: `safe_fread`/`safe_fwrite` loops handle partial reads/writes on slow disks, pipes, or network mounts.

---

## 📦 Build & Compile

### 1️⃣ Dependencies
```bash
# Ubuntu/Debian
sudo apt install build-essential libsodium-dev libargon2-0 libssl-dev

# macOS (Homebrew)
brew install libsodium argon2 openssl@3
```

### 2️⃣ Prepare Kyber Reference Implementation
```bash
mkdir -p kyber && cd kyber
git clone https://github.com/pq-crystals/kyber.git ref
cd ..
```

### 3️⃣ Compile Kyber Library
```bash
cd kyber/ref
gcc -O2 -fPIC -DKYBER_K=4 -c *.c
ar rcs libpqcrystals_kyber1024_ref.a *.o
cd ../..
```

### 4️⃣ Compile Light
```bash
gcc -O2 -Wall -Wextra -D_FILE_OFFSET_BITS=64 \
    -Ikyber/ref -o light light.c \
    kyber/ref/libpqcrystals_kyber1024_ref.a \
    -lssl -lcrypto -lsodium -largon2
```

---

## 🚀 Usage
Light uses an interactive TUI menu. Run:
```bash
./light
```

### 📋 Menu Options
| Option | Description |
|--------|-------------|
| `1`    | Encrypt a file (password + cipher selection applied) |
| `2`    | Decrypt a file (cipher auto-detected from encrypted blob) |
| `3`    | Toggle password visibility (ON/OFF) |
| `4`    | **Settings** → Switch between `AES-256-GCM` and `Obscurity` |
| `5`    | Exit |

### 💡 Workflow Example
```
=== Light Encryption Utility (Hybrid Kyber-1024 + X25519) ===
1. Encrypt a file
2. Decrypt a file
3. Toggle password visibility (currently OFF)
4. Settings
5. Exit
Choice: 1

Input file: secret_doc.pdf
Output file: secret_doc.enc
Password: ********

[Encrypting (Obscurity)] 100% - 42.18 MB/s
File encrypted successfully: secret_doc.enc
```
*Note: Decryption automatically detects whether AES or Obscurity was used. No manual flag required.*

---

## 🔍 Technical Highlights
- 🧵 **Streaming AEAD**: O(1) RAM usage. Safely handles multi-gigabyte files without memory exhaustion.
- 🛑 **Signal Safety**: `SIGINT`/`SIGTERM` triggers `_Exit(130)` + temp file cleanup + terminal restoration.
- 🔐 **KEM Combination**: Kyber-1024 + X25519 shared secrets combined via `crypto_generichash` (BLAKE2b) per NIST hybrid KEM best practices.
- 📉 **Page Cache Hygiene**: Ready for `posix_fadvise(POSIX_FADV_DONTNEED)` post-operation to drop plaintext/ciphertext from OS cache.
- 🧪 **Simulation Ready**: Clean abstraction layer for swapping experimental primitives without touching I/O or key management logic.

---

## 📜 License & Usage Terms
```
MIT License (Research / Simulation Use Only)

Copyright (c) 2026 Effjy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

⚠️ This code simulates classified cryptographic engineering patterns. 
It is NOT audited, NOT standardized, and NOT suitable for real-world 
operational security without formal cryptographic review.
```

---

## 🙏 Acknowledgments
- [pq-crystals/kyber](https://github.com/pq-crystals/kyber) – Reference KEM implementation
- [libsodium](https://libsodium.org/) – Modern crypto primitives & secure memory management
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) – Memory-hard password hashing
- OpenSSL – Streaming AEAD backend

*Built for research. Simulated for learning. Secured by design.* 🔐✨
