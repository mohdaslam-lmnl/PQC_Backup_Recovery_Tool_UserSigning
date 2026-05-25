# enc_app — Post-Quantum Hybrid Encryption with Passphrase, Shamir Sharding & ML-DSA Shard Signing

A production-safe standalone CLI plus **two separate local web tools** (backup and recovery) that implement a **KEM-DEM** design extended with a **user passphrase layer** and **ML-DSA (Dilithium3) signatures** on every shard:

- **ML-KEM 768** (NIST FIPS 203) encapsulation establishes the shared secret.
- A random **256-bit DEK** is generated per backup and encrypted under an ML-KEM-derived **KEK**.
- The **user passphrase** is combined with the DEK (via HKDF) to derive the **file encryption key** — so both the passphrase _and_ the ML-KEM secret key are required to decrypt the file.
- **Shamir Secret Sharing** (`threshold`-of-`total_shards`) is applied to the **ML-KEM-encrypted DEK** (`enc_aes_key`).
- Each shard is **self-contained** — it embeds all encryption parameters (`kem_ct`, nonces, data ciphertext) and carries a **Dilithium3 ML-DSA signature** over itself, eliminating the need for a separate "rest payload" file.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Installation](#installation)
- [Usage](#usage)
- [Shard File Format](#shard-file-format)
- [Module Reference](#module-reference)
- [Security Properties](#security-properties)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Threat Model & Limitations](#threat-model--limitations)
- [Project Structure](#project-structure)

---

## Overview

### Backup Pipeline

1. **ML-KEM 768 encapsulation** — against the recipient's public key: produces a **KEM ciphertext** (`kem_ct`) and a **32-byte shared secret**.
2. **KEK derivation** — `HKDF-SHA256(IKM=shared_secret, salt=none, info="aes-key-wrapping")` → **Key Encryption Key (KEK)**.
3. **DEK generation** — `OsRng` generates a random **32-byte Data Encryption Key (DEK)**.
4. **File key derivation** — `HKDF-SHA256(IKM=DEK, salt=SHA256(passphrase), info="backup-file-encryption")` → **file_key**. The passphrase is hashed to a fixed-length salt; the DEK is the IKM (high-entropy raw material).
5. **Data encryption** — `AES-256-GCM(key=file_key)` encrypts the user payload → `ciphertext` + `msg_nonce`.
6. **DEK wrapping** — `AES-256-GCM(key=KEK)` encrypts the raw DEK → `enc_aes_key` + `key_nonce`.
7. **Shamir sharding** — `enc_aes_key` is split into `total_shards` shares; any `threshold` reconstruct it.
8. **ML-DSA signing** — a fresh **Dilithium3** keypair is generated; each shard wire-bytes are signed together with the shared secret. Every resulting `SignedKeyShard` file is self-contained (embeds `params` + ML-DSA signature).

### Recovery Pipeline

1. Upload the **ML-KEM secret key** + **Dilithium3 signing public key** + at least `threshold` **shard files**.
2. Each shard signature is **verified** (ML-DSA) before any decryption is attempted.
3. Shards are **combined** (Shamir) → `enc_aes_key`.
4. **ML-KEM decapsulation** (`kem_ct` + secret key) → shared secret → `HKDF` → **KEK**.
5. `AES-256-GCM decrypt(KEK, enc_aes_key, key_nonce)` → **DEK**.
6. User enters **passphrase** → `HKDF-SHA256(IKM=DEK, salt=SHA256(passphrase))` → **file_key**.
7. `AES-256-GCM decrypt(file_key, ciphertext, msg_nonce)` → original data.

> **Both the ML-KEM secret key and the backup passphrase are required to decrypt.** Loss of either makes decryption impossible.

---

## Architecture

### Encryption (Backup)

```
User Passphrase ──SHA-256──▶ salt ──┐
                                    │   HKDF-SHA256
OsRng ──────────▶ DEK (32 B) ──IKM──┴──────────────▶ file_key
                  │                                       │
                  │                                       ▼
                  │                              AES-256-GCM(file_key)
                  │                                       │
                  │                               ciphertext + msg_nonce
                  │                               (user data encrypted)
                  │
ML-KEM 768 encaps(pk) ──▶ shared_secret + kem_ct
                                │
                         HKDF-SHA256 (info: "aes-key-wrapping")
                                │
                               KEK (32 B)
                                │
                    AES-256-GCM(KEK, DEK) ──▶ enc_aes_key + key_nonce
                                │
                     Shamir threshold-of-N
                                │
              ┌────────┬────────┬─── ··· ───┐
           shard 1  shard 2  shard 3      shard N
              │
              ▼  Each shard is signed (ML-DSA / Dilithium3):
          SignedKeyShard {
            index, total, threshold,
            data: base64(shard_bytes),
            params: { kem_ct, key_nonce, ciphertext, msg_nonce },
            encapsulation_key_b64,
            original_filename,
            signature: ML-DSA sign(shard_bytes ‖ shared_secret)
          }
```

### Decryption (Recovery)

```
≥ threshold SignedKeyShard files
        │
        ├── ML-DSA verify(shard_bytes ‖ shared_secret)  ← reject if any fails
        │
        ├── Shamir combine ──▶ enc_aes_key
        │
        ├── ML-KEM decaps(kem_ct, sk) ──▶ shared_secret
        │        │
        │   HKDF-SHA256 (info: "aes-key-wrapping")
        │        │
        │       KEK
        │        │
        │   AES-256-GCM decrypt(enc_aes_key, key_nonce)
        │        │
        │       DEK (32 B)
        │
User Passphrase ──SHA-256──▶ salt ──┐
                                    │   HKDF-SHA256
                    DEK ──IKM───────┴──────────────▶ file_key
                                                          │
                                          AES-256-GCM decrypt(ciphertext, msg_nonce)
                                                          │
                                                   Original data ✓
```

---

## Cryptographic Design

### Algorithm Selection

| Component              | Algorithm                 | Standard        | Key / Output Size           |
|------------------------|---------------------------|-----------------|-----------------------------|
| Key Encapsulation      | ML-KEM 768                | NIST FIPS 203   | SS: 32 B, CT: 1088 B        |
| Symmetric Encryption   | AES-256-GCM               | NIST SP 800-38D | Key: 32 B, Nonce: 12 B      |
| KEK Derivation         | HKDF-SHA256               | RFC 5869        | IKM: shared_secret (32 B)   |
| File Key Derivation    | HKDF-SHA256               | RFC 5869        | IKM: DEK, Salt: SHA256(pass)|
| Key Sharding           | Shamir SS (GF 2⁸)         | Shamir 1979     | ≤ 255 shards, any threshold |
| Shard Signing          | ML-DSA (Dilithium3)       | NIST FIPS 204   | Sign key: 4 KB, Sig: ~3.3 KB|
| Passphrase Hashing     | SHA-256                   | FIPS 180-4      | 32-byte salt for HKDF       |
| Encoding               | Base64 (standard)         | RFC 4648        | —                           |

### Key Hierarchy

```
ML-KEM 768 Keypair
    │
    ├── Public key (1184 B)  →  backup: encapsulation input
    └── Secret key (2400 B)  →  recovery: kem_ct decapsulation
              │
              ▼
        ML-KEM Shared Secret (32 B)
              │
              ▼  HKDF-SHA256 (IKM=SS, salt=none, info="aes-key-wrapping")
        Key Encryption Key / KEK (32 B)
              │
              ▼  AES-256-GCM(KEK) encrypts DEK
        enc_aes_key (~48 B, includes 16-B GCM tag)
              │
              ▼  Shamir t-of-N
        shard 1 … shard N

OsRng ──▶ DEK (32 B, random per backup)
              │
User Passphrase ──SHA-256──▶ 32-B salt
              │
              ▼  HKDF-SHA256 (IKM=DEK, salt=SHA256(passphrase), info="backup-file-encryption")
        file_key (32 B)
              │
              ▼  AES-256-GCM(file_key) encrypts user payload
        ciphertext + msg_nonce
```

### Two HKDF Invocations

| Purpose     | IKM            | Salt                  | Info                      | Output    |
|-------------|----------------|-----------------------|---------------------------|-----------|
| KEK         | ML-KEM SS (32 B) | none (0x00…00)      | `"aes-key-wrapping"`      | KEK 32 B  |
| file_key    | DEK (32 B)     | SHA-256(passphrase)   | `"backup-file-encryption"`| key 32 B  |

**Why passphrase as HKDF salt and DEK as IKM?**

HKDF's extract step is `PRK = HMAC-SHA256(salt, IKM)`. By making the passphrase the HMAC key (salt), a wrong passphrase at recovery yields a completely different PRK and therefore a different `file_key` — decryption fails at the AES-GCM authentication tag. The DEK (high-entropy random) is the IKM, which is the cryptographically appropriate role.

---

## Installation

### Prerequisites

- **Rust toolchain** ≥ 1.70.0 (edition 2021)
- **C compiler** (`gcc` / `clang`) for `pqcrypto` native bindings

### Build

```bash
cargo build            # debug
cargo build --release  # optimised (binary at target/release/enc_app)
```

---

## Usage

### Quick Demo

```bash
cargo run -- demo
```

Runs a full keygen → encrypt → verify → decrypt roundtrip.

### Generate Keypair

```bash
cargo run -- keygen
# Writes pk.b64 (ML-KEM public key) and sk.b64 (ML-KEM secret key)
```

| File     | Contents                        | Size     |
|----------|---------------------------------|----------|
| `pk.b64` | ML-KEM 768 public key (base64)  | ~1580 B  |
| `sk.b64` | ML-KEM 768 secret key (base64)  | ~3200 B  |

> **⚠️ Security**: Protect `sk.b64` — it is required for recovery.

### Encrypt (CLI)

```bash
# Inline data, signed shards to a directory (default 2-of-3)
cargo run -- encrypt --pk pk.b64 --passphrase "my-passphrase" \
    --data '{"name":"Alice"}' --shards-dir ./shards/

# Custom Shamir parameters (3-of-5)
cargo run -- encrypt --pk pk.b64 --passphrase "pw" \
    --data '{"name":"Alice"}' --shards-dir ./shards/ \
    --threshold 3 --total-shares 5

# From stdin
cat document.json | cargo run -- encrypt --pk pk.b64 --passphrase "pw"
```

| Flag             | Required | Description                                                    |
|------------------|----------|----------------------------------------------------------------|
| `--pk`           | Yes      | ML-KEM public key file path                                    |
| `--passphrase`   | Yes      | Backup passphrase (combined with random DEK to derive file key)|
| `--data`         | No       | Plaintext string; reads stdin if omitted                       |
| `-o/--output`    | No       | Output file for the signed-shard array (stdout if omitted)     |
| `--shards-dir`   | No       | Directory to write one `*.shard{n}.json` file per shard        |
| `--threshold`    | No       | Shamir recovery threshold (default: 2)                         |
| `--total-shares` | No       | Total shards (default: 3)                                      |

The `--shards-dir` output also writes `{basename}.sign_pk.b64` — save this; it is required at recovery.

### Decrypt (CLI)

```bash
# From signed shard files (requires --sign-pk)
cargo run -- decrypt --sk sk.b64 --passphrase "my-passphrase" \
    --sign-pk ./shards/backup.sign_pk.b64 \
    --shard ./shards/backup.shard1.json \
    --shard ./shards/backup.shard2.json
```

| Flag           | Required | Description                                               |
|----------------|----------|-----------------------------------------------------------|
| `--sk`         | Yes      | ML-KEM secret key file path                               |
| `--passphrase` | Yes      | Same passphrase used at backup time                       |
| `--sign-pk`    | Yes (for signed shards) | Dilithium3 signing public key file         |
| `--shard`      | Repeatable | Signed shard JSON files (at least `threshold` required) |
| `-i/--input`   | No       | JSON file containing a shard array or legacy envelope      |

### Web Tools

**Backup tool** (port 8081) — 4-step wizard:

| Step | Action |
|------|--------|
| 1    | Paste the ML-KEM **public key** (base64) |
| 2    | Upload the **.json file** to encrypt |
| 3    | Enter **passphrase** + choose Shamir parameters (total shards / threshold) |
| 4    | Dilithium3 signing keypair is auto-generated; click **Encrypt** → download the **signing public key** and each **signed shard file** |

```bash
cargo run -- backup-server          # http://localhost:8081
cargo run -- backup-server --port 8081
```

**Recovery tool** (port 8082) — 4-step wizard:

| Step | Action |
|------|--------|
| 1    | Paste the ML-KEM **secret key** (base64) |
| 2    | Paste or upload the **Dilithium3 signing public key** |
| 3    | Upload and **verify** each shard file (click _Verify shard_ between files) |
| 4    | Enter the **backup passphrase** → click **Decrypt** |

```bash
cargo run -- recovery-server          # http://localhost:8082
cargo run -- recovery-server --port 8082
```

---

## Shard File Format

Every shard file is a **self-contained** `SignedKeyShard` JSON — no separate "rest payload" file is needed:

```json
{
  "index": 1,
  "total": 3,
  "threshold": 2,
  "data": "<base64 — Shamir share of enc_aes_key>",
  "params": {
    "kem_ct":     "<base64 — ML-KEM 768 ciphertext (1088 B)>",
    "key_nonce":  "<base64 — AES-GCM nonce for DEK encryption (12 B)>",
    "ciphertext": "<base64 — AES-GCM encrypted user data>",
    "msg_nonce":  "<base64 — AES-GCM nonce for data encryption (12 B)>"
  },
  "encapsulation_key_b64": "<base64 — ML-KEM public key used at backup>",
  "original_filename": "document.json",
  "signature": "<base64 — Dilithium3 detached signature over shard_bytes ‖ shared_secret>"
}
```

| Field                   | Raw size             | Description                                             |
|-------------------------|----------------------|---------------------------------------------------------|
| `data`                  | varies               | Shamir share wire bytes of `enc_aes_key`                |
| `params.kem_ct`         | 1088 B               | ML-KEM 768 KEM ciphertext                               |
| `params.key_nonce`      | 12 B                 | Nonce used to AES-GCM-encrypt the DEK                   |
| `params.ciphertext`     | `len(data) + 16` B   | AES-GCM encrypted user payload (includes 16-B auth tag) |
| `params.msg_nonce`      | 12 B                 | Nonce used to AES-GCM-encrypt user data                 |
| `signature`             | ~3293 B              | Dilithium3 detached signature                           |

> **Note**: `enc_aes_key` (the ML-KEM-wrapped DEK) is never stored in cleartext. It is reconstructed by combining ≥ `threshold` shards and decrypted with the ML-KEM-derived KEK.

---

## Module Reference

### `main.rs` — CLI, Pipelines, Integration Tests

| Function / type                    | Description |
|------------------------------------|-------------|
| `encrypt_signed_backup_artifacts`  | Full backup pipeline: keygen → DEK → file_key(passphrase+DEK) → data encrypt → DEK wrap → shard → sign each shard. |
| `decrypt_from_signed_shards`       | Verify ML-DSA signatures → combine shards → ML-KEM decapsulate → KEK → DEK → file_key(passphrase+DEK) → decrypt. |
| `verify_signed_shard`              | Verify one ML-DSA shard signature. |
| `decrypt_with_shards`              | Low-level: Shamir combine → KEK path → file_key path → AES-GCM decrypt. |
| `decrypt_from_rest`                | Legacy: validates RestPayload against shards, then `decrypt_with_shards`. |
| `ensure_signed_shards_consistent`  | Validates all shards carry identical embedded params. |
| Subcommands                        | `keygen`, `encrypt`, `decrypt`, `demo`, `backup-server`, `recovery-server` |

### `crypto.rs` — AES-256-GCM & HKDF

| Function                | Signature                                                                    | Description |
|-------------------------|------------------------------------------------------------------------------|-------------|
| `derive_key`            | `fn(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>>`                   | HKDF-SHA256 (`IKM=shared_secret`, `salt=none`, `info="aes-key-wrapping"`) → KEK. |
| `derive_backup_file_key`| `fn(dek: &[u8; 32], passphrase: &str) -> Result<Zeroizing<[u8; 32]>>`      | HKDF-SHA256 (`IKM=dek`, `salt=SHA256(passphrase)`, `info="backup-file-encryption"`) → file_key. |
| `encrypt`               | `fn(aes_key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])>`  | AES-256-GCM with a random `OsRng` nonce. Returns `(ciphertext_with_tag, nonce)`. |
| `decrypt`               | `fn(aes_key: &[u8; 32], ct: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>>`  | AES-256-GCM decrypt + authenticate. |

### `kem.rs` — ML-KEM 768

| Function          | Returns                        | Description |
|-------------------|--------------------------------|-------------|
| `keygen`          | `(Vec<u8>, Vec<u8>)`          | Generate ML-KEM 768 keypair `(pk, sk)`. |
| `encapsulate_key` | `Result<(Vec<u8>, Vec<u8>)>`  | Encapsulate against `pk`. Returns `(kem_ct, shared_secret)`. |
| `decapsulate_key` | `Result<Vec<u8>>`             | Decapsulate `kem_ct` with `sk`. Returns `shared_secret`. |

### `sign.rs` — ML-DSA (Dilithium3) Signatures

| Function               | Description |
|------------------------|-------------|
| `keygen`               | Generate a Dilithium3 (ML-DSA) signing keypair `(sign_pk, sign_sk)`. |
| `sign_message`         | Sign a message with a Dilithium3 secret key. |
| `verify_message`       | Verify a Dilithium3 signature. Fails if tampered. |
| `shard_signing_message`| Construct the canonical message `shard_wire_bytes ‖ shared_secret` used for signing/verifying each shard. |

### `sharding.rs` — Shamir Secret Sharing

| Function              | Description |
|-----------------------|-------------|
| `validate_sharding`   | Ensures `1 ≤ threshold ≤ total_shares ≤ 255`. |
| `split_secret`        | Dealer produces `total_shares` GF(2⁸) shares. |
| `combine_shares`      | Lagrange recovery from any `threshold` distinct shares; rejects duplicates. |

### `server_backup.rs` — Backup Web API (port 8081)

| Endpoint              | Method | Body / Response |
|-----------------------|--------|-----------------|
| `/api/signing-keygen` | POST   | → `{ signing_public_key_b64, signing_secret_key_b64 }` |
| `/api/encrypt`        | POST   | `{ public_key_b64, signing_secret_key_b64, signing_public_key_b64, passphrase, plaintext, threshold, total_shards, original_filename? }` → `{ signing_public_key_b64, shards: [SignedKeyShard] }` |

### `server_recovery.rs` — Recovery Web API (port 8082)

| Endpoint           | Method | Body / Response |
|--------------------|--------|-----------------|
| `/api/verify-shard`| POST   | `{ secret_key_b64, signing_public_key_b64, shard }` → `{ valid, threshold, total_shards, message }` |
| `/api/decrypt`     | POST   | `{ secret_key_b64, signing_public_key_b64, passphrase, shards: [SignedKeyShard] }` → `{ plaintext, original_filename? }` |

### `errors.rs` / `utils.rs`

`AppError` covers every failure mode (`KemEncapsulationFailed`, `AesDecryptionFailed`, `ShardingFailed`, `RecoveryFailed`, `SignatureVerificationFailed`, etc.).  
`utils::{b64e, b64d}` — standard base64 encode / decode.

---

## Security Properties

| Property                       | Mechanism |
|--------------------------------|-----------|
| **Confidentiality**            | AES-256-GCM with a file_key derived from DEK + passphrase |
| **Integrity & Authenticity**   | AES-GCM 128-bit auth tags on both layers; ML-DSA signature on every shard |
| **Post-Quantum Security**      | ML-KEM 768 (NIST Level 3, IND-CCA2); ML-DSA Dilithium3 (NIST Level 3, EUF-CMA) |
| **Dual-Factor Recovery**       | Requires ML-KEM secret key **and** backup passphrase |
| **Shard Integrity**            | Dilithium3 signature over `shard_bytes ‖ shared_secret` catches tampering or substitution |
| **Forward Secrecy**            | Fresh DEK per backup; fresh ML-KEM encapsulation per backup |
| **Key Zeroization**            | `Zeroizing<>` wrappers erase DEK, KEK, and file_key from memory on drop |
| **CSPRNG**                     | `OsRng` (OS-level CSPRNG) for all randomness |
| **Distributed Key Custody**    | Shamir: any single shard reveals zero information about `enc_aes_key` (information-theoretic, GF(2⁸)) |
| **Fault Tolerance**            | Up to `total_shards − threshold` shards can be lost; recovery still possible |

---

## Testing

```bash
cargo test
```

38 tests cover: ML-KEM roundtrips, AES-GCM roundtrips and tamper detection, HKDF correctness (passphrase mismatch → different key), Shamir split/combine (all subsets, duplicates, below-threshold), ML-DSA sign/verify + tamper detection, full encrypt/decrypt integration (signed + unsigned), HTTP API (passphrase required, correct vs. wrong passphrase, blank passphrase rejected).

---

## Dependencies

| Crate              | Version | Purpose |
|--------------------|---------|---------|
| `pqcrypto-mlkem`   | 0.1     | ML-KEM 768 (NIST FIPS 203) |
| `pqcrypto-dilithium`| 0.5   | Dilithium3 / ML-DSA (NIST FIPS 204) |
| `pqcrypto-traits`  | 0.3     | Trait interfaces for PQCrypto types |
| `aes-gcm`          | 0.10    | AES-256-GCM authenticated encryption |
| `hkdf`             | 0.12    | HKDF-SHA256 key derivation |
| `sha2`             | 0.10    | SHA-256 (HKDF inner hash + passphrase salt) |
| `rand`             | 0.8     | `OsRng` CSPRNG |
| `zeroize`          | 1       | Secure key erasure |
| `serde` / `serde_json` | 1.0 | Serialization |
| `base64`           | 0.21    | Base64 encode/decode |
| `clap`             | 4       | CLI argument parsing |
| `thiserror`        | 1.0     | Error type derivation |
| `actix-web`        | 4       | HTTP server |
| `actix-cors`       | 0.7     | CORS middleware |
| `actix-files`      | 0.6     | Static file serving |
| `tokio`            | 1       | Async runtime |
| `sharks`           | 0.5     | Shamir Secret Sharing over GF(2⁸) |

---

## Threat Model & Limitations

### In Scope

- Encryption of JSON data at rest with post-quantum security
- Dual-factor recovery (ML-KEM secret key + passphrase)
- Tamper detection on ciphertext, wrapped DEK, nonces, and every shard (ML-DSA)
- Distributed shard custody with configurable threshold

### Limitations

| Limitation                    | Explanation |
|-------------------------------|-------------|
| **No key storage encryption** | `sk.b64` is stored as plaintext. In production, protect it with a passphrase (e.g. Argon2+AES) or an HSM. |
| **Passphrase not stretched**  | The passphrase enters HKDF directly (via SHA-256 for the salt). For low-entropy passphrases, consider Argon2 pre-processing before calling HKDF. |
| **No key rotation**           | Each keypair is static; implement versioning for long-lived deployments. |
| **No multi-recipient**        | Single public key per encryption; encapsulate separately per recipient for multi-recipient scenarios. |
| **No streaming**              | Entire plaintext is loaded into memory; use chunked encryption for files > 1 GB. |
| **No X25519 hybrid**          | Uses ML-KEM only. A defense-in-depth system may combine ML-KEM with X25519. |

---

## Project Structure

```
enc_app/
├── Cargo.toml
├── Cargo.lock
├── pk.b64                # ML-KEM public key (after keygen)
├── sk.b64                # ML-KEM secret key (protect this!)
├── static_backup/        # Backup web tool (wizard UI)
│   ├── app.js
│   ├── index.html
│   └── style.css
├── static_recovery/      # Recovery web tool
│   ├── app.js
│   ├── index.html
│   └── style.css
└── src/
    ├── main.rs           # CLI, data structures, encrypt/decrypt pipelines, tests
    ├── kem.rs            # ML-KEM 768 keygen / encapsulate / decapsulate
    ├── crypto.rs         # AES-256-GCM encrypt/decrypt, HKDF (KEK + file_key)
    ├── sharding.rs       # Shamir SS — parameterised split / combine
    ├── sign.rs           # Dilithium3 (ML-DSA) keygen / sign / verify
    ├── server_backup.rs  # Actix backup server — /api/signing-keygen, /api/encrypt
    ├── server_recovery.rs# Actix recovery server — /api/verify-shard, /api/decrypt
    ├── errors.rs         # AppError enum (thiserror)
    └── utils.rs          # Base64 helpers (b64e / b64d)
```

---

## License

*Specify your license here.*
