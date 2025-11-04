[![CI Status](https://github.com/AaronSchnacky1/pqc-combo/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronSchnacky1/pqc-combo/actions)
# pqc-combo v0.0.6 — NIST Kyber L5 + Dilithium L3 + AES-256-GCM

**25 hardening tests across all feature combinations**  
**FIPS 203/204 compliance verified**  
**Zero heap. Zero warnings. Maximum security.**

```toml
# Secure embedded (PQC only)
pqc-combo = "0.0.6"

# Secure embedded (Hybrid PQC + AES-GCM)
pqc-combo = { version = "0.0.6", features = ["aes-gcm"] }

# For alloc support (e.g., large messages)
pqc-combo = { version = "0.0.6", features = ["alloc", "aes-gcm"] }

# For std support (e.g., concurrency, auto-RNG, FFI)
pqc-combo = { version = "0.0.6", features = ["std", "aes-gcm"] }
```

---

## Hybrid Encryption: AES-GCM

This crate supports **AES-256-GCM** via the `aes-gcm` feature, enabling a full **hybrid encryption** workflow:

```rust
let (kyber_ct, aes_key) = encapsulate_shared_secret(&pk);
let nonce = generate_aes_nonce(); // requires `std`
let ciphertext = encrypt_aes_gcm(&aes_key, &nonce, plaintext)?;
```

---

## Confidence Levels

| Confidence | Status | Details |
|----------|--------|-------|
| **Standards Compliance** | ✅ Verified | FIPS 203 ML-KEM-1024 (PK=1568, SK=3168, CT=1568, SS=32 bytes) |
| | | FIPS 204 ML-DSA-65 (PK=1952, SK=4032, Sig=3343 bytes) |
| **Usability (FFI)** | ✅ Achieved | C-compatible `.dll`/`.so` built. **Rust FFI test** passes using `libloading`. |
| **Security (Fuzzing)** | ✅ Ready | `cargo fuzz` harness prepared. Finds panics on garbage input. |

---

## Features

| Feature | Status |
|-------|--------|
| AES-256-GCM | Optional |
| `no_std` | Supported |
| `no_alloc` | Default |
| `alloc` | Optional |
| `std` | Optional |
| Zeroize | Supported |
| Tampering detection | Supported |
| C FFI | Supported |
| Zero warnings | Supported |
| FIPS 203/204 compliance | Verified |

---

## Comprehensive Testing (v0.0.6)

Run these commands from the repository root:

```bash
cargo test                                # no_std + no_alloc (15 tests)
cargo test --features aes-gcm             # + aes-gcm (16 tests)
cargo test --no-default-features --features "alloc,aes-gcm"  # + alloc (20 tests)
cargo test --features "std,aes-gcm"       # Full (25 tests: 21 unit + 4 integration)
```

**Test Suite Coverage**:
- Full round-trip: Kyber KEM, Dilithium signatures, AES-GCM
- Input variation: zero-length, single-byte, 1MB payloads
- Mismatched keys, malformed inputs, API misuse
- Concurrency (std only), serialization round-trip
- **Tampering detection** verified
- **FIPS 203/204 format compliance** verified (integration tests)
- **KEM and signature security properties** validated

---

## FIPS 203/204 Compliance

Integration tests (`tests/integration.rs`) verify compliance with NIST standards:

- ✅ ML-KEM-1024 (FIPS 203): Correct key, ciphertext, and shared secret sizes
- ✅ ML-DSA-65 (FIPS 204): Correct key and signature sizes
- ✅ KEM security: Encapsulation randomization, decapsulation correctness
- ✅ Signature security: Deterministic signing, verification correctness

```bash
cargo test --features std --test integration
```

---

## FFI Usage (C, Python, C#)

```bash
cargo build --release --features std
```

Produces:
- `target/release/libpqc_combo.so` (Linux/macOS)
- `target/release/pqc_combo.dll` (Windows)

**Rust FFI test** (`tests/ffi.rs`) proves ABI compatibility.

---

## Embedded & Cross-Compilation

Depends on PQClean C code. For cross-compilation (e.g. ARM):

```bash
# Install toolchain
sudo apt install gcc-arm-none-eabi

# Build
cargo build --target thumbv7em-none-eabihf --release --features std
```

---

## Source Code

- GitHub: [AaronSchnacky1/pqc-combo](https://github.com/AaronSchnacky1/pqc-combo)
- Crates.io: [pqc-combo](https://crates.io/crates/pqc-combo)

---

**Last updated: November 4, 2025**