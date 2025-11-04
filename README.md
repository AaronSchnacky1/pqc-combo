[![CI Status](https://github.com/AaronSchnacky1/pqc-combo/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronSchnacky1/pqc-combo/actions)
# pqc-combo v0.0.5 — NIST Kyber L5 + Dilithium L3 + AES-256-GCM

**21 hardening tests across all feature combinations**  
**Zero heap. Zero warnings. Maximum security.**

```toml
# Secure embedded (PQC only)
pqc-combo = "0.0.5"

# Secure embedded (Hybrid PQC + AES-GCM)
pqc-combo = { version = "0.0.5", features = ["aes-gcm"] }

# For alloc support (e.g., large messages)
pqc-combo = { version = "0.0.5", features = ["alloc", "aes-gcm"] }

# For std support (e.g., concurrency, auto-RNG, FFI)
pqc-combo = { version = "0.0.5", features = ["std", "aes-gcm"] }
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
| **Ecosystem (Interop)** | Deferred | Pure-Rust `kyber-rs` and `dilithium` crates are unstable pre-releases. Interop testing blocked. |
| **Usability (FFI)** | Achieved | C-compatible `.dll`/`.so` built. **Rust FFI test** passes using `libloading`. No Python needed. |
| **Security (Fuzzing)** | Ready | `cargo fuzz` harness prepared. Finds panics on garbage input. |

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

---

## Comprehensive Testing (v0.0.5)

Run these commands from the repository root:

```bash
cargo test                                # no_std + no_alloc (15 tests)
cargo test --features aes-gcm             # + aes-gcm (16 tests)
cargo test --no-default-features --features "alloc,aes-gcm"  # + alloc (20 tests)
cargo test --features "std,aes-gcm"       # Full (21 tests)
```

**Test Suite Coverage**:
- Full round-trip: Kyber KEM, Dilithium signatures, AES-GCM
- Input variation: zero-length, single-byte, 1MB payloads
- Mismatched keys, malformed inputs, API misuse
- Concurrency (std only), serialization round-trip
- **Tampering detection** verified

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
```