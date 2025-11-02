# pqc-combo v0.0.2 — Hardened Minimalist Post-Quantum Cryptography Core 🛡️

[](https://github.com/AaronSchnacky1/pqc-combo/actions)
[](https://crates.io/crates/pqc-combo)

> **NIST Level 5 KEM + Level 3 Signatures**  
> **`no_std` + `no_alloc` by default**  
> **Zero heap. Zero warnings. Maximum security.**

The library is designed for `no_std` and `no_alloc` by default,
it's compatible with the standard library and dynamic memory allocation if needed.

A tiny, auditable PQC library for **firmware**, **secure boot**, **HSMs**, and **embedded systems**.

-----

## 📦 Installation & Usage

Add the following to your `Cargo.toml`.

```toml
# Secure embedded (recommended)
pqc-combo = "0.0.2"

# For alloc support (e.g., large messages)
pqc-combo = { version = "0.0.2", features = ["alloc"] }

# For std support (e.g., concurrency)
pqc-combo = { version = "0.0.2", features = ["std"] }
```

### Links

  * **Source Code:** [AaronSchnacky1/pqc-combo](https://github.com/AaronSchnacky1/pqc-combo)
  * **Crates.io:** [pqc-combo](https://crates.io/crates/pqc-combo)

-----

## 🛠️ Features

| Feature | Status |
| :--- | :--- |
| `no_std` | Supported |
| `no_alloc` | **Default** |
| `alloc` | Optional |
| `std` | Optional |
| Zeroize | Supported |
| Tampering detection | Supported |
| PQClean FFI | Supported |
| **Zero warnings** | Supported |

-----

## 🧪 Comprehensive Testing (v0.0.2)

`pqc-combo` is rigorously tested across all three of its feature configurations to ensure maximum reliability.

| Command | Environment |
| :--- | :--- |
| `cargo test` | **`no_std` + `no_alloc`** (Default) |
| `cargo test --features alloc` | **`no_std` + `alloc`** |
| `cargo test --features std` | **`std` + `alloc`** |

### Test Suite Coverage

Our test suite includes the following checks:

  * **Core Crypto:** Full round-trip success for Kyber KEM and Dilithium signatures.
  * **Input Variation:** Messages are tested with zero-length (`b""`), single-byte (`b"\x01"`), and large (1MB) payloads.
  * **Malformed Inputs:** Functions gracefully handle tampered ciphertexts, tampered signatures, and keys/ciphertexts of invalid byte lengths.
  * **Mismatched Keys:** Ensures verification fails when using the wrong public key and decapsulation fails when using the wrong secret key.
  * **Security Properties:** Verifies that Dilithium signatures are deterministic.
  * **State & Lifecycle:** All keys are checked for successful serialization and deserialization.
  * **Concurrency (`std` only):** Key generation, signing, and decapsulation are tested for thread-safety.

-----

### Embedded & Cross-Compilation

> This crate depends on `pqcrypto` libraries, which build C code.
> When cross-compiling (e.g., for `thumbv7em-none-eabihf`), you **must**
> have the corresponding C cross-compiler toolchain installed and available in your `PATH`.
>
> For ARM targets, you will typically need `arm-none-eabi-gcc`.