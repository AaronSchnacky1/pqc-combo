# `pqc-combo` — Minimalist Post-Quantum Cryptography Core

> **NIST Level 5 KEM + Level 3 Signatures**  
> **`no_std` + `no_alloc` by default**  
> **Zero heap. Zero warnings. Maximum security.**

The library is designed for no_std and no_alloc by default,
it is compatible with standard library and dynamic memory allocation if needed.

A tiny, auditable PQC library for **firmware**, **secure boot**, **HSMs**, and **embedded systems**.

---

## Features

| Feature | Status |
|-------|--------|
| `no_std` | Supported |
| `no_alloc` | **Default** |
| `alloc` | Optional (one test) |
| `std` | Optional (tests) |
| Zeroize | Supported |
| Tampering detection | Supported |
| PQClean FFI | Supported |
| **Zero warnings** | Supported |

---

## Usage

```toml
# Secure embedded (recommended)
pqc-combo = "0.0.1"

# Only if you need the tampering test
pqc-combo = { version = "0.0.1", features = ["alloc"] }
