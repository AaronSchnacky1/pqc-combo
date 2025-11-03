[![CI Status](https://github.com/AaronSchnacky1/pqc-combo/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronSchnacky1/pqc-combo/actions)
pqc-combo v0.0.3 — 18 hardening tests across all three environments

NIST Kyber L5 + Dilithium L3.
Zero heap. Zero warnings. Maximum security.

no_std + no_alloc by default  
The library is designed for no_std and no_alloc by default,
it's compatible with the standard library and dynamic memory allocation if needed.

A tiny, auditable PQC library for firmware, secure boot, HSMs, and embedded systems.

📦 Installation & Usage

Add the following to your Cargo.toml.

# Secure embedded (recommended)
pqc-combo = "0.0.3"

# For alloc support (e.g., large messages)
pqc-combo = { version = "0.0.3", features = ["alloc"] }

# For std support (e.g., concurrency)
pqc-combo = { version = "0.0.3", features = ["std"] }




Links

  * Source Code: AaronSchnacky1/pqc-combo
  * Crates.io: pqc-combo

🛠️ Features

Feature

Status

no_std

Supported

no_alloc

Default

alloc

Optional

std

Optional

Zeroize

Supported

Tampering detection

Supported

PQClean FFI

Supported

Zero warnings

Supported

🧪 Comprehensive Testing (v0.0.3)

pqc-combo is rigorously tested across all three of its feature configurations to ensure maximum reliability.

Command

Environment

cargo test

no_std + no_alloc (Default)

cargo test --no-default-features --features alloc

no_std + alloc

cargo test --features std

std + alloc

Test Suite Coverage

This release integrates 8 new hardening tests (for a total of 18) to validate cryptographic security, API robustness, and lifecycle management. The suite now includes:

  * Core Crypto: Full round-trip success for Kyber KEM and Dilithium signatures.
  * Input Variation: Messages are tested with zero-length (b""), single-byte (b"\x01"), and large (1MB) payloads (alloc only).
  * Mismatched Keys: Ensures verification fails when using the wrong public key and decapsulation fails when using the wrong secret key.
  * Concurrency (std only): Key generation, signing, and decapsulation are tested for thread-safety.
 
  * NEW - Malformed Inputs: Crypto operations are proven to gracefully fail with:
    * Tampered ciphertexts & signatures
    * All-zero (default) keys and signatures
    * Cryptographically random (garbage) keys
  * NEW - API Misuse: Functions correctly handle invalid data, such as:
    * Keys/ciphertexts of invalid byte lengths
    * Empty byte slices (no_std only)
  * NEW - Security Properties:
    * Verifies that Dilithium signatures are deterministic.
    * Verifies that Kyber KEM is non-deterministic (std only).
  * NEW - State & Lifecycle:
    * All key types are checked for successful serialization/deserialization.
    * All ciphertext & signature types are checked for successful serialization/deserialization (std only).

Embedded & Cross-Compilation

This crate depends on pqcrypto libraries, which build C code.
When cross-compiling (e.g., for thumbv7em-none-eabihf), you must
have the corresponding C cross-compiler toolchain installed and available in your PATH.

For ARM targets, you will typically need arm-none-eabi-gcc.
