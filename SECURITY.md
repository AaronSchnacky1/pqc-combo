Security Model 🛡️

The pqc-combo library is designed to offer maximum security and auditability, targeting resource-constrained environments where security is critical.

Algorithms: All primitives are sourced from the PQClean project via the pqcrypto crates, providing NIST-standardized implementations (FIPS 203 & FIPS 204).

Memory Safety: no_std + no_alloc by default enforces zero heap usage, eliminating side channels related to dynamic memory allocation.

Key Protection: Sensitive keys are automatically wiped using the zeroize trait upon drop.

Rust Safety: The library contains no user-written unsafe Rust, relying solely on minimal, generated FFI bindings to the audited C implementations.

Tampering Detection: Ciphertext tampering detection is available when the alloc feature is enabled (verified by unit test).

Threat Model

Threat

Mitigated?

Notes

Quantum Attack

Yes

Uses ML-KEM (Kyber1024, NIST Level 5) and ML-DSA (Dilithium3, NIST Level 3).

Side-channel (Timing)

Yes

Relies on the constant-time design of the underlying PQClean C implementations.

Heap Overflow/Poison

Yes

Enforced by no_alloc default. Dynamic memory is disabled unless the alloc feature is used.

Key Leakage

Yes

SecretKey structures are automatically zeroized on drop.

Supply Chain

Partially

All code is publicly reviewable, and FFI bindings are kept minimal.

Verification (v0.0.3) ✅

The core components have been verified by a suite of 18 tests across all three feature combinations (no_std, no_std + alloc, and std).

Core Crypto: Full round-trip success for Kyber KEM and Dilithium signatures.

Input Variation: Messages are tested with zero-length (b""), single-byte (b"\x01"), and large (1MB) payloads (alloc only).

Mismatched Keys: Ensures verification fails when using the wrong public key and decapsulation fails when using the wrong secret key.

Concurrency (std only): Key generation, signing, and decapsulation are tested for thread-safety.

Malformed Inputs: Crypto operations are proven to gracefully fail with:

Tampered ciphertexts & signatures

All-zero (default) keys and signatures

Cryptographically random (garbage) keys

API Misuse: Functions correctly handle invalid data, such as:

Keys/ciphertexts of invalid byte lengths

Empty byte slices (no_std only)

Security Properties:

Verifies that Dilithium signatures are deterministic.

Verifies that Kyber KEM is non-deterministic (std only).

State & Lifecycle:

All key types are checked for successful serialization/deserialization.

All ciphertext & signature types are checked for successful serialization/deserialization (std only).

Last updated: November 2, 2025