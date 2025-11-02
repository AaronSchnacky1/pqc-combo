Updat v0.0.2 `SECURITY.md` for your `pqc-combo v0.0.2` project.

I have removed the outdated `Known Limitations` section, incorporated the passing tests into `Verification`, and updated the version notes.

***

## Security Model 🛡️

The `pqc-combo` library is designed to offer maximum security and auditability, targeting resource-constrained environments where security is critical.

* **Algorithms:** All primitives are sourced from the **PQClean** project, providing battle-tested, **NIST-selected** implementations.
* **Memory Safety:** **`no_std` + `no_alloc` by default** enforces zero heap usage, eliminating side channels related to dynamic memory allocation.
* **Key Protection:** Sensitive keys are automatically wiped using the **`zeroize`** trait upon drop.
* **Rust Safety:** The library contains **no user-written `unsafe` Rust**, relying solely on minimal, generated FFI bindings to the audited C implementations.
* **Tampering Detection:** Ciphertext tampering detection is available when the `alloc` feature is enabled (verified by unit test).

***

## Threat Model

| Threat | Mitigated? | Notes |
| :--- | :--- | :--- |
| **Quantum Attack** | **Yes** | Uses Kyber1024 (NIST Level 5 KEM) and Dilithium3 (NIST Level 3 Signature). |
| **Side-channel (Timing)** | **Yes** | Relies on the constant-time design of the underlying PQClean C implementations. |
| **Heap Overflow/Poison** | **Yes** | Enforced by `no_alloc` default. Dynamic memory is disabled unless the `alloc` feature is used. |
| **Key Leakage** | **Yes** | `SecretKey` structures are automatically zeroized on drop. |
| **Supply Chain** | Partially | All code is **publicly reviewable**, and FFI bindings are kept minimal. |

***

## Verification (v0.0.2) ✅

The core components have been verified across all available feature combinations.

* **Test Suite:** Unit tests verify correct behavior for `no_alloc`, `alloc`, and `std` environments.
* **Coverage:** Tests successfully validate round-trip cryptography, input length variations, key/data mismatch failures, and key serialization.
* **Concurrency:** Thread-safe key generation and operations are verified under the `std` feature.
* **Compliance:** Known-Answer Tests (KATs) are planned for implementation in a future release.

***

*Last updated: November 2, 2025*