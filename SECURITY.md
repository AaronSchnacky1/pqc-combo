# Security Model
v0.0.5 — NIST Kyber L5 + Dilithium L3 + AES-256-GCM
**21 hardening tests across all feature combinations**  

## Algorithms

| Primitive | Source | Standard |
|---------|--------|----------|
| **ML-KEM (Kyber1024)** | PQClean via `pqcrypto-kyber` | FIPS 203 (Level 5) |
| **ML-DSA (Dilithium3)** | PQClean via `pqcrypto-dilithium` | FIPS 204 (Level 3) |
| **AES-256-GCM** | `aes-gcm` (RustCrypto) | NIST SP 800-38D |

---

## Memory Safety

- `no_std + no_alloc` by default → **zero heap usage**
- Eliminates heap overflow, use-after-free, side-channel leaks
- Dynamic memory only with `alloc` feature (opt-in)

---

## Key Protection

- `KyberSecretKey`, `DilithiumSecretKey`, `KyberSharedSecret` implement `zeroize::ZeroizeOnDrop`
- Sensitive data **automatically wiped** from memory on drop

---

## Rust Safety

- **No `unsafe` in user code**
- Only audited FFI bindings to PQClean C
- Pure-Rust `aes-gcm` crate (constant-time, AES-NI accelerated)

---

## Authenticated Encryption

- AES-GCM provides **built-in tampering detection**
- Tested in `no_alloc` (in-place) and `alloc` (heap) modes

---

## Threat Model

| Threat | Mitigated? | Notes |
|------|------------|-------|
| **Quantum Attack** | Yes | Kyber1024 (Level 5), Dilithium3 (Level 3) |
| **Side-channel (Timing)** | Yes | PQClean C impls are constant-time; `aes-gcm` uses AES-NI |
| **Heap Overflow/Poison** | Yes | `no_alloc` default |
| **Key Leakage** | Yes | `zeroize` on drop |
| **Supply Chain** | Partial | Minimal deps: PQClean + RustCrypto |
| **Garbage Input Panic** | Ready | Fuzzing harness included |

---

## Verification (v0.0.5)

**21 hardening tests** across all feature combinations:

- Core round-trip success
- Mismatched keys, malformed inputs
- API misuse, concurrency, serialization
- **Tampering detection** verified
- **FFI ABI compatibility** proven via `libloading`

---

**Security Confidence (Fuzzing):** Ready not performed

---

**Last updated: November 4, 2025**
```
| Goal | Achieved |
|------|----------|
| Post-Quantum Security | Yes |
| Memory Safety | Yes |
| Key Hygiene | Yes |
| Tamper Detection | Yes |
| FFI Safety | Yes |
| Fuzz-Ready | Yes |

---
