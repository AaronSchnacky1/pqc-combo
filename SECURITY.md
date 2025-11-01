## Security Model

- **All crypto via PQClean** — battle-tested, NIST-selected
- **`no_std` + `no_alloc` by default** — no heap, no side channels from allocation
- **Zeroize** on sensitive keys
- **No unsafe Rust** (only FFI bindings)
- **Tampering detection** in KEM (test-only)

---

## Known Limitations

- `pqcrypto-dilithium 0.5.0` only supports **Dilithium3** (Level 3)
- Dilithium5 support planned for `v0.1.0`

---

## Threat Model

| Threat | Mitigated? | Notes |
|-------|------------|-------|
| Quantum attack | Yes | Kyber1024 (Level 5), Dilithium3 (Level 3) |
| Side-channel (timing) | Yes | Constant-time PQClean impl |
| Heap overflow | Yes | `no_alloc` by default |
| Key leakage | Yes | `zeroize` on drop |

---

## Verification

- All code is **publicly reviewable**
- FFI bindings are **minimal**
- Tests cover round-trip and tampering

---

*Last updated: October 31, 2025*