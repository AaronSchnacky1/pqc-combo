# FIPS 140-3 User Guide

This guide provides instructions for installing, configuring, and operating the **pqc-combo** cryptographic module in FIPS 140-3 Approved Mode.

---

## 1. Installation

Add the library to your `Cargo.toml` with the `fips_140_3` feature enabled:

```toml
[dependencies]
pqc-combo = { version = "0.1.0", features = ["fips_140_3"] }
```

**Note:** The `fips_140_3` feature is **REQUIRED** for FIPS Approved Mode. It enables:
*   Pre-Operational Self-Tests (POST)
*   Conditional Self-Tests (PCT)
*   Strict Critical Security Parameter (CSP) controls
*   State machine enforcement

---

## 2. Initialization

The module implements a Finite State Machine (FSM) as required by FIPS 140-3. You **MUST** transition the module from the `PowerOn` state to the `Operational` state before performing any cryptographic operations.

### 2.1 Running Self-Tests

Call `run_post()` or `run_post_or_panic()` at the very beginning of your application:

```rust
use pqc_combo::{run_post, run_post_or_panic};

fn main() {
    // Option 1: Handle errors gracefully
    if let Err(e) = run_post() {
        eprintln!("FIPS Self-Tests Failed: {:?}", e);
        std::process::exit(1);
    }

    // Option 2: Panic on failure (recommended for simple apps)
    run_post_or_panic();

    // Now the module is in 'Operational' state
    println!("Module initialized and ready.");
}
```

If you attempt to use any cryptographic function (KeyGen, Encrypt, Sign) *before* running `run_post()`, the module will panic or return an error indicating it is not in the Operational state.

---

## 3. Secure Operation

### 3.1 Key Generation

Always use the `_with_pct` variants of key generation functions. These ensure that a Pair-wise Consistency Test is performed on the generated keys.

**ML-KEM (Kyber):**
```rust
use pqc_combo::KyberKeys;

// CORRECT: Performs PCT
let keys = KyberKeys::generate_key_pair_with_pct().expect("KeyGen failed");

// INCORRECT (in FIPS mode):
// let keys = KyberKeys::generate_key_pair(); // Might not run PCT depending on config
```

**ML-DSA (Dilithium):**
```rust
use pqc_combo::generate_dilithium_keypair_with_pct;

// CORRECT: Performs PCT
let (pk, sk) = generate_dilithium_keypair_with_pct().expect("KeyGen failed");
```

### 3.2 Zeroization

Secret keys (`KyberSecretKey`, `DilithiumSecretKey`) automatically implement the `Drop` trait to zeroize their memory when they go out of scope.

*   **Do not** attempt to read the internal bytes of a secret key and copy them to a non-zeroizing buffer.
*   **Do not** serialize secret keys to disk unless encrypted with an approved method (e.g., AES-GCM).

### 3.3 Error Handling

If any cryptographic operation returns an error (e.g., `PqcError::CryptoFailure`, `PqcError::FipsStateError`), you must assume the operation failed securely.

If the module enters the `Error` state (e.g., due to a continuous self-test failure), it must be restarted (process restart) to return to the `PowerOn` state.

---

## 4. Checklist for FIPS Compliance

To ensure your application is FIPS 140-3 compliant:

- [ ] **Compile** with `features = ["fips_140_3"]`.
- [ ] **Call** `run_post()` immediately on startup.
- [ ] **Check** the result of `run_post()` and abort if it fails.
- [ ] **Use** `generate_key_pair_with_pct()` for all key generation.
- [ ] **Protect** secret keys from unauthorized disclosure.
- [ ] **Do not** modify the library source code.

---

## 5. Troubleshooting

**"Module not in operational state"**
*   **Cause:** You forgot to call `run_post()`.
*   **Fix:** Add `pqc_combo::run_post_or_panic();` to the start of your `main` function.

**"Self-test failed"**
*   **Cause:** Hardware instability, memory corruption, or binary tampering.
*   **Fix:** Restart the application. If the issue persists, verify the integrity of the binary.
