[![CI Status](https://github.com/AaronSchnacky1/pqc-combo/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronSchnacky1/pqc-combo/actions)
![Pure Rust](https://img.shields.io/badge/100%25-Rust-orange)
![no_std](https://img.shields.io/badge/no__std-Ready-green)

# pqc-combo v0.1.0 NO KAT TEST

[![Crates.io](https://img.shields.io/crates/v/pqc-combo.svg)](https://crates.io/crates/pqc-combo)
[![Documentation](https://docs.rs/pqc-combo/badge.svg)](https://docs.rs/pqc-combo)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://github.com/AaronSchnacky1/pqc-combo/workflows/CI/badge.svg)](https://github.com/AaronSchnacky1/pqc-combo/actions)

**Pure Rust Post-Quantum Cryptography Library with FIPS 140-3 Support**

A production-ready, `no_std` compatible cryptography library implementing NIST-standardized post-quantum algorithms with optional FIPS 140-3 compliance features.

🌐 **Website:** [www.pqc-combo.com](https://www.pqc-combo.com/)  
📦 **Crate:** [crates.io/crates/pqc-combo](https://crates.io/crates/pqc-combo)  
📖 **Documentation:** [docs.rs/pqc-combo](https://docs.rs/pqc-combo)  
🔗 **Repository:** [github.com/AaronSchnacky1/pqc-combo](https://github.com/AaronSchnacky1/pqc-combo)

## ✨ Features

## 🧪 Testing

```bash
cargo test --features std
cargo test --features "std,ml-kem,ml-dsa"
cargo test --features "std,fips_140_3"
cargo test --all-features

cargo test --no-default-features
cargo test --no-default-features --features alloc
cargo test --no-default-features --features "alloc,aes-gcm"

cargo bench
cargo bench --features "std,ml-kem,ml-dsa"
cargo bench keygen
cargo bench ML-KEM
```

### Cryptographic Algorithms

- **ML-KEM-1024** (Kyber) - FIPS 203, Security Level 5
  - Key Encapsulation Mechanism for secure key exchange
  - 1568-byte public keys, 3168-byte private keys
  - 32-byte shared secrets

- **ML-DSA-65** (Dilithium) - FIPS 204, Security Level 3
  - Digital signature algorithm for authentication
  - 1952-byte public keys, 4032-byte private keys
  - 3309-byte signatures

- **AES-256-GCM** - FIPS 197 & SP 800-38D
  - Authenticated encryption with associated data
  - Optional feature for hybrid encryption schemes

### FIPS 140-3 Compliance Features

When the `fips_140_3` feature is enabled, the library includes:

- ✅ **Pre-Operational Self-Tests (POST)**
  - Cryptographic Algorithm Self-Tests (CASTs) for hash functions
  - Known Answer Tests (KATs) for ML-KEM and ML-DSA
  - Pair-wise Consistency Tests (PCTs) for key generation

- ✅ **State Machine**
  - Enforces proper initialization before cryptographic operations
  - States: Uninitialized → POST → Operational → Error

- ✅ **CSP Controls**
  - Prevents plaintext export of secret keys in FIPS mode
  - Automatic key zeroization on drop
  - Keys only accessible through approved APIs

### Platform Support

- ✅ **`no_std` + `no_alloc`** - Bare metal / embedded systems
- ✅ **`no_std` + `alloc`** - Embedded with allocator
- ✅ **`std`** - Full standard library with OS RNG

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
pqc-combo = "0.1"
```

### Basic Usage

```rust
use pqc_combo::*;

// Key Encapsulation (KEM)
let keys = KyberKeys::generate_key_pair();
let (ciphertext, shared_secret_sender) = encapsulate_shared_secret(&keys.pk);
let shared_secret_receiver = decapsulate_shared_secret(&keys.sk, &ciphertext);
assert_eq!(shared_secret_sender, shared_secret_receiver);

// Digital Signatures
let (pk, sk) = generate_dilithium_keypair();
let message = b"Hello, Post-Quantum World!";
let signature = sign_message(&sk, message);
assert!(verify_signature(&pk, message, &signature));
```

### FIPS 140-3 Mode

```rust
use pqc_combo::*;

// Run Pre-Operational Self-Tests
run_post().expect("POST failed");

// Generate keys with Pair-wise Consistency Test
let keys = KyberKeys::generate_key_pair_with_pct()
    .expect("PCT failed");

// Use keys normally
let (ct, ss) = encapsulate_shared_secret(&keys.pk);
```

### `no_std` Usage

```rust
#![no_std]

use pqc_combo::*;

// Bring your own entropy source
let seed: [u8; 64] = get_hardware_entropy();

// Generate keys from seed
let keys = KyberKeys::generate_key_pair_with_seed(seed);
```

## 📋 Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library support, enables OS RNG | ✅ |
| `alloc` | Allocator support, required for AES-GCM | ✅ |
| `ml-kem` | ML-KEM-1024 (Kyber) algorithm | ✅ |
| `ml-dsa` | ML-DSA-65 (Dilithium) algorithm | ✅ |
| `aes-gcm` | AES-256-GCM symmetric encryption | ✅ |
| `fips_140_3` | FIPS 140-3 compliance features | ❌ |

### Configuration Examples

```toml
# Default: Full featured with std
pqc-combo = "0.1"

# FIPS mode
pqc-combo = { version = "0.1", features = ["fips_140_3"] }

# Minimal no_std
pqc-combo = { version = "0.1", default-features = false, features = ["ml-kem", "ml-dsa"] }

# no_std with allocator and AES
pqc-combo = { version = "0.1", default-features = false, features = ["alloc", "ml-kem", "ml-dsa", "aes-gcm"] }
```

## 🔒 Security

### Algorithm Security Levels

- **ML-KEM-1024**: NIST Security Level 5 (equivalent to AES-256)
- **ML-DSA-65**: NIST Security Level 3 (equivalent to AES-192)
- **AES-256-GCM**: 256-bit security

### Implementation Security

- ✅ **Pure Rust** - Memory safety guaranteed by Rust
- ✅ **Constant-time operations** - Via libcrux implementations
- ✅ **Automatic zeroization** - Secret keys cleared on drop
- ✅ **No unsafe code** - In the public API surface
- ✅ **FIPS 140-3 ready** - Self-tests and state machine included

### Security Considerations

- **RNG Quality**: Use hardware RNG in production environments
- **Side-channel resistance**: Implementations use constant-time operations where possible
- **Key management**: Secret keys are automatically zeroized, but ensure proper key lifecycle management
- **Not yet certified**: FIPS 140-3 certification is in progress

See [SECURITY.md](SECURITY.md) for more details.

## 📊 Performance

**Measured on modern x86_64 hardware (November 2024):**

| Operation | Time | Throughput |
|-----------|------|------------|
| ML-KEM-1024 KeyGen | 12.2 µs | ~81,900 ops/sec |
| ML-KEM-1024 Encapsulate | 12.9 µs | ~77,500 ops/sec |
| ML-KEM-1024 Decapsulate | 13.7 µs | ~72,900 ops/sec |
| ML-DSA-65 KeyGen | 29.8 µs | ~33,500 ops/sec |
| ML-DSA-65 Sign | 80.2 µs | ~12,470 ops/sec |
| ML-DSA-65 Verify | 29.1 µs | ~34,360 ops/sec |

**Key Insights:**
- 🚀 All operations complete in **under 100 microseconds**
- 🚀 ML-KEM is **faster than RSA-2048** for key exchange
- 🚀 ML-DSA is **competitive with ECDSA** for signatures
- 🚀 Pure Rust with **no performance compromises**

*Run `cargo bench` to measure on your hardware. See [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md) for detailed analysis.*

## 🛠️ Development Status

### ✅ Completed

- [x] Pure Rust implementations via libcrux
- [x] `no_std` support (bare metal to full std)
- [x] ML-KEM-1024 (Kyber) implementation
- [x] ML-DSA-65 (Dilithium) implementation
- [x] AES-256-GCM integration
- [x] FIPS 140-3 state machine
- [x] Pair-wise Consistency Tests (PCT)
- [x] Hash function CASTs
- [x] Known Answer Tests (KATs) for ML-KEM and ML-DSA
- [x] CSP controls and zeroization
- [x] Comprehensive test suite

### 🚧 In Progress

- [ ] FIPS 140-3 certification documentation
- [ ] Additional algorithm support (ML-KEM-768, ML-DSA-87)

### 📝 Planned

- [ ] C FFI wrapper (separate crate)
- [ ] Python bindings
- [ ] WebAssembly support
- [ ] Hardware acceleration
- [ ] Formal verification

## 📚 Documentation

- **API Documentation**: Run `cargo doc --open`
- **FIPS 140-3 Security Policy**: See [docs/FIPS_140_3_SECURITY_POLICY.md](docs/FIPS_140_3_SECURITY_POLICY.md)
- **FIPS 140-3 User Guide**: See [docs/FIPS_140_3_USER_GUIDE.md](docs/FIPS_140_3_USER_GUIDE.md)
- **Testing Guide**: See [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md)
- **Security Policy**: See [SECURITY.md](SECURITY.md)
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **libcrux** - Pure Rust cryptographic implementations
- **NIST** - Post-quantum cryptography standardization
- **Rust Crypto** - Cryptographic primitives ecosystem

## 📧 Contact

**Author**: Aaron Schnacky  
**Email**: aaronschnacky@gmail.com  
**Website**: [www.pqc-combo.com](https://www.pqc-combo.com/)  
**GitHub**: [@AaronSchnacky1](https://github.com/AaronSchnacky1)

For security issues, please see [SECURITY.md](SECURITY.md) for responsible disclosure process.

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind. While it implements NIST-standardized algorithms and includes FIPS 140-3 compliance features, it has not yet completed FIPS 140-3 certification. Use in production environments should be evaluated based on your specific security requirements.

---

**Built with ❤️ in Rust** | **Securing tomorrow's communications today**