![Pure Rust](https://img.shields.io/badge/100%25-Rust-orange)
![no_std](https://img.shields.io/badge/no__std-no__alloc-green)
![KATs Complete](https://img.shields.io/badge/KATs-Complete-brightgreen)
```
# Security Policy v0.1.0 NO KAT TESTS

> [!NOTE]
> For the formal FIPS 140-3 Security Policy required for validation, please see [docs/FIPS_140_3_SECURITY_POLICY.md](docs/FIPS_140_3_SECURITY_POLICY.md).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model

### Threat Model

pqc-combo is designed to protect against:

✅ **Quantum Computer Attacks**
- Future quantum computers capable of breaking RSA and ECC
- Implements NIST-standardized post-quantum algorithms

✅ **Classical Cryptographic Attacks**
- Key recovery attacks
- Forgery attacks on signatures
- Man-in-the-middle attacks (when used correctly)

✅ **Implementation Attacks**
- Memory safety issues (via Rust's type system)
- Timing side-channels (via constant-time implementations)
- Key leakage (via automatic zeroization)

### Out of Scope

❌ **Physical Attacks**
- Hardware tampering
- Power analysis
- Electromagnetic analysis
- Fault injection

❌ **Social Engineering**
- Phishing
- Credential theft
- Insider threats

❌ **Application-Level Issues**
- Improper key management by applications
- Insecure protocol design
- Business logic flaws

## Security Features

### Cryptographic Algorithms

#### ML-KEM-1024 (FIPS 203)
- **Security Level**: NIST Level 5 (equivalent to AES-256)
- **Status**: NIST standardized (August 2024)
- **Use Case**: Key encapsulation for secure key exchange
- **Key Sizes**: 1568-byte public key, 3168-byte private key
- **Shared Secret**: 32 bytes

#### ML-DSA-65 (FIPS 204)
- **Security Level**: NIST Level 3 (equivalent to AES-192)
- **Status**: NIST standardized (August 2024)
- **Use Case**: Digital signatures for authentication
- **Key Sizes**: 1952-byte public key, 4032-byte private key
- **Signature Size**: 3309 bytes

#### AES-256-GCM (FIPS 197, SP 800-38D)
- **Security Level**: 256-bit symmetric security
- **Status**: NIST approved
- **Use Case**: Authenticated encryption
- **Optional**: Enable with `aes-gcm` feature

### Implementation Security

#### Memory Safety
- ✅ Pure Rust implementation
- ✅ No unsafe code in public API
- ✅ Automatic bounds checking
- ✅ No use-after-free vulnerabilities
- ✅ No buffer overflows

#### Constant-Time Operations
- ✅ Implementations via libcrux use constant-time primitives
- ✅ No secret-dependent branches in critical paths
- ✅ No secret-dependent memory access patterns

#### Key Zeroization
- ✅ Automatic zeroization via `zeroize` crate
- ✅ Keys cleared on drop
- ✅ `ZeroizeOnDrop` trait implementation
- ⚠️ Cannot protect against:
  - Hardware memory remanence
  - Hibernation/swap files
  - Memory dumps
  - DMA attacks

#### Random Number Generation
- ✅ Uses OS entropy source (`OsRng`) in `std` mode
- ⚠️ `no_std` mode requires external entropy source
- ⚠️ Seed validation (rejects all-zero seeds)
- ❌ No built-in entropy pool for `no_std`

### FIPS 140-3 Features

When `fips_140_3` feature is enabled:

#### Pre-Operational Self-Tests (POST)
- ✅ Cryptographic Algorithm Self-Tests (CASTs)
  - SHA3-256, SHA3-512
  - SHAKE-128, SHAKE-256
- ✅ Known Answer Tests (KATs)
  - ML-KEM-1024: Public key, secret key, encapsulation/decapsulation
  - ML-DSA-65: Public key, secret key, signature generation/verification
  - All tests verify determinism and correct cryptographic operations
- ✅ Pair-wise Consistency Tests (PCTs)
  - All key pairs validated before use

#### State Machine
- ✅ Enforces initialization before operations
- ✅ Thread-safe atomic state
- ✅ Error state on POST failure

#### CSP Controls
- ✅ Prevents plaintext key export in FIPS mode
- ✅ Keys only accessible through approved APIs
- ✅ Automatic zeroization

## Known Limitations

### ⚠️ Critical Limitations

1. **Not Yet FIPS Certified**
   - Implementation includes FIPS 140-3 features
   - CMVP certification not yet obtained
   - Do not claim FIPS compliance in production

2. **No Hardware Acceleration**
   - Pure software implementation
   - May be slower than hardware-accelerated alternatives
   - Consider performance requirements

### ⚠️ Important Considerations

3. **RNG Quality**
   - `std` mode: Uses `OsRng` (high quality)
   - `no_std` mode: Application must provide entropy
   - Poor entropy = weak keys

4. **Side-Channel Resistance**
   - Basic constant-time operations implemented
   - No guarantees against advanced side-channels
   - Physical security measures may be needed

5. **Key Management**
   - Library zeroizes keys on drop
   - Cannot protect keys in all scenarios:
     - Core dumps
     - Swap files
     - Hibernation
     - Hardware attacks

6. **No Formal Verification**
   - Code not formally verified
   - Relies on libcrux implementations
   - Standard software testing applied

## Responsible Disclosure

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure practices:

### Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **aaronschnacky@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### Response Timeline

- **24 hours**: Initial response acknowledging receipt
- **7 days**: Initial assessment and triage
- **30 days**: Target for fix development
- **90 days**: Public disclosure (coordinated with reporter)

### Security Advisories

Security advisories will be published:
- GitHub Security Advisories
- RustSec Advisory Database
- Release notes and CHANGELOG

## Security Best Practices

### For Application Developers

#### Key Generation
```rust
// ✅ GOOD: Use with OS RNG
let keys = KyberKeys::generate_key_pair();

// ⚠️ CAUTION: Ensure seed has sufficient entropy
let seed = get_hardware_entropy(); // Must be cryptographically secure
let keys = KyberKeys::generate_key_pair_with_seed(seed);

// ❌ BAD: Never use predictable seeds
let bad_seed = [0u8; 64]; // Insecure!
```

#### FIPS Mode
```rust
// ✅ GOOD: Run POST before operations
run_post().expect("POST failed");

// ✅ GOOD: Use PCT-validated keys
let keys = KyberKeys::generate_key_pair_with_pct()?;

// ⚠️ CAUTION: Check operational state
if !is_operational() {
    return Err("Module not operational");
}
```

#### Key Storage
```rust
// ✅ GOOD: Keys automatically zeroized
{
    let keys = KyberKeys::generate_key_pair();
    // Use keys...
} // Keys zeroized here

// ❌ BAD: Serializing secret keys to disk
let sk_bytes = sk.as_slice(); // Don't do this in FIPS mode
std::fs::write("secret.key", sk_bytes); // Very insecure!
```

#### Error Handling
```rust
// ✅ GOOD: Handle errors properly
match verify_signature(&pk, msg, &sig) {
    true => // Authentic message
    false => // Invalid signature - REJECT
}

// ❌ BAD: Ignoring verification failures
if verify_signature(&pk, msg, &sig) {
    // Process message
}
// Implicitly accepts on panic/error!
```

### For Embedded Systems

#### Entropy Sources
```rust
// ✅ GOOD: Use hardware RNG
let seed = read_hardware_rng();

// ⚠️ ACCEPTABLE: Use TRNG with post-processing
let raw = read_trng();
let seed = hash_entropy_pool(raw);

// ❌ BAD: Pseudo-random or predictable
let seed = get_timestamp(); // Insecure!
```

#### Memory Protection
```rust
// ✅ GOOD: Disable swap/hibernation for sensitive memory
// (OS/hardware specific)

// ✅ GOOD: Use MPU/MMU to protect key memory
// (hardware specific)

// ⚠️ CAUTION: Ensure zeroization actually happens
// (compiler optimizations may remove it)
```

## Cryptographic Agility

This library is designed for cryptographic agility:

### Algorithm Substitution
- Feature flags allow disabling algorithms
- Easy to add new algorithms when standardized
- Maintains backward compatibility

### Key Rotation
- Support key rotation at application level
- No built-in key management (by design)
- Applications should implement:
  - Regular key rotation
  - Key versioning
  - Graceful algorithm migration

### Hybrid Schemes
Applications can implement hybrid schemes:
```rust
// Example: Hybrid KEM with classical ECDH
let pq_ss = encapsulate_shared_secret(&kyber_pk);
let classical_ss = ecdh_key_exchange(&ecdh_pk);
let combined = kdf(pq_ss || classical_ss);
```

## Compliance and Certifications

### Current Status
- ✅ Implements NIST-standardized algorithms (FIPS 203, 204)
- ✅ Includes FIPS 140-3 self-test framework
- ❌ FIPS 140-3 certification: **Not obtained**
- ❌ Common Criteria: **Not evaluated**

### Roadmap
1. Complete KAT test vectors
2. Prepare FIPS 140-3 Security Policy
3. Submit to CMVP for validation
4. Obtain FIPS 140-3 certificate
5. Consider Common Criteria evaluation

## Security Contact

For security-related questions or concerns:

**Email**: aaronschnacky@gmail.com  
**PGP Key**: Available on request  
**Response Time**: Within 24 hours

For general questions, use GitHub Discussions or Issues.

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 140-3 Standard](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [RustSec Advisory Database](https://rustsec.org/)
- [libcrux Cryptography](https://github.com/cryspen/libcrux)

## Updates

This security policy is reviewed and updated with each release.

**Last Updated**: November 2024  
**Version**: 0.1.0