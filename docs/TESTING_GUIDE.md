# pqc-combo Testing Guide

## 📋 Table of Contents

1. [Overview](#overview)
2. [Test Categories](#test-categories)
3. [Running Tests](#running-tests)
4. [Fuzzing](#fuzzing)
5. [Property-Based Testing](#property-based-testing)
6. [Cross-Implementation Validation](#cross-implementation-validation)
7. [Continuous Integration](#continuous-integration)
8. [Test Coverage](#test-coverage)
9. [FIPS 140-3 Testing Requirements](#fips-140-3-testing-requirements)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The pqc-combo library employs multiple testing strategies to ensure correctness, security, and compliance with FIPS 140-3 requirements:

- **Unit Tests**: Test individual functions and modules
- **Integration Tests**: Test component interactions
- **Fuzzing**: Discover edge cases and vulnerabilities
- **Property-Based Testing**: Verify mathematical properties
- **Cross-Validation**: Ensure compatibility with other implementations
- **FIPS Tests**: Verify compliance with FIPS 140-3 requirements

### Test Statistics

- **Total Tests**: 50+ test functions
- **Test Lines**: 3000+ lines of test code
- **Fuzzing Targets**: 9 specialized fuzzers
- **Property Tests**: 15+ property-based tests
- **Cross-Validation Vectors**: 20+ NIST test vectors

---

## Test Categories

### 1. Unit Tests (`src/*/tests`)

Located within source files using `#[cfg(test)]` modules.

**What they test:**
- Individual algorithm operations
- Error handling
- State machine transitions
- Cryptographic primitives (CASTs)
- Key generation, encapsulation, signing, verification

**Run with:**
```bash
cargo test --lib
```

### 2. Integration Tests (`tests/`)

Located in the `tests/` directory.

**Files:**
- `integration.rs` - Basic crypto operations
- `cast_tests.rs` - Hash function CASTs
- `fips_140_3.rs` - PCT and FIPS compliance
- `property_tests.rs` - Property-based tests (proptest)
- `cross_validation.rs` - NIST test vectors

**Run with:**
```bash
cargo test --tests
```

### 3. Benchmarks (`benches/`)

Performance measurements using Criterion.

**Run with:**
```bash
cargo bench
```

---

## Running Tests

### Quick Start

```bash
# Run all tests with all features
cargo test --all-features

# Run tests with std support
cargo test --features "std,ml-kem,ml-dsa"

# Run tests in FIPS mode
cargo test --features "std,fips_140_3"

# Run specific test
cargo test test_kyber_roundtrip

# Run with verbose output
cargo test -- --nocapture

# Run with specific thread count
cargo test -- --test-threads=1
```

### Feature Combinations

Test different feature combinations to ensure `no_std` compatibility:

```bash
# Minimal (no_std, no_alloc)
cargo test --no-default-features --features "ml-kem,ml-dsa"

# With allocator
cargo test --no-default-features --features "alloc,ml-kem,ml-dsa"

# With AES-GCM
cargo test --no-default-features --features "alloc,ml-kem,ml-dsa,aes-gcm"

# Full std
cargo test --features "std,ml-kem,ml-dsa,aes-gcm"

# FIPS mode
cargo test --features "std,fips_140_3"
```

### CI Testing Matrix

For thorough testing, use this matrix in CI:

```yaml
strategy:
  matrix:
    features:
      - "ml-kem"
      - "ml-dsa"
      - "ml-kem,ml-dsa"
      - "std,ml-kem,ml-dsa"
      - "std,ml-kem,ml-dsa,aes-gcm"
      - "std,fips_140_3"
      - "alloc,ml-kem,ml-dsa"
```

---

## Fuzzing

### Setup

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

### Available Fuzz Targets

#### Basic Fuzzers

1. **fuzz_kyber_keys** - ML-KEM key generation
2. **fuzz_dilithium_keys** - ML-DSA key generation
3. **fuzz_encapsulation** - KEM encapsulation/decapsulation
4. **fuzz_signature** - Signature generation/verification

#### Structure-Aware Fuzzers

5. **fuzz_kyber_structured** - Advanced KEM testing with specific scenarios
6. **fuzz_dilithium_structured** - Advanced signature testing

#### Specialized Fuzzers

7. **fuzz_pct** - Pair-wise Consistency Tests
8. **fuzz_state_machine** - FIPS state machine
9. **fuzz_aes_gcm** - AES-GCM encryption

### Running Fuzzers

```bash
# Run a specific fuzzer
cargo fuzz run fuzz_kyber_keys

# Run with time limit (5 minutes)
cargo fuzz run fuzz_kyber_keys -- -max_total_time=300

# Run with specific number of runs
cargo fuzz run fuzz_kyber_keys -- -runs=10000

# Run with more workers (parallel)
cargo fuzz run fuzz_kyber_keys -- -workers=8

# Run with custom memory limit
cargo fuzz run fuzz_kyber_keys -- -rss_limit_mb=4096

# Run with ASan (AddressSanitizer)
RUSTFLAGS="-Z sanitizer=address" cargo fuzz run fuzz_kyber_keys
```

### Fuzzing Strategy

**Short runs** (for CI):
```bash
# 1 minute per fuzzer
for fuzzer in fuzz_kyber_keys fuzz_dilithium_keys fuzz_encapsulation fuzz_signature; do
    cargo fuzz run $fuzzer -- -max_total_time=60
done
```

**Long runs** (overnight):
```bash
# 8 hours per fuzzer
for fuzzer in fuzz_*; do
    cargo fuzz run $fuzzer -- -max_total_time=28800
done
```

**Continuous fuzzing** (OSS-Fuzz):
- Runs 24/7 on Google's infrastructure
- See [OSS-Fuzz Integration](#oss-fuzz-integration)

### Analyzing Crashes

When a fuzzer finds a crash:

```bash
# Reproduce the crash
cargo fuzz run fuzz_kyber_keys fuzz/artifacts/fuzz_kyber_keys/crash-123abc

# Minimize the crash input
cargo fuzz cmin fuzz_kyber_keys

# Get detailed backtrace
RUST_BACKTRACE=full cargo fuzz run fuzz_kyber_keys crash-file
```

### Corpus Management

```bash
# Minimize corpus (remove redundant inputs)
cargo fuzz cmin fuzz_kyber_keys

# Merge multiple corpora
cargo fuzz cmin -merge fuzz_kyber_keys corpus1 corpus2

# Check corpus coverage
cargo fuzz coverage fuzz_kyber_keys
```

---

## Property-Based Testing

Property-based tests use `proptest` to generate random inputs and verify mathematical properties.

### Running Property Tests

```bash
# Run all property tests
cargo test --test property_tests

# Run specific property test
cargo test --test property_tests prop_kyber_roundtrip

# Run with more test cases (default is 100)
PROPTEST_CASES=1000 cargo test --test property_tests

# Run with specific seed for reproducibility
PROPTEST_SEED=12345 cargo test --test property_tests
```

### Available Properties

**ML-KEM Properties:**
- Encap/Decap roundtrip always produces matching shared secrets
- Determinism: same seeds produce same keys/ciphertexts
- Different seeds produce different keys
- Wrong key produces different shared secret

**ML-DSA Properties:**
- Sign/Verify roundtrip always succeeds for valid keys
- Determinism: same seeds/randomness produce same signatures
- Modified message fails verification
- Wrong public key fails verification

**AES-GCM Properties:**
- Encrypt/Decrypt roundtrip recovers plaintext
- Wrong key fails authentication
- Tampered ciphertext fails authentication

### Writing New Property Tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_your_test_name(
        seed in valid_seed_64(),
        message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        // Your test logic here
        prop_assert!(condition, "Error message");
    }
}
```

---

## Cross-Implementation Validation

Ensures compatibility with NIST specifications and other implementations.

### Running Cross-Validation Tests

```bash
# Run all cross-validation tests
cargo test --test cross_validation -- --nocapture

# Run specific vector test
cargo test --test cross_validation test_kem_keygen_vector_1

# Run FIPS compliance tests
cargo test --test cross_validation fips_compliance
```

### Test Vector Sources

1. **NIST Official Test Vectors**
   - From NIST PQC standardization project
   - FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)

2. **Reference Implementations**
   - pqclean reference implementations
   - libcrux test vectors

3. **Interoperability Tests**
   - Key serialization/deserialization
   - Cross-platform determinism

### Adding New Test Vectors

```rust
#[test]
fn test_new_vector() {
    let seed_hex = "0102030405..."; // From NIST
    let seed = hex::decode(seed_hex).unwrap();
    let seed: [u8; 64] = seed.try_into().unwrap();
    
    let keys = KyberKeys::generate_key_pair_with_seed(seed);
    
    // Compare with expected output
    let expected_pk_hex = "a1b2c3d4...";
    let expected_pk = hex::decode(expected_pk_hex).unwrap();
    assert_eq!(keys.pk.as_slice(), &expected_pk[..]);
}
```

---

## Continuous Integration

### GitHub Actions Workflow

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable, beta, nightly]
        features:
          - "ml-kem,ml-dsa"
          - "std,ml-kem,ml-dsa"
          - "std,ml-kem,ml-dsa,aes-gcm"
          - "std,fips_140_3"
    
    steps:
      - uses: actions/checkout@v3
      
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      
      - name: Run tests
        run: cargo test --features "${{ matrix.features }}"
  
  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: dtolnay/rust-toolchain@nightly
      
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      
      - name: Run short fuzz tests
        run: |
          for target in fuzz_kyber_keys fuzz_dilithium_keys; do
            cargo fuzz run $target -- -max_total_time=60
          done
  
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: dtolnay/rust-toolchain@nightly
      
      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin
      
      - name: Generate coverage
        run: cargo tarpaulin --all-features --out Xml
      
      - name: Upload to codecov
        uses: codecov/codecov-action@v3
```

---

## Test Coverage

### Measuring Coverage

Install `cargo-tarpaulin`:

```bash
cargo install cargo-tarpaulin
```

Generate coverage reports:

```bash
# Generate coverage for all tests
cargo tarpaulin --all-features --out Html

# Generate coverage for specific features
cargo tarpaulin --features "std,ml-kem,ml-dsa" --out Html

# Exclude files from coverage
cargo tarpaulin --all-features --exclude-files "fuzz/*" --out Html

# Open coverage report
xdg-open tarpaulin-report.html
```

### Coverage Goals

- **Overall**: >90%
- **Critical paths** (crypto operations): 100%
- **Error handling**: >85%
- **FIPS mode**: 100% of FIPS-specific code

### Viewing Coverage

```bash
# HTML report (most detailed)
cargo tarpaulin --all-features --out Html
open tarpaulin-report.html

# Terminal output
cargo tarpaulin --all-features --out Stdout

# XML for CI integration
cargo tarpaulin --all-features --out Xml
```

---

## FIPS 140-3 Testing Requirements

### Required Tests for FIPS Certification

1. **Pre-Operational Self-Tests (POST)**
   - CASTs (Cryptographic Algorithm Self-Tests)
   - KATs (Known Answer Tests)
   - PCTs (Pair-wise Consistency Tests)

2. **Conditional Tests**
   - PCT on every key generation
   - Continuous RNG tests (if applicable)

3. **Error States**
   - Test error handling
   - Test error state recovery

### Running FIPS Tests

```bash
# Run all FIPS tests
cargo test --features "std,fips_140_3"

# Run POST
cargo test --features "std,fips_140_3" test_post_success

# Run CASTs
cargo test --test cast_tests

# Run PCTs
cargo test --test fips_140_3

# Run KATs
cargo test kat_kyber
cargo test kat_dilithium
```

### FIPS Test Checklist

- [ ] All CASTs pass (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256)
- [ ] All KATs pass (ML-KEM-1024, ML-DSA-65)
- [ ] All PCTs pass for valid keys
- [ ] PCTs fail for invalid/mismatched keys
- [ ] State machine enforces proper initialization
- [ ] CSP controls prevent plaintext export in FIPS mode
- [ ] Error state handling works correctly
- [ ] POST runs successfully before operations

---

## OSS-Fuzz Integration

### Submitting to OSS-Fuzz

1. **Fork OSS-Fuzz repository**:
   ```bash
   git clone https://github.com/google/oss-fuzz.git
   cd oss-fuzz
   ```

2. **Create project directory**:
   ```bash
   mkdir projects/pqc-combo
   ```

3. **Add configuration files**:
   - Copy `oss-fuzz/project.yaml` to `projects/pqc-combo/`
   - Copy `oss-fuzz/Dockerfile` to `projects/pqc-combo/`
   - Copy `oss-fuzz/build.sh` to `projects/pqc-combo/`

4. **Test locally**:
   ```bash
   python infra/helper.py build_image pqc-combo
   python infra/helper.py build_fuzzers pqc-combo
   python infra/helper.py run_fuzzer pqc-combo fuzz_kyber_keys
   ```

5. **Submit PR to OSS-Fuzz**

### Benefits of OSS-Fuzz

- **24/7 Fuzzing**: Continuous fuzzing on Google's infrastructure
- **ClusterFuzz**: Advanced corpus management and bug reporting
- **Coverage-guided**: Intelligent input generation
- **Multiple Sanitizers**: ASan, MSan, UBSan
- **Automatic Bug Reports**: Filed as GitHub issues
- **Free for open source projects**

---

## Troubleshooting

### Common Issues

#### Test Failures

**Issue**: Tests fail with "POST not run"
```
Error: FipsNotInitialized
```

**Solution**: Run POST before tests in FIPS mode:
```rust
#[test]
fn test_my_function() {
    #[cfg(feature = "fips_140_3")]
    run_post().expect("POST failed");
    
    // Your test code
}
```

**Issue**: Fuzzer crashes with "Zero seed invalid"

**Solution**: Fuzz targets must ensure non-zero seeds:
```rust
if seed.iter().any(|&b| b != 0) {
    // Use seed
}
```

#### Performance Issues

**Issue**: Tests are slow

**Solution**: Run tests in parallel or reduce test cases:
```bash
# Parallel execution
cargo test -- --test-threads=8

# Fewer proptest cases
PROPTEST_CASES=10 cargo test
```

#### Coverage Issues

**Issue**: tarpaulin fails to build

**Solution**: Use nightly toolchain:
```bash
rustup toolchain install nightly
cargo +nightly tarpaulin
```

### Getting Help

- **GitHub Issues**: https://github.com/AaronSchnacky1/pqc-combo/issues
- **Security Issues**: security@pqc-combo.com (or aaronschnacky@gmail.com)
- **Documentation**: https://docs.rs/pqc-combo

---

## Best Practices

1. **Run tests before every commit**:
   ```bash
   cargo test --all-features
   ```

2. **Run fuzzers periodically**:
   ```bash
   # Weekly: 1 hour each fuzzer
   ```

3. **Update test vectors** when algorithms change

4. **Maintain >90% coverage**

5. **Document new tests**

6. **Use descriptive test names**:
   ```rust
   #[test]
   fn test_kyber_encap_decap_with_valid_keys_produces_matching_shared_secrets()
   ```

7. **Test error cases**, not just happy paths

8. **Keep tests fast**: Unit tests <1s, integration tests <10s

9. **Use CI** to catch regressions early

10. **Review fuzzer findings** regularly

---

## Test Maintenance

### Regular Tasks

**Daily**:
- Monitor CI test results
- Review fuzzer crashes

**Weekly**:
- Run extended fuzz tests (1+ hours)
- Review test coverage

**Monthly**:
- Update test vectors from NIST
- Review and update property tests
- Run full test suite on multiple platforms

**Per Release**:
- Run complete test suite with all features
- Verify FIPS tests pass
- Update benchmark results
- Review security test results

---

## Appendix: Test Commands Quick Reference

```bash
# Basic tests
cargo test
cargo test --all-features
cargo test --features "std,ml-kem,ml-dsa"

# Specific tests
cargo test --test integration
cargo test --test cross_validation
cargo test -- test_name

# Fuzzing
cargo fuzz run fuzz_kyber_keys
cargo fuzz run fuzz_kyber_keys -- -max_total_time=300

# Property tests
cargo test --test property_tests
PROPTEST_CASES=1000 cargo test --test property_tests

# Coverage
cargo tarpaulin --all-features --out Html

# Benchmarks
cargo bench
cargo bench -- keygen

# FIPS tests
cargo test --features "std,fips_140_3"

# No-std tests
cargo test --no-default-features --features "ml-kem,ml-dsa"
```

---

**Last Updated**: November 2024  
**Version**: 1.0.0  
**Maintainer**: Aaron Schnacky (aaronschnacky@gmail.com)
