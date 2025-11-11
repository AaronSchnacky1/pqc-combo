// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// INTELLECTUAL PROPERTY: OFFERED FOR ACQUISITION
// NOVEMBER 11, 2025 — 04:47 AM PST — @AaronSchnacky (US)
// ------------------------------------------------------------------------
// Copyright © 2025 Aaron Schnacky. All rights reserved.
// License: MIT (publicly auditable for FIPS/CMVP verification)
//
// This implementation is engineered to satisfy FIPS 140-3 requirements:
// • ML-KEM-1024 (FIPS 203) — Level 5
// • ML-DSA-65 (FIPS 204) — Level 3
// • Pair-wise Consistency Tests (PCT) — 100% PASS
// • All 5 configs verified: no_std/no_alloc → std/aes-gcm
//
// Contact: aaronschnacky@gmail.com
// ------------------------------------------------------------------------
//! Conditional Algorithm Self-Tests (CASTs) for FIPS 140-3
//! 
//! Per FIPS 140-3 IG 10.3.A, all algorithms that ML-KEM and ML-DSA depend on
//! must be tested: SHA3-256, SHA3-512, SHAKE-128, SHAKE-256
//!
//! Uses NIST CAVP test vectors for validation.

use crate::error::{PqcError, Result};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// CAST for SHA3-256
/// 
/// Test vector from NIST CAVP: SHA3-256 with empty input
/// Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
pub fn sha3_256_cast() -> Result<()> {
    const EXPECTED: &[u8] = &[
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
    ];
    
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, b"");
    let result = hasher.finalize();
    
    if result[..] == EXPECTED[..] {
        Ok(())
    } else {
        Err(PqcError::CastFailure)
    }
}

/// CAST for SHA3-512
/// 
/// Test vector from NIST CAVP: SHA3-512 with empty input
/// Expected: a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
///           15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
pub fn sha3_512_cast() -> Result<()> {
    const EXPECTED: &[u8] = &[
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
    ];
    
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, b"");
    let result = hasher.finalize();
    
    if result[..] == EXPECTED[..] {
        Ok(())
    } else {
        Err(PqcError::CastFailure)
    }
}

/// CAST for SHAKE-128
/// 
/// Test vector from NIST CAVP: SHAKE-128 with empty input, 256-bit output
/// Expected: 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
pub fn shake128_cast() -> Result<()> {
    const EXPECTED: &[u8] = &[
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
    ];
    
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, b"");
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);
    
    if output == EXPECTED {
        Ok(())
    } else {
        Err(PqcError::CastFailure)
    }
}

/// CAST for SHAKE-256
/// 
/// Test vector from NIST CAVP: SHAKE-256 with empty input, 512-bit output
/// Expected: 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
///           d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be
pub fn shake256_cast() -> Result<()> {
    const EXPECTED: &[u8] = &[
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
        0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
        0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
    ];
    
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, b"");
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 64];
    reader.read(&mut output);
    
    if output == EXPECTED {
        Ok(())
    } else {
        Err(PqcError::CastFailure)
    }
}

/// Run all hash function CASTs
/// 
/// This must be called before any cryptographic operations in FIPS mode.
/// All four hash functions (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256)
/// must pass their CASTs.
pub fn run_hash_casts() -> Result<()> {
    sha3_256_cast()?;
    sha3_512_cast()?;
    shake128_cast()?;
    shake256_cast()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha3_256_cast_passes() {
        assert!(sha3_256_cast().is_ok(), "SHA3-256 CAST should pass");
    }
    
    #[test]
    fn test_sha3_512_cast_passes() {
        assert!(sha3_512_cast().is_ok(), "SHA3-512 CAST should pass");
    }
    
    #[test]
    fn test_shake128_cast_passes() {
        assert!(shake128_cast().is_ok(), "SHAKE-128 CAST should pass");
    }
    
    #[test]
    fn test_shake256_cast_passes() {
        assert!(shake256_cast().is_ok(), "SHAKE-256 CAST should pass");
    }
    
    #[test]
    fn test_all_hash_casts_pass() {
        assert!(run_hash_casts().is_ok(), "All hash CASTs should pass");
    }
    
    #[test]
    fn test_sha3_256_non_empty_input() {
        // Test with "abc" input
        const EXPECTED: &[u8] = &[
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, b"abc");
        let result = hasher.finalize();
        
        assert_eq!(&result[..], EXPECTED);
    }
    
    #[test]
    fn test_shake128_variable_output() {
        // Test SHAKE-128 can produce variable-length output
        let mut hasher = Shake128::default();
        Update::update(&mut hasher, b"test");
        let mut reader = hasher.finalize_xof();
        
        let mut output_16 = [0u8; 16];
        reader.read(&mut output_16);
        assert_ne!(output_16, [0u8; 16]);
        
        let mut output_32 = [0u8; 32];
        reader.read(&mut output_32);
        assert_ne!(output_32, [0u8; 32]);
    }
    
    #[test]
    fn test_hash_determinism() {
        // Verify hash functions are deterministic
        let input = b"deterministic test";
        
        let mut h1 = Sha3_256::new();
        Digest::update(&mut h1, input);
        let r1 = h1.finalize();
        
        let mut h2 = Sha3_256::new();
        Digest::update(&mut h2, input);
        let r2 = h2.finalize();
        
        assert_eq!(r1, r2, "Hash output should be deterministic");
    }
}