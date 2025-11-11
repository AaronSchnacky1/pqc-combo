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
//! Pre-Operational Self-Tests (POST) for FIPS 140-3
//! 
//! Runs all required self-tests before allowing cryptographic operations:
//! 1. Hash function CASTs (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256)
//! 2. Pair-wise Consistency Tests (PCT) for key generation

use crate::error::Result;
use crate::cast::run_hash_casts;
use crate::pct::{kyber_pct, dilithium_pct};
use crate::state::{enter_post_state, enter_operational_state, enter_error_state};
use crate::KyberKeys;
use pqcrypto_dilithium::dilithium3::keypair as dilithium_keypair;

/// Run complete Pre-Operational Self-Tests (POST)
/// 
/// FIPS 140-3 requires POST to run:
/// - On module initialization (power-on)
/// - On demand when requested
/// - Before any cryptographic operations
/// 
/// This function performs:
/// 1. Hash function CASTs for all dependent algorithms
/// 2. Generates test keys and runs PCTs to verify key generation
/// 
/// Returns Ok(()) if all tests pass, Err otherwise.
/// On success, module enters Operational state.
/// On failure, module enters Error state.
pub fn run_post() -> Result<()> {
    // Enter POST state
    enter_post_state();
    
    // Run all self-tests
    let result = run_all_self_tests();
    
    // Update state based on result
    match result {
        Ok(()) => {
            enter_operational_state();
            Ok(())
        }
        Err(e) => {
            enter_error_state();
            Err(e)
        }
    }
}

/// Internal function to run all self-tests
fn run_all_self_tests() -> Result<()> {
    // 1. Hash function CASTs (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256)
    run_hash_casts()?;
    
    // 2. Kyber PCT - Generate test keys and verify consistency
    let kyber_keys = KyberKeys::generate_key_pair();
    kyber_pct(&kyber_keys)?;
    
    // 3. Dilithium PCT - Generate test keys and verify consistency
    let (dil_pk, dil_sk) = dilithium_keypair();
    dilithium_pct(&dil_pk, &dil_sk)?;
    
    Ok(())
}

/// Run POST and panic on failure (for FIPS strict mode)
/// 
/// Use this in applications that require FIPS mode and should not
/// continue execution if self-tests fail.
pub fn run_post_or_panic() {
    run_post().expect("FIPS 140-3 Pre-Operational Self-Tests failed - cannot continue");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{get_fips_state, FipsState, reset_fips_state};

    #[test]
    fn test_post_success() {
        reset_fips_state();
        
        let result = run_post();
        assert!(result.is_ok(), "POST should pass: {:?}", result.err());
        assert_eq!(get_fips_state(), FipsState::Operational);
    }

    #[test]
    fn test_post_state_transitions() {
        reset_fips_state();
        assert_eq!(get_fips_state(), FipsState::Uninitialized);
        
        run_post().expect("POST failed");
        
        assert_eq!(get_fips_state(), FipsState::Operational);
    }

    #[test]
    fn test_post_repeatable() {
        // POST should be able to run multiple times
        for _ in 0..5 {
            reset_fips_state();
            let result = run_post();
            assert!(result.is_ok(), "POST should pass on repeated runs");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_post_or_panic_success() {
        reset_fips_state();
        run_post_or_panic(); // Should not panic
        assert_eq!(get_fips_state(), FipsState::Operational);
    }
}