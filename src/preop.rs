// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// Pre-Operational Self-Tests (POST) for FIPS 140-3
// ------------------------------------------------------------------------
//! Runs all required self-tests before allowing cryptographic operations:
//! 1. Hash function CASTs (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256)
//! 2. Known Answer Tests (KATs) - FIPS mode only
//! 3. Pair-wise Consistency Tests (PCT) for key generation

use crate::error::Result;
use crate::cast::run_hash_casts;
use crate::state::{enter_post_state, enter_operational_state, enter_error_state};

#[cfg(all(feature = "ml-kem", feature = "fips_140_3"))]
use crate::kat_kyber::run_kyber_decap_kat;

#[cfg(all(feature = "ml-dsa", feature = "fips_140_3"))]
use crate::kat_dilithium::run_dilithium_verify_kat;

#[cfg(all(feature = "ml-kem", feature = "std"))]
use crate::{pct::kyber_pct, KyberKeys};

#[cfg(all(feature = "ml-dsa", feature = "std"))]
use crate::{pct::dilithium_pct, generate_dilithium_keypair};

/// Run complete Pre-Operational Self-Tests (POST)
/// 
/// FIPS 140-3 requires POST to run:
/// - On module initialization (power-on)
/// - On demand when requested
/// - Before any cryptographic operations
/// 
/// This function performs:
/// 1. Hash function CASTs for all dependent algorithms
/// 2. Known Answer Tests (KATs) - in FIPS mode only
/// 3. Generates test keys and runs PCTs to verify key generation
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
    
    // 2. Known Answer Tests (KATs) - FIPS mode only
    #[cfg(all(feature = "ml-kem", feature = "fips_140_3"))]
    run_kyber_decap_kat()?;
    
    #[cfg(all(feature = "ml-dsa", feature = "fips_140_3"))]
    run_dilithium_verify_kat()?;
    
    // 3. Pair-wise Consistency Tests (PCTs)
    // Only run if std feature is enabled (requires RNG)
    #[cfg(all(feature = "ml-kem", feature = "std"))]
    {
        let kyber_keys = KyberKeys::generate_key_pair();
        kyber_pct(&kyber_keys)?;
    }
    
    #[cfg(all(feature = "ml-dsa", feature = "std"))]
    {
        let (dil_pk, dil_sk) = generate_dilithium_keypair();
        dilithium_pct(&dil_pk, &dil_sk)?;
    }
    
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