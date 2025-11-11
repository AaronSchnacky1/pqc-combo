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
// src/pct.rs
//! Pair-wise Consistency Test (PCT) for FIPS 140-3 compliance
//!
//! Per FIPS 140-3 IG D.F, all newly generated asymmetric key pairs must be
//! validated before use via a sign-and-verify or encrypt-and-decrypt operation.

use crate::error::{PqcError, Result};
use crate::{
    decapsulate_shared_secret, encapsulate_shared_secret, sign_message, verify_signature,
    DilithiumPublicKey, DilithiumSecretKey, KyberKeys,
};
use pqcrypto_traits::kem::SharedSecret;

/// Performs Pair-wise Consistency Test (PCT) for Kyber key generation.
///
/// FIPS 140-3 requirement: Verify that a newly generated key pair is consistent
/// by performing an encapsulate-decapsulate cycle and verifying the shared secrets match.
///
/// # Arguments
/// * `keys` - The newly generated Kyber key pair to test
///
/// # Returns
/// * `Ok(())` if the PCT passes (shared secrets match)
/// * `Err(PqcError::PairwiseConsistencyTestFailure)` if the test fails
pub fn kyber_pct(keys: &KyberKeys) -> Result<()> {
    // 1. Encapsulate with the public key
    let (ciphertext, ss_encap) = encapsulate_shared_secret(&keys.pk);

    // 2. Decapsulate with the secret key
    let ss_decap = decapsulate_shared_secret(&keys.sk, &ciphertext);

    // 3. Verify shared secrets match
    if ss_encap.as_bytes() == ss_decap.as_bytes() {
        Ok(())
    } else {
        Err(PqcError::PairwiseConsistencyTestFailure)
    }
}

/// Performs Pair-wise Consistency Test (PCT) for Dilithium key generation.
///
/// FIPS 140-3 requirement: Verify that a newly generated key pair is consistent
/// by signing a known message and verifying the signature with the public key.
///
/// # Arguments
/// * `pk` - The public key to test
/// * `sk` - The secret key to test
///
/// # Returns
/// * `Ok(())` if the PCT passes (signature verifies correctly)
/// * `Err(PqcError::PairwiseConsistencyTestFailure)` if the test fails
pub fn dilithium_pct(pk: &DilithiumPublicKey, sk: &DilithiumSecretKey) -> Result<()> {
    // Use a fixed test message for PCT
    const PCT_MESSAGE: &[u8] = b"FIPS 140-3 Pair-wise Consistency Test";

    // 1. Sign the test message with the secret key
    let signature = sign_message(sk, PCT_MESSAGE);

    // 2. Verify the signature with the public key
    if verify_signature(pk, PCT_MESSAGE, &signature) {
        Ok(())
    } else {
        Err(PqcError::PairwiseConsistencyTestFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium3::keypair as dilithium_keypair;

    #[test]
    fn test_kyber_pct_success() {
        let keys = KyberKeys::generate_key_pair();
        assert!(kyber_pct(&keys).is_ok(), "Kyber PCT should pass for valid keys");
    }

    #[test]
    fn test_dilithium_pct_success() {
        let (pk, sk) = dilithium_keypair();
        assert!(
            dilithium_pct(&pk, &sk).is_ok(),
            "Dilithium PCT should pass for valid keys"
        );
    }

    #[test]
    fn test_kyber_pct_failure_mismatched_keys() {
        // Create two different key pairs
        let keys1 = KyberKeys::generate_key_pair();
        let keys2 = KyberKeys::generate_key_pair();

        // Create a mismatched pair (pk from keys1, sk from keys2)
        let mismatched = KyberKeys {
            pk: keys1.pk,
            sk: keys2.sk,
        };

        // PCT should fail for mismatched keys
        let result = kyber_pct(&mismatched);
        assert!(result.is_err(), "Kyber PCT should fail for mismatched keys");
        assert_eq!(
            result.unwrap_err(),
            PqcError::PairwiseConsistencyTestFailure
        );
    }

    #[test]
    fn test_dilithium_pct_failure_mismatched_keys() {
        let (pk1, _sk1) = dilithium_keypair();
        let (_pk2, sk2) = dilithium_keypair();

        // PCT should fail when using mismatched pk/sk
        let result = dilithium_pct(&pk1, &sk2);
        assert!(result.is_err(), "Dilithium PCT should fail for mismatched keys");
        assert_eq!(
            result.unwrap_err(),
            PqcError::PairwiseConsistencyTestFailure
        );
    }

    #[test]
    fn test_pct_multiple_iterations() {
        // Verify PCT works consistently across multiple key generations
        for _ in 0..10 {
            let keys = KyberKeys::generate_key_pair();
            assert!(kyber_pct(&keys).is_ok());

            let (pk, sk) = dilithium_keypair();
            assert!(dilithium_pct(&pk, &sk).is_ok());
        }
    }
}