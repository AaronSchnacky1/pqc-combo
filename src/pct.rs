// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// Pair-wise Consistency Test (PCT) for FIPS 140-3 compliance
// ------------------------------------------------------------------------
//! Per FIPS 140-3 IG D.F, all newly generated asymmetric key pairs must be
//! validated before use via a sign-and-verify or encrypt-and-decrypt operation.

#[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
use crate::error::{PqcError, Result};

#[cfg(feature = "ml-kem")]
use crate::{
    decapsulate_shared_secret, encapsulate_shared_secret, KyberKeys,
};

#[cfg(feature = "ml-dsa")]
use crate::{
    sign_message, verify_signature,
    DilithiumPublicKey, DilithiumSecretKey,
};

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
#[cfg(feature = "ml-kem")]
pub fn kyber_pct(keys: &KyberKeys) -> Result<()> {
    // 1. Encapsulate with the public key
    let (ciphertext, ss_encap) = encapsulate_shared_secret(&keys.pk);

    // 2. Decapsulate with the secret key
    let ss_decap = decapsulate_shared_secret(&keys.sk, &ciphertext);

    // 3. Verify shared secrets match (both are [u8; 32])
    if ss_encap == ss_decap {
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
#[cfg(feature = "ml-dsa")]
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
    #[cfg(any(feature = "ml-kem", feature = "ml-dsa"))]
    use super::*;

    #[test]
    #[cfg(all(feature = "ml-kem", feature = "std"))]
    fn test_kyber_pct_success() {
        use crate::KyberKeys;
        let keys = KyberKeys::generate_key_pair();
        assert!(kyber_pct(&keys).is_ok(), "Kyber PCT should pass for valid keys");
    }

    #[test]
    #[cfg(all(feature = "ml-dsa", feature = "std"))]
    fn test_dilithium_pct_success() {
        use crate::generate_dilithium_keypair;
        let (pk, sk) = generate_dilithium_keypair();
        assert!(
            dilithium_pct(&pk, &sk).is_ok(),
            "Dilithium PCT should pass for valid keys"
        );
    }

    #[test]
    #[cfg(all(feature = "ml-kem", feature = "std"))]
    fn test_kyber_pct_failure_mismatched_keys() {
        use crate::KyberKeys;
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
    #[cfg(all(feature = "ml-dsa", feature = "std"))]
    fn test_dilithium_pct_failure_mismatched_keys() {
        use crate::generate_dilithium_keypair;
        let (pk1, _sk1) = generate_dilithium_keypair();
        let (_pk2, sk2) = generate_dilithium_keypair();

        // PCT should fail when using mismatched pk/sk
        let result = dilithium_pct(&pk1, &sk2);
        assert!(result.is_err(), "Dilithium PCT should fail for mismatched keys");
        assert_eq!(
            result.unwrap_err(),
            PqcError::PairwiseConsistencyTestFailure
        );
    }

    #[test]
    #[cfg(all(feature = "std", feature = "ml-kem", feature = "ml-dsa"))]
    fn test_pct_multiple_iterations() {
        use crate::{KyberKeys, generate_dilithium_keypair};
        // Verify PCT works consistently across multiple key generations
        for _ in 0..10 {
            let keys = KyberKeys::generate_key_pair();
            assert!(kyber_pct(&keys).is_ok());

            let (pk, sk) = generate_dilithium_keypair();
            assert!(dilithium_pct(&pk, &sk).is_ok());
        }
    }
}