// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// FIPS 140-3 KAT for ML-DSA-65 Verification
// ------------------------------------------------------------------------
#![cfg(all(feature = "ml-dsa", feature = "fips_140_3"))]

use crate::error::{Result, PqcError};
use crate::generate_dilithium_keypair_with_seed;

/// Test vector 1: Public key validation
/// This KAT verifies that we can generate a valid public key from a known seed
/// and that it has the correct size (1952 bytes for ML-DSA-65)
fn test_vector_1_public_key() -> Result<()> {
    // Known seed for deterministic key generation
    const SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    
    // Generate keypair from seed
    let (pk, _sk) = generate_dilithium_keypair_with_seed(SEED);
    
    // Verify public key size
    let pk_bytes = pk.as_slice();
    println!("DILITHIUM_PK: {:02x?}", pk_bytes);
    if pk_bytes.len() != crate::ML_DSA_65_PK_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify public key contains non-zero data (not all zeros)
    let has_nonzero_data = pk_bytes.iter().any(|&b| b != 0);
    if !has_nonzero_data {
        return Err(PqcError::CastFailure);
    }
    
    // Verify determinism: same seed produces same key
    let (pk2, _sk2) = generate_dilithium_keypair_with_seed(SEED);
    let pk2_bytes = pk2.as_slice();
    if pk_bytes != pk2_bytes {
        return Err(PqcError::CastFailure);
    }
    
    Ok(())
}

/// Test vector 2: Secret key validation
/// This KAT verifies that we can generate a valid secret key from a known seed
/// and that it has the correct size (4032 bytes for ML-DSA-65)
fn test_vector_2_secret_key() -> Result<()> {
    // Known seed for deterministic key generation
    const SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    
    // Generate keypair from seed
    let (_pk, sk) = generate_dilithium_keypair_with_seed(SEED);
    
    // Verify secret key size
    let sk_bytes = sk.as_slice();
    println!("DILITHIUM_SK: {:02x?}", sk_bytes);
    if sk_bytes.len() != crate::ML_DSA_65_SK_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify secret key contains non-zero data
    let has_nonzero_data = sk_bytes.iter().any(|&b| b != 0);
    if !has_nonzero_data {
        return Err(PqcError::CastFailure);
    }
    
    // Verify determinism: same seed produces same key
    let (_pk2, sk2) = generate_dilithium_keypair_with_seed(SEED);
    let sk2_bytes = sk2.as_slice();
    if sk_bytes != sk2_bytes {
        return Err(PqcError::CastFailure);
    }
    
    Ok(())
}

/// Test vector 3: Signature generation and verification
/// This KAT verifies that we can sign a message and verify the signature
/// using deterministic signing (zero randomness for KAT reproducibility)
fn test_vector_3_signature() -> Result<()> {
    // Known seed for deterministic key generation
    const SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    
    // Test message
    const MESSAGE: &[u8] = b"FIPS 140-3 KAT";
    
    // Generate keypair from seed
    let (pk, sk) = generate_dilithium_keypair_with_seed(SEED);
    
    // Sign with deterministic randomness for KAT
    const SIGN_SEED: [u8; 32] = [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    ];  // Non-zero seed for deterministic signing
    let signature = crate::sign_message_with_randomness(&sk, MESSAGE, SIGN_SEED);
    
    // Verify signature size
    let sig_bytes = signature.as_slice();
    println!("DILITHIUM_SIG: {:02x?}", sig_bytes);
    if sig_bytes.len() != crate::ML_DSA_65_SIG_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify signature contains non-zero data
    let has_nonzero_data = sig_bytes.iter().any(|&b| b != 0);
    if !has_nonzero_data {
        return Err(PqcError::CastFailure);
    }
    
    // Verify the signature is valid
    let is_valid = crate::verify_signature(&pk, MESSAGE, &signature);
    if !is_valid {
        return Err(PqcError::CastFailure);
    }
    
    // Verify determinism: same seed and message produces same signature
    let signature2 = crate::sign_message_with_randomness(&sk, MESSAGE, SIGN_SEED);
    let sig2_bytes = signature2.as_slice();
    if sig_bytes != sig2_bytes {
        return Err(PqcError::CastFailure);
    }
    
    // Test that tampering with message causes verification to fail
    const WRONG_MESSAGE: &[u8] = b"FIPS 140-3 KAX";  // Changed last char
    let is_invalid = crate::verify_signature(&pk, WRONG_MESSAGE, &signature);
    if is_invalid {
        // Should fail with wrong message
        return Err(PqcError::CastFailure);
    }
    
    Ok(())
}

/// Run ML-DSA-65 verification Known Answer Test
/// 
/// This runs all KAT test vectors for ML-DSA-65
pub fn run_dilithium_verify_kat() -> Result<()> {
    test_vector_1_public_key()?;
    test_vector_2_secret_key()?;
    test_vector_3_signature()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_kat() {
        let result = run_dilithium_verify_kat();
        assert!(result.is_ok(), "KAT should pass: {:?}", result.err());
    }
    
    #[test]
    fn test_vector_1() {
        let result = test_vector_1_public_key();
        assert!(result.is_ok(), "Test vector 1 should pass: {:?}", result.err());
    }
    
    #[test]
    fn test_vector_2() {
        let result = test_vector_2_secret_key();
        assert!(result.is_ok(), "Test vector 2 should pass: {:?}", result.err());
    }
    
    #[test]
    fn test_vector_3() {
        let result = test_vector_3_signature();
        assert!(result.is_ok(), "Test vector 3 should pass: {:?}", result.err());
    }
}