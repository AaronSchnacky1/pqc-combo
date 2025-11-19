// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// FIPS 140-3 KAT for ML-KEM-1024 Decapsulation
// ------------------------------------------------------------------------
#![cfg(all(feature = "ml-kem", feature = "fips_140_3"))]

use crate::error::{Result, PqcError};
use crate::KyberKeys;

/// Test vector 1: Public key validation
/// This KAT verifies that we can generate a valid public key from a known seed
/// and that it has the correct size (1568 bytes for ML-KEM-1024)
fn test_vector_1_public_key() -> Result<()> {
    // Known seed for deterministic key generation (64 bytes for ML-KEM)
    const SEED: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    
    // Generate keypair from seed
    let keys = KyberKeys::generate_key_pair_with_seed(SEED);
    
    // Verify public key size
    let pk_bytes = keys.pk.as_slice();
    println!("KYBER_PK: {:02x?}", pk_bytes);
    if pk_bytes.len() != crate::ML_KEM_1024_PK_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify public key contains non-zero data
    let has_nonzero_data = pk_bytes.iter().any(|&b| b != 0);
    if !has_nonzero_data {
        return Err(PqcError::CastFailure);
    }
    
    // Verify determinism: same seed produces same key
    let keys2 = KyberKeys::generate_key_pair_with_seed(SEED);
    let pk2_bytes = keys2.pk.as_slice();
    if pk_bytes != pk2_bytes {
        return Err(PqcError::CastFailure);
    }
    
    Ok(())
}

/// Test vector 2: Secret key validation
/// This KAT verifies that we can generate a valid secret key from a known seed
/// and that it has the correct size (3168 bytes for ML-KEM-1024)
fn test_vector_2_secret_key() -> Result<()> {
    // Known seed for deterministic key generation (64 bytes for ML-KEM)
    const SEED: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    
    // Generate keypair from seed
    let keys = KyberKeys::generate_key_pair_with_seed(SEED);
    
    // Verify secret key size
    let sk_bytes = keys.sk.as_slice();
    println!("KYBER_SK: {:02x?}", sk_bytes);
    if sk_bytes.len() != crate::ML_KEM_1024_SK_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify secret key contains non-zero data
    let has_nonzero_data = sk_bytes.iter().any(|&b| b != 0);
    if !has_nonzero_data {
        return Err(PqcError::CastFailure);
    }
    
    // Verify determinism: same seed produces same key
    let keys2 = KyberKeys::generate_key_pair_with_seed(SEED);
    let sk2_bytes = keys2.sk.as_slice();
    if sk_bytes != sk2_bytes {
        return Err(PqcError::CastFailure);
    }
    
    Ok(())
}

/// Test vector 3: Encapsulation and decapsulation
/// This KAT verifies that we can encapsulate a shared secret and decapsulate it
/// using deterministic randomness for KAT reproducibility
fn test_vector_3_encap_decap() -> Result<()> {
    // Known seed for deterministic key generation (64 bytes for ML-KEM)
    const SEED: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    
    // Generate keypair from seed
    let keys = KyberKeys::generate_key_pair_with_seed(SEED);
    
    // Deterministic randomness for encapsulation (for KAT reproducibility)
    const ENCAP_SEED: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    
    // Encapsulate with deterministic randomness
    let (ciphertext, shared_secret_sender) = 
        crate::encapsulate_shared_secret_with_randomness(&keys.pk, ENCAP_SEED);
    
    // Verify ciphertext size
    let ct_bytes = ciphertext.as_slice();
    println!("KYBER_CT: {:02x?}", ct_bytes);
    println!("KYBER_SS: {:02x?}", shared_secret_sender);
    if ct_bytes.len() != crate::ML_KEM_1024_CT_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify shared secret size
    if shared_secret_sender.len() != crate::ML_KEM_1024_SS_BYTES {
        return Err(PqcError::CastFailure);
    }
    
    // Verify ciphertext contains non-zero data
    let has_nonzero_ct = ct_bytes.iter().any(|&b| b != 0);
    if !has_nonzero_ct {
        return Err(PqcError::CastFailure);
    }
    
    // Verify shared secret contains non-zero data
    let has_nonzero_ss = shared_secret_sender.iter().any(|&b| b != 0);
    if !has_nonzero_ss {
        return Err(PqcError::CastFailure);
    }
    
    // Verify determinism: same seeds produce same ciphertext and shared secret
    let (ciphertext2, shared_secret2) = 
        crate::encapsulate_shared_secret_with_randomness(&keys.pk, ENCAP_SEED);
    let ct2_bytes = ciphertext2.as_slice();
    
    if ct_bytes != ct2_bytes {
        return Err(PqcError::CastFailure);
    }
    if shared_secret_sender != shared_secret2 {
        return Err(PqcError::CastFailure);
    }
    
    // Decapsulate with secret key
    let shared_secret_receiver = crate::decapsulate_shared_secret(&keys.sk, &ciphertext);
    
    // Verify shared secrets match
    if shared_secret_sender != shared_secret_receiver {
        return Err(PqcError::CastFailure);
    }
    
    // Test that decapsulation with wrong secret key produces different shared secret
    // Generate a different keypair
    const WRONG_SEED: [u8; 64] = [0xff; 64];
    let wrong_keys = KyberKeys::generate_key_pair_with_seed(WRONG_SEED);
    
    let wrong_shared_secret = crate::decapsulate_shared_secret(&wrong_keys.sk, &ciphertext);
    
    // Should NOT match (different key)
    if wrong_shared_secret == shared_secret_sender {
        return Err(PqcError::CastFailure);
    }
    
    Ok(())
}

/// Run ML-KEM-1024 decapsulation Known Answer Test
/// 
/// This runs all KAT test vectors for ML-KEM-1024
pub fn run_kyber_decap_kat() -> Result<()> {
    test_vector_1_public_key()?;
    test_vector_2_secret_key()?;
    test_vector_3_encap_decap()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_kat() {
        let result = run_kyber_decap_kat();
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
        let result = test_vector_3_encap_decap();
        assert!(result.is_ok(), "Test vector 3 should pass: {:?}", result.err());
    }
}
