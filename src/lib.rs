// src/lib.rs
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", allow(unused_imports))]

#[cfg(feature = "alloc")]
extern crate alloc;

use pqcrypto_kyber::kyber1024::{
    self,
    PublicKey   as KyberPublicKey,
    SecretKey   as KyberSecretKey,
    Ciphertext  as KyberCiphertext,
    SharedSecret as KyberSharedSecret,
};

// Import SharedSecret for KEM test (always in test)
#[cfg(test)]
use pqcrypto_traits::kem::SharedSecret;

// Import Ciphertext ONLY when alloc is enabled (used in tampering test)
#[cfg(feature = "alloc")]
use pqcrypto_traits::kem::Ciphertext;

use pqcrypto_dilithium::dilithium3::{
    sign,
    open,
    // keypair is imported in mod tests
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};

pub mod error;
pub use error::{PqcError, Result};
use rand_core::{RngCore, CryptoRng};

pub struct KyberKeys {
    pub pk: KyberPublicKey,
    pub sk: KyberSecretKey,
}

impl KyberKeys {
    pub fn generate_key_pair<R: RngCore + CryptoRng>(_rng: &mut R) -> Result<Self> {
        let (pk, sk) = kyber1024::keypair();
        Ok(KyberKeys { pk, sk })
    }
}

pub fn encapsulate_shared_secret<R: RngCore + CryptoRng>(
    pk: &KyberPublicKey,
    _rng: &mut R,
) -> Result<(KyberCiphertext, KyberSharedSecret)> {
    let (ss, ct) = kyber1024::encapsulate(pk);
    Ok((ct, ss))
}

pub fn decapsulate_shared_secret(
    sk: &KyberSecretKey,
    ciphertext: &KyberCiphertext,
) -> KyberSharedSecret {
    kyber1024::decapsulate(ciphertext, sk)
}

pub fn sign_message(sk: &DilithiumSecretKey, message: &[u8]) -> DilithiumSignedMessage {
    sign(message, sk)
}

pub fn verify_signature(
    pk: &DilithiumPublicKey,
    expected_message: &[u8],
    signed_message: &DilithiumSignedMessage,
) -> bool {
    match open(signed_message, pk) {
        Ok(extracted) => extracted == expected_message,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    // Moved here as it's only used by tests
    use pqcrypto_dilithium::dilithium3::keypair as dilithium_keypair;

    // --- Imports for advanced tests ---
    
    // Import traits for as_bytes() and from_bytes()
    use pqcrypto_traits::kem::{
        PublicKey as KemPublicKeyTrait, 
        SecretKey as KemSecretKeyTrait, 
        Ciphertext as KemCiphertextTrait
    };
    use pqcrypto_traits::sign::{
        PublicKey as SignPublicKeyTrait, 
        SecretKey as SignSecretKeyTrait,
        SignedMessage as SignSignedMessageTrait
    };
    
    // Imports for alloc/std features
    #[cfg(feature = "alloc")]
    use alloc::{vec, vec::Vec, boxed::Box};
    
    #[cfg(feature = "std")]
    use std::{thread, sync::Arc};


    // --- Original Tests (Grouped) ---

    #[test]
    fn test_kyber_kem_round_trip_success() {
        let mut rng = OsRng;
        let keys = KyberKeys::generate_key_pair(&mut rng).unwrap();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk, &mut rng).unwrap();
        let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn test_dilithium_sign_verify_success_and_wrong_msg() {
        let (pk, sk) = dilithium_keypair();
        let msg = b"The secure PQC core is audited.";
        let signed = sign_message(&sk, msg);
        
        // Test success
        assert!(verify_signature(&pk, msg, &signed));

        // Test Category 3: Mismatched Key/Data (Wrong Message)
        let bad_msg = b"The secure PQC core is tampered.";
        assert!(!verify_signature(&pk, bad_msg, &signed));
    }

    // --- Category 1: Input Length Variation Tests ---

    #[test]
    fn test_sign_verify_empty_message() {
        let (pk, sk) = dilithium_keypair();
        let msg = b""; // Empty message
        let signed = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &signed));
    }

    #[test]
    fn test_sign_verify_single_byte_message() {
        let (pk, sk) = dilithium_keypair();
        let msg = b"\x01"; // Single byte
        let signed = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &signed));
    }

    // This test requires allocation for the large message
    #[cfg(feature = "alloc")]
    #[test]
    fn test_sign_verify_large_message() {
        let (pk, sk) = dilithium_keypair(); 
        // Create a 1MB message (10MB is excessive for a unit test)
        let msg = vec![0x42; 1 * 1024 * 1024]; 
        let signed = sign_message(&sk, &msg);
        assert!(verify_signature(&pk, &msg, &signed));
    }

    // --- Category 2: Malformed and Edge-Case Input Tests ---

    #[cfg(feature = "alloc")]
    #[test]
    fn test_decapsulate_failure_on_tampering() {
        let mut rng = OsRng;
        let keys = KyberKeys::generate_key_pair(&mut rng).unwrap();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk, &mut rng).unwrap();

        // Tamper with the ciphertext
        let mut bytes = ct.as_bytes().to_vec();
        bytes[0] ^= 0xFF; // Flip first byte
        let tampered_ct = KyberCiphertext::from_bytes(&bytes)
            .expect("tampered ciphertext should have correct length");

        let ss_t = decapsulate_shared_secret(&keys.sk, &tampered_ct);
        
        // Decapsulation of tampered text should not equal original shared secret
        assert_ne!(ss_a.as_bytes(), ss_t.as_bytes());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verify_tampered_signature() {
        let (pk, sk) = dilithium_keypair();
        let msg = b"valid message";
        let signed = sign_message(&sk, msg);

        // Tamper with the signature
        let mut bytes = signed.as_bytes().to_vec();
        
        // ---
        // FIXED: Store length first to avoid borrow error
        // ---
        let last_index = bytes.len() - 1;
        bytes[last_index] ^= 0xFF; // Flip last byte
        
        let tampered_sig = DilithiumSignedMessage::from_bytes(&bytes)
            .expect("tampered signature should have correct length");

        // Verification should fail
        assert!(!verify_signature(&pk, msg, &tampered_sig));
    }
    
    #[test]
    fn test_invalid_key_length() {
        // Test truncated key
        let bad_key_bytes = [0u8; pqcrypto_kyber::kyber1024::public_key_bytes() - 1];
        assert!(KyberPublicKey::from_bytes(&bad_key_bytes).is_err());
        
        // Test oversized key (slicing)
        let bad_key_bytes_long = [0u8; pqcrypto_kyber::kyber1024::public_key_bytes() + 1];
        assert!(KyberPublicKey::from_bytes(&bad_key_bytes_long).is_err());

        // Test truncated ciphertext
        let bad_ct_bytes = [0u8; pqcrypto_kyber::kyber1024::ciphertext_bytes() - 1];
        assert!(KyberCiphertext::from_bytes(&bad_ct_bytes).is_err());
    }

    // --- Category 3: Mismatched Key/Data Tests ---

    #[test]
    fn test_verify_with_wrong_public_key() {
        let (_pk_a, sk_a) = dilithium_keypair();
        let (pk_b, _sk_b) = dilithium_keypair();
        let msg = b"message signed by A";

        let signed = sign_message(&sk_a, msg);
        
        // Verify with pk_b should fail
        assert!(!verify_signature(&pk_b, msg, &signed));
    }

    #[test]
    fn test_decapsulate_with_wrong_secret_key() {
        let mut rng = OsRng;
        let keys_a = KyberKeys::generate_key_pair(&mut rng).unwrap();
        let keys_b = KyberKeys::generate_key_pair(&mut rng).unwrap();

        // Encapsulate to A's public key
        let (ct, ss_a) = encapsulate_shared_secret(&keys_a.pk, &mut rng).unwrap();

        // Decapsulate with B's secret key
        let ss_b = decapsulate_shared_secret(&keys_b.sk, &ct);

        // Secrets should not match
        assert_ne!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    // --- Category 5: Known-Answer Tests (KATs) ---

    #[test]
    #[ignore]
    fn test_known_answer_kem() {
        // TODO: Add hard-coded NIST KAT vectors for Kyber1024
        panic!("Not implemented: Requires NIST KAT vectors");
    }

    #[test]
    #[ignore]
    fn test_known_answer_signature() {
        // TODO: Add hard-coded NIST KAT vectors for Dilithium3
        panic!("Not implemented: Requires NIST KAT vectors");
    }

    // --- Category 6: Security and Side-Channel Tests ---
    
    #[test]
    fn test_deterministic_signatures() {
        // Dilithium signing is deterministic (no RNG)
        let (_pk, sk) = dilithium_keypair();
        let msg = b"test message";
        
        let sig1 = sign_message(&sk, msg);
        let sig2 = sign_message(&sk, msg);

        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }
    
    // NOTE: test_zeroization_on_drop_secret_key requires complex unsafe code
    // and memory inspection, and is omitted as a standard unit test.

    // --- Category 7: State and Lifecycle Tests ---
    
    #[test]
    fn test_keypair_serialization_deserialization() {
        let mut rng = OsRng;
        let (pk_dil, sk_dil) = dilithium_keypair();
        let keys_kyber = KyberKeys::generate_key_pair(&mut rng).unwrap();

        // Dilithium round-trip
        let pk_dil_bytes = pk_dil.as_bytes();
        let sk_dil_bytes = sk_dil.as_bytes();
        let pk_dil_rt = DilithiumPublicKey::from_bytes(&pk_dil_bytes).unwrap();
        let sk_dil_rt = DilithiumSecretKey::from_bytes(&sk_dil_bytes).unwrap();
        
        assert_eq!(pk_dil.as_bytes(), pk_dil_rt.as_bytes());
        assert_eq!(sk_dil.as_bytes(), sk_dil_rt.as_bytes());

        // Kyber round-trip
        let pk_kyber_bytes = keys_kyber.pk.as_bytes();
        let sk_kyber_bytes = keys_kyber.sk.as_bytes();
        let pk_kyber_rt = KyberPublicKey::from_bytes(&pk_kyber_bytes).unwrap();
        let sk_kyber_rt = KyberSecretKey::from_bytes(&sk_kyber_bytes).unwrap();

        assert_eq!(pk_kyber_bytes, pk_kyber_rt.as_bytes());
        assert_eq!(sk_kyber_bytes, sk_kyber_rt.as_bytes());
    }

    // --- Category 9: Concurrency and Multithreading Tests ---

    #[cfg(feature = "std")]
    #[test]
    fn test_concurrent_operations() {
        let mut rng = OsRng;
        let (pk_dil, sk_dil) = dilithium_keypair();
        let keys_kyber = KyberKeys::generate_key_pair(&mut rng).unwrap();

        // Arc for thread-safe sharing
        let pk_dil_arc = Arc::new(pk_dil);
        let sk_kyber_arc = Arc::new(keys_kyber.sk);
        let pk_kyber_arc = Arc::new(keys_kyber.pk);

        let mut handles = vec![];

        for i in 0..10 {
            // Clone Arcs for each thread
            let pk_dil = Arc::clone(&pk_dil_arc);
            let sk_kyber = Arc::clone(&sk_kyber_arc);
            let pk_kyber = Arc::clone(&pk_kyber_arc);

            handles.push(thread::spawn(move || {
                let mut thread_rng = OsRng;
                let msg = format!("message from thread {}", i).into_bytes();
                
                // Test 1: Concurrent keygen (uses local sk)
                let (local_pk, local_sk) = dilithium_keypair();
                let local_sig = sign_message(&local_sk, &msg);
                assert!(verify_signature(&local_pk, &msg, &local_sig));

                // Test 2: Concurrent verification (uses shared pk)
                let sig = sign_message(&sk_dil, &msg); // Need local SK for this test
                assert!(verify_signature(&pk_dil, &msg, &sig));
                
                // Test 3: Concurrent decapsulation (uses shared sk)
                let (ct, ss_a) = encapsulate_shared_secret(&pk_kyber, &mut thread_rng).unwrap();
                let ss_b = decapsulate_shared_secret(&sk_kyber, &ct);
                assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}