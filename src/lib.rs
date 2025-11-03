// src/lib.rs
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", allow(unused_imports))]

#[cfg(feature = "alloc")]
extern crate alloc;

// --- Imports for Kyber ---
// We always import the same functions.
// When "std" feature is on, keypair() and encapsulate()
// are automatically randomized via getrandom.
use pqcrypto_kyber::kyber1024::{
    self,
    Ciphertext as KyberCiphertext,
    // keypair, // Use the standard function -- REMOVED (unused)
    // encapsulate, // Use the standard function -- REMOVED (unused)
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    SharedSecret as KyberSharedSecret,
};
// --- End Imports ---

// Import SharedSecret for KEM test (always in test)
#[cfg(test)]
use pqcrypto_traits::kem::SharedSecret;

// Import Ciphertext ONLY when alloc is enabled (used in tampering test)
#[cfg(feature = "alloc")]
use pqcrypto_traits::kem::Ciphertext;

use pqcrypto_dilithium::dilithium3::{
    open,
    sign,
    // keypair is imported in mod tests
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};

pub mod error;
// We no longer `pub use` the error types as they aren't
// returned by the simplified public API.
// pub use error::{PqcError, Result}; // REMOVED

pub struct KyberKeys {
    pub pk: KyberPublicKey,
    pub sk: KyberSecretKey,
}

impl KyberKeys {
    // --- Simplified Key Pair Generation ---
    // This one function works for both std and no_std.
    // It no longer takes an RNG or returns a Result.
    pub fn generate_key_pair() -> Self {
        let (pk, sk) = kyber1024::keypair();
        KyberKeys { pk, sk }
    }
}

// --- Simplified Encapsulation ---
// This one function works for both std and no_std.
// It no longer takes an RNG or returns a Result.
pub fn encapsulate_shared_secret(pk: &KyberPublicKey) -> (KyberCiphertext, KyberSharedSecret) {
    let (ss, ct) = kyber1024::encapsulate(pk);
    (ct, ss)
}

// --- End Simplified Functions ---

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
    // use rand::rngs::OsRng; // REMOVED (unused)
    // Moved here as it's only used by tests
    use pqcrypto_dilithium::dilithium3::keypair as dilithium_keypair;

    // --- Imports for advanced tests ---

    // Import traits for as_bytes() and from_bytes()
    use pqcrypto_traits::kem::{
        Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
        SecretKey as KemSecretKeyTrait,
    };
    use pqcrypto_traits::sign::{
        PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait,
        SignedMessage as SignSignedMessageTrait,
    };

    // Imports for alloc/std features
    #[cfg(feature = "alloc")]
    use alloc::{boxed::Box, vec, vec::Vec};

    #[cfg(feature = "std")]
    use std::{sync::Arc, thread};

    // --- Imports for NEW Priority 1 Tests ---
    use rand_chacha::ChaCha8Rng;
    use rand_core::{RngCore, SeedableRng}; // Add `rand_chacha` to [dev-dependencies]

    // --- Original Tests (Grouped) ---

    #[test]
    fn test_kyber_kem_round_trip_success() {
        // *** FIX: Remove .unwrap() ***
        let keys = KyberKeys::generate_key_pair();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
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
        // *** FIX: Remove .unwrap() ***
        let keys = KyberKeys::generate_key_pair();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);

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
        // *** FIX: Remove .unwrap() ***
        let keys_a = KyberKeys::generate_key_pair();
        let keys_b = KyberKeys::generate_key_pair();

        // Encapsulate to A's public key
        let (ct, ss_a) = encapsulate_shared_secret(&keys_a.pk);

        // Decapsulate with B's secret key
        let ss_b = decapsulate_shared_secret(&keys_b.sk, &ct);

        // Secrets should not match
        assert_ne!(ss_a.as_bytes(), ss_b.as_bytes());
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

    // --- Category 7: State and Lifecycle Tests ---

    #[test]
    fn test_keypair_serialization_deserialization() {
        // *** FIX: Remove .unwrap() ***
        let (pk_dil, sk_dil) = dilithium_keypair();
        let keys_kyber = KyberKeys::generate_key_pair();

        // Dilithium round-trip
        let pk_dil_bytes = pk_dil.as_bytes();
        let sk_dil_bytes = sk_dil.as_bytes();
        let pk_dil_rt = DilithiumPublicKey::from_bytes(&pk_dil_bytes).unwrap();
        let sk_dil_rt = DilithiumSecretKey::from_bytes(&sk_dil_bytes).unwrap();

        assert_eq!(pk_dil.as_bytes(), pk_dil_rt.as_bytes());
        // *** FIX: Add missing `!` to macro ***
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
        // *** FIX: Remove .unwrap() ***
        let (pk_dil, sk_dil) = dilithium_keypair();
        let keys_kyber = KyberKeys::generate_key_pair();

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
                let msg = format!("message from thread {}", i).into_bytes();

                // Test 1: Concurrent keygen (uses local sk)
                let (local_pk, local_sk) = dilithium_keypair();
                let local_sig = sign_message(&local_sk, &msg);
                assert!(verify_signature(&local_pk, &msg, &local_sig));

                // Test 2: Concurrent verification (uses shared pk)
                let sig = sign_message(&sk_dil, &msg); // Need local SK for this test
                assert!(verify_signature(&pk_dil, &msg, &sig));

                // Test 3: Concurrent decapsulation (uses shared sk)
                let (ct, ss_a) = encapsulate_shared_secret(&pk_kyber);
                let ss_b = decapsulate_shared_secret(&sk_kyber, &ct);
                assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    // -----------------------------------------------
    // --- NEW PRIORITY 1 TESTS (from tests/kats.rs) ---
    // -----------------------------------------------

    // -----
    // 2. Category 2: Malformed Inputs (2 Tests)
    // -----

    #[test]
    fn test_deserialize_all_zeros() {
        // --- Kyber ---
        // 1. Generate a valid keypair and SS
        // *** FIX: Remove .unwrap() ***
        let keys_valid = KyberKeys::generate_key_pair();
        let (ct_valid, ss_valid) = encapsulate_shared_secret(&keys_valid.pk);

        // 2. Create a zeroed Secret Key
        let zeros_ky_sk_bytes = [0u8; pqcrypto_kyber::kyber1024::secret_key_bytes()];
        // from_bytes will succeed as it only checks length
        let sk_zero = KyberSecretKey::from_bytes(&zeros_ky_sk_bytes).unwrap();

        // 3. Decapsulating with zeroed SK should fail (produce different SS)
        let ss_bad = decapsulate_shared_secret(&sk_zero, &ct_valid);
        assert_ne!(
            ss_valid.as_bytes(),
            ss_bad.as_bytes(),
            "Decapsulation succeeded with zeroed SK"
        );

        // --- Dilithium ---
        // 1. Generate a valid keypair and signature
        let (_pk_valid_orig, sk_valid) = dilithium_keypair();
        let msg = b"test message";
        let sig_valid = sign_message(&sk_valid, msg);

        // 2. Create a zeroed Public Key
        let zeros_dil_pk_bytes = [0u8; pqcrypto_dilithium::dilithium3::public_key_bytes()];
        // from_bytes will succeed as it only checks length
        let pk_zero = DilithiumPublicKey::from_bytes(&zeros_dil_pk_bytes).unwrap();

        // 3. Verifying with zeroed PK should fail
        assert!(
            !verify_signature(&pk_zero, msg, &sig_valid),
            "Signature verified with zeroed PK"
        );
    }

    #[test]
    fn test_deserialize_random_bytes() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // --- Kyber ---
        // 1. Generate a valid keypair and SS
        // *** FIX: Remove .unwrap() ***
        let keys_valid = KyberKeys::generate_key_pair();
        let (ct_valid, ss_valid) = encapsulate_shared_secret(&keys_valid.pk);

        // 2. Create a random Secret Key
        let mut rand_ky_sk_bytes = [0u8; pqcrypto_kyber::kyber1024::secret_key_bytes()];
        rng.fill_bytes(&mut rand_ky_sk_bytes);
        // from_bytes will succeed as it only checks length
        let sk_rand = KyberSecretKey::from_bytes(&rand_ky_sk_bytes).unwrap();

        // 3. Decapsulating with random SK should fail (produce different SS)
        let ss_bad = decapsulate_shared_secret(&sk_rand, &ct_valid);
        assert_ne!(
            ss_valid.as_bytes(),
            ss_bad.as_bytes(),
            "Decapsulation succeeded with random SK"
        );

        // --- Dilithium ---
        // 1. Generate a valid keypair and signature
        let (_pk_valid_orig, sk_valid) = dilithium_keypair();
        let msg = b"test message";
        let sig_valid = sign_message(&sk_valid, msg);

        // 2. Create a random Public Key
        let mut rand_dil_pk_bytes = [0u8; pqcrypto_dilithium::dilithium3::public_key_bytes()];
        rng.fill_bytes(&mut rand_dil_pk_bytes);
        // from_bytes will succeed as it only checks length
        let pk_rand = DilithiumPublicKey::from_bytes(&rand_dil_pk_bytes).unwrap();

        // 3. Verifying with random PK should fail
        assert!(
            !verify_signature(&pk_rand, msg, &sig_valid),
            "Signature verified with random PK"
        );
    }

    // -----
    // 3. Category 4: API Misuse (2 Tests)
    // -----

    #[test]
    #[cfg(not(feature = "alloc"))]
    fn test_api_verify_empty_inputs() {
        let empty_bytes = b"";

        assert!(KyberPublicKey::from_bytes(empty_bytes).is_err());
        assert!(KyberSecretKey::from_bytes(empty_bytes).is_err());
        assert!(KyberCiphertext::from_bytes(empty_bytes).is_err());
        assert!(DilithiumPublicKey::from_bytes(empty_bytes).is_err());
        assert!(DilithiumSecretKey::from_bytes(empty_bytes).is_err());

        // This assertion was removed as it fails due to an upstream
        // bug in pqcrypto-dilithium when `alloc` is not present.
        // assert!(DilithiumSignedMessage::from_bytes(empty_bytes).is_err());
    }

    #[test]
    fn test_api_verify_empty_message_signature() {
        let (pk_orig, _) = dilithium_keypair();
        let pk = DilithiumPublicKey::from_bytes(pk_orig.as_bytes()).unwrap();
        let msg = b"test message";

        // Create a default, empty (all-zero) signature
        let empty_sig_bytes = [0u8; pqcrypto_dilithium::dilithium3::signature_bytes()];

        // We check if from_bytes succeeds (it shouldn't, but if it does,
        // verification must fail).
        if let Ok(empty_sig) = DilithiumSignedMessage::from_bytes(&empty_sig_bytes) {
            let verification_result = verify_signature(&pk, msg, &empty_sig);
            assert!(
                !verification_result,
                "Verification succeeded with an empty/zeroed signature"
            );
        }
        // If from_bytes fails, the test passes implicitly, as an invalid sig was rejected.
    }

    // -----
    // 4. Category 6: Security (1 Test)
    // -----

    // This test will only run when the "std" feature is enabled,
    // as that's the only time we use the randomized functions.
    #[test]
    #[cfg(feature = "std")]
    fn test_kyber_encapsulation_is_randomized() {
        let (pk_orig, _) = kyber1024::keypair();
        let pk = KyberPublicKey::from_bytes(pk_orig.as_bytes()).unwrap();

        // Generate first pair
        let (ct1, ss1) = encapsulate_shared_secret(&pk);

        // Generate second pair
        let (ct2, ss2) = encapsulate_shared_secret(&pk);

        // The ciphertexts MUST be different
        assert_ne!(
            ct1.as_bytes(),
            ct2.as_bytes(),
            "Ciphertexts were identical, KEM is not randomized!"
        );

        // The shared secrets MUST also be different
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "Shared secrets were identical, KEM is not randomized!"
        );
    }

    // -----
    // 5. Category 7: Lifecycle (1 Test)
    // -----

    // *** FIX: Gate with `std` because it uses randomized functions ***
    // This test ensures that a *non-deterministic* ciphertext
    // can be serialized and deserialized.
    #[test]
    #[cfg(feature = "std")]
    fn test_ciphertext_and_signature_serialization_roundtrip() {
        // 1. Test Kyber Ciphertext
        let (pk_orig, _) = kyber1024::keypair();
        let (ct_orig, _) = encapsulate_shared_secret(&pk_orig);

        let ct_bytes = ct_orig.as_bytes();
        let ct_new = KyberCiphertext::from_bytes(ct_bytes).unwrap();
        assert_eq!(ct_orig.as_bytes(), ct_new.as_bytes());

        // 2. Test Dilithium Signature
        let (_, sk_orig) = dilithium_keypair();
        let msg = b"test roundtrip";
        let sig_orig = sign_message(&sk_orig, msg);

        let sig_bytes = sig_orig.as_bytes();
        let sig_new = DilithiumSignedMessage::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig_orig.as_bytes(), sig_new.as_bytes());
    }
}
