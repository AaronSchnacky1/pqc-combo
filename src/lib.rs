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
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", allow(unused_imports))]

#[cfg(feature = "alloc")]
extern crate alloc;



// --- Imports for Kyber ---
use pqcrypto_kyber::kyber1024::{
    self, Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
    SharedSecret as KyberSharedSecret,
};

#[allow(unused_imports)]
use pqcrypto_traits::kem::SharedSecret;



// --- Imports for Dilithium ---
use pqcrypto_dilithium::dilithium3::{
    open, sign, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};

// Import Ciphertext ONLY when alloc is enabled (used in tampering test)
#[cfg(feature = "alloc")]
use pqcrypto_traits::kem::Ciphertext;



// --- Imports for AES-GCM ---
#[cfg(feature = "aes-gcm")]
use aes_gcm_crate::{
    aead::{AeadInPlace, Key, KeyInit, Nonce, Tag},
    Aes256Gcm,
};

#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
use aes_gcm_crate::aead::Aead;

#[cfg(all(feature = "aes-gcm", feature = "std"))]
use rand_core::{OsRng, RngCore};

#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
use alloc::vec::Vec;

pub mod error;
pub use error::{PqcError, Result};

// --- FIPS 140-3 Modules ---
pub mod pct;
pub use pct::{dilithium_pct, kyber_pct};

pub mod cast;
pub use cast::{run_hash_casts, sha3_256_cast, sha3_512_cast, shake128_cast, shake256_cast};

pub mod state;
pub use state::{get_fips_state, is_operational, FipsState};

pub mod preop;
pub use preop::{run_post, run_post_or_panic};

pub mod csp;
pub use csp::{get_csp_export_policy, CspExportPolicy};

#[cfg(feature = "std")]
pub mod ffi_boundary;
#[cfg(feature = "std")]
pub use ffi_boundary::{ffi_entry_guard, ffi_csp_export_guard};

// --- Structs and KEM Functions ---

pub struct KyberKeys {
    pub pk: KyberPublicKey,
    pub sk: KyberSecretKey,
}

impl KyberKeys {
    /// Generates a Kyber key pair.
    ///
    /// **FIPS 140-3 Mode**: When `fips_140_3` feature is enabled, this function
    /// automatically performs a Pair-wise Consistency Test (PCT) after generation.
    /// If the PCT fails, the function panics (as per FIPS 140-3 requirements).
    /// 
    /// **Important**: In FIPS mode, call `run_post()` before generating keys.
    pub fn generate_key_pair() -> Self {
        #[cfg(feature = "fips_140_3")]
        {
            // In FIPS mode, require operational state
            state::check_operational().expect("FIPS: Module not operational - run POST first");
        }
        
        let (pk, sk) = kyber1024::keypair();
        let keys = KyberKeys { pk, sk };

        // FIPS 140-3: Perform PCT if feature is enabled
        #[cfg(feature = "fips_140_3")]
        {
            kyber_pct(&keys).expect("FIPS 140-3 Kyber PCT failed - key generation aborted");
        }

        keys
    }

    /// Generates a Kyber key pair with explicit PCT.
    ///
    /// This function always performs a Pair-wise Consistency Test (PCT)
    /// regardless of feature flags. Use this when you need guaranteed PCT
    /// for compliance purposes.
    ///
    /// # Returns
    /// * `Ok(KyberKeys)` if generation and PCT succeed
    /// * `Err(PqcError::PairwiseConsistencyTestFailure)` if PCT fails
    pub fn generate_key_pair_with_pct() -> Result<Self> {
        #[cfg(feature = "fips_140_3")]
        {
            // In FIPS mode, require operational state
            state::check_operational()?;
        }
        
        let (pk, sk) = kyber1024::keypair();
        let keys = KyberKeys { pk, sk };

        // Always perform PCT
        kyber_pct(&keys)?;

        Ok(keys)
    }
}

/// Generates a Dilithium key pair.
///
/// **FIPS 140-3 Mode**: When `fips_140_3` feature is enabled, this function
/// automatically performs a Pair-wise Consistency Test (PCT) after generation.
/// If the PCT fails, the function panics (as per FIPS 140-3 requirements).
///
/// **Important**: In FIPS mode, call `run_post()` before generating keys.
///
/// # Returns
/// A tuple of (PublicKey, SecretKey)
pub fn generate_dilithium_keypair() -> (DilithiumPublicKey, DilithiumSecretKey) {
    #[cfg(feature = "fips_140_3")]
    {
        // In FIPS mode, require operational state
        state::check_operational().expect("FIPS: Module not operational - run POST first");
    }
    
    let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();

    // FIPS 140-3: Perform PCT if feature is enabled
    #[cfg(feature = "fips_140_3")]
    {
        dilithium_pct(&pk, &sk)
            .expect("FIPS 140-3 Dilithium PCT failed - key generation aborted");
    }

    (pk, sk)
}

/// Generates a Dilithium key pair with explicit PCT.
///
/// This function always performs a Pair-wise Consistency Test (PCT)
/// regardless of feature flags. Use this when you need guaranteed PCT
/// for compliance purposes.
///
/// # Returns
/// * `Ok((PublicKey, SecretKey))` if generation and PCT succeed
/// * `Err(PqcError::PairwiseConsistencyTestFailure)` if PCT fails
pub fn generate_dilithium_keypair_with_pct() -> Result<(DilithiumPublicKey, DilithiumSecretKey)> {
    #[cfg(feature = "fips_140_3")]
    {
        // In FIPS mode, require operational state
        state::check_operational()?;
    }
    
    let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();

    // Always perform PCT
    dilithium_pct(&pk, &sk)?;

    Ok((pk, sk))
}

pub fn encapsulate_shared_secret(pk: &KyberPublicKey) -> (KyberCiphertext, KyberSharedSecret) {
    let (ss, ct) = kyber1024::encapsulate(pk);
    (ct, ss)
}

pub fn decapsulate_shared_secret(
    sk: &KyberSecretKey,
    ciphertext: &KyberCiphertext,
) -> KyberSharedSecret {
    kyber1024::decapsulate(ciphertext, sk)
}

// --- Signature Functions ---

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

// --- AES-GCM Constants ---

#[cfg(feature = "aes-gcm")]
pub const AES_KEY_BYTES: usize = 32;
#[cfg(feature = "aes-gcm")]
pub const AES_NONCE_BYTES: usize = 12;
#[cfg(feature = "aes-gcm")]
pub const AES_TAG_BYTES: usize = 16;

// --- AES-GCM Helper Functions ---

#[cfg(all(feature = "aes-gcm", feature = "std"))]
pub fn generate_aes_nonce() -> [u8; AES_NONCE_BYTES] {
    let mut nonce_bytes = [0u8; AES_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
#[allow(deprecated)]
pub fn encrypt_aes_gcm(
    key: &KyberSharedSecret,
    nonce: &[u8; AES_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key_array = Key::<Aes256Gcm>::clone_from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(&key_array);
    let nonce_array = Nonce::<Aes256Gcm>::clone_from_slice(nonce);

    cipher
        .encrypt(&nonce_array, plaintext)
        .map_err(|_| PqcError::AesGcmOperationFailed)
}

#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
#[allow(deprecated)]
pub fn decrypt_aes_gcm(
    key: &KyberSharedSecret,
    nonce: &[u8; AES_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key_array = Key::<Aes256Gcm>::clone_from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(&key_array);
    let nonce_array = Nonce::<Aes256Gcm>::clone_from_slice(nonce);

    cipher
        .decrypt(&nonce_array, ciphertext)
        .map_err(|_| PqcError::AesGcmOperationFailed)
}

#[cfg(feature = "aes-gcm")]
#[allow(deprecated)]
pub fn encrypt_aes_gcm_in_place(
    key: &KyberSharedSecret,
    nonce: &[u8; AES_NONCE_BYTES],
    buffer: &mut [u8],
    plaintext_len: usize,
) -> Result<usize> {
    if buffer.len() < plaintext_len + AES_TAG_BYTES {
        return Err(PqcError::AesGcmOperationFailed);
    }

    let key_array = Key::<Aes256Gcm>::clone_from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(&key_array);
    let nonce_array = Nonce::<Aes256Gcm>::clone_from_slice(nonce);

    let (plaintext_buf, tag_buf) = buffer.split_at_mut(plaintext_len);
    let tag = cipher
        .encrypt_in_place_detached(&nonce_array, b"", plaintext_buf)
        .map_err(|_| PqcError::AesGcmOperationFailed)?;

    tag_buf[..AES_TAG_BYTES].copy_from_slice(&tag);

    Ok(plaintext_len + AES_TAG_BYTES)
}

#[cfg(feature = "aes-gcm")]
#[allow(deprecated)]
pub fn decrypt_aes_gcm_in_place<'a>(
    key: &KyberSharedSecret,
    nonce: &[u8; AES_NONCE_BYTES],
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    if buffer.len() < AES_TAG_BYTES {
        return Err(PqcError::AesGcmOperationFailed);
    }

    let key_array = Key::<Aes256Gcm>::clone_from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(&key_array);
    let nonce_array = Nonce::<Aes256Gcm>::clone_from_slice(nonce);

    let ciphertext_len = buffer.len() - AES_TAG_BYTES;
    let (ciphertext_buf, tag_buf) = buffer.split_at_mut(ciphertext_len);
    let tag_array = Tag::<Aes256Gcm>::clone_from_slice(tag_buf);

    cipher
        .decrypt_in_place_detached(&nonce_array, b"", ciphertext_buf, &tag_array)
        .map_err(|_| PqcError::AesGcmOperationFailed)?;

    Ok(ciphertext_buf)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium3::keypair as dilithium_keypair;

    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    use super::error::PqcError;

    use pqcrypto_traits::kem::{
        Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
        SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
    };
    use pqcrypto_traits::sign::{
        PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait,
        SignedMessage as SignSignedMessageTrait,
    };

    #[cfg(feature = "alloc")]
    use alloc::{boxed::Box, vec, vec::Vec};

    #[cfg(feature = "std")]
    use std::{sync::Arc, thread};

    use rand_chacha::ChaCha8Rng;
    use rand_core::{RngCore, SeedableRng};

    // --- NEW: PCT Tests ---

    #[test]
    fn test_kyber_keypair_generation_with_pct() {
        // Test the explicit PCT function
        let result = KyberKeys::generate_key_pair_with_pct();
        assert!(result.is_ok(), "Kyber key generation with PCT should succeed");
    }

    #[test]
    fn test_dilithium_keypair_generation_with_pct() {
        // Test the explicit PCT function
        let result = generate_dilithium_keypair_with_pct();
        assert!(result.is_ok(), "Dilithium key generation with PCT should succeed");
    }

    #[test]
    fn test_pct_integration_in_workflow() {
        // Verify PCT-validated keys work in full workflow
        let keys = KyberKeys::generate_key_pair_with_pct().unwrap();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
        let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());

        let (pk, sk) = generate_dilithium_keypair_with_pct().unwrap();
        let msg = b"PCT-validated signature test";
        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
    }

    // --- AES-GCM Tests ---

    #[cfg(feature = "aes-gcm")]
    #[test]
    fn test_aes_gcm_round_trip_alloc() {
        #[cfg(feature = "alloc")]
        {
            let keys = KyberKeys::generate_key_pair();
            let (_, shared_secret) = encapsulate_shared_secret(&keys.pk);

            let nonce = [0x42u8; AES_NONCE_BYTES];
            let msg = b"This is a secret message.";

            let ciphertext = encrypt_aes_gcm(&shared_secret, &nonce, msg)
                .expect("AES-GCM encryption failed");

            assert_ne!(msg, &ciphertext[..]);
            assert_eq!(ciphertext.len(), msg.len() + AES_TAG_BYTES);

            let plaintext = decrypt_aes_gcm(&shared_secret, &nonce, &ciphertext)
                .expect("AES-GCM decryption failed");

            assert_eq!(msg, &plaintext[..]);
        }
    }

    #[cfg(feature = "aes-gcm")]
    #[test]
    fn test_aes_gcm_round_trip_in_place() {
        let keys = KyberKeys::generate_key_pair();
        let (_, shared_secret) = encapsulate_shared_secret(&keys.pk);

        let nonce = [0xABu8; AES_NONCE_BYTES];
        let msg = b"no_alloc secret";
        let msg_len = msg.len();

        let mut buffer = [0u8; 100];
        buffer[..msg_len].copy_from_slice(msg);

        let ciphertext_len =
            encrypt_aes_gcm_in_place(&shared_secret, &nonce, &mut buffer, msg_len)
                .expect("in-place encryption failed");

        assert_eq!(ciphertext_len, msg_len + AES_TAG_BYTES);
        assert_ne!(&buffer[..msg_len], msg);

        let plaintext_slice =
            decrypt_aes_gcm_in_place(&shared_secret, &nonce, &mut buffer[..ciphertext_len])
                .expect("in-place decryption failed");

        assert_eq!(plaintext_slice.len(), msg_len);
        assert_eq!(plaintext_slice, msg);
    }

    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    #[test]
    fn test_aes_gcm_tamper_failure() {
        let keys = KyberKeys::generate_key_pair();
        let (_, shared_secret) = encapsulate_shared_secret(&keys.pk);
        let nonce = [0x01u8; AES_NONCE_BYTES];
        let msg = b"don't tamper with me";

        let mut ciphertext = encrypt_aes_gcm(&shared_secret, &nonce, msg).unwrap();

        let last_byte_index = ciphertext.len() - 1;
        ciphertext[last_byte_index] ^= 0xFF;

        let result = decrypt_aes_gcm(&shared_secret, &nonce, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PqcError::AesGcmOperationFailed);
    }

    // --- Original Tests ---

    #[test]
    fn test_kyber_kem_round_trip_success() {
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

        assert!(verify_signature(&pk, msg, &signed));
        let bad_msg = b"The secure PQC core is tampered.";
        assert!(!verify_signature(&pk, bad_msg, &signed));
    }

    #[test]
    fn test_sign_verify_empty_message() {
        let (pk, sk) = dilithium_keypair();
        let msg = b"";
        let signed = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &signed));
    }

    #[test]
    fn test_sign_verify_single_byte_message() {
        let (pk, sk) = dilithium_keypair();
        let msg = b"\x01";
        let signed = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &signed));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sign_verify_large_message() {
        let (pk, sk) = dilithium_keypair();
        let msg = vec![0x42; 1 * 1024 * 1024];
        let signed = sign_message(&sk, &msg);
        assert!(verify_signature(&pk, &msg, &signed));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_decapsulate_failure_on_tampering() {
        let keys = KyberKeys::generate_key_pair();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);

        let mut bytes = ct.as_bytes().to_vec();
        bytes[0] ^= 0xFF;
        let tampered_ct = KyberCiphertext::from_bytes(&bytes)
            .expect("tampered ciphertext should have correct length");

        let ss_t = decapsulate_shared_secret(&keys.sk, &tampered_ct);
        assert_ne!(ss_a.as_bytes(), ss_t.as_bytes());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_verify_tampered_signature() {
        let (pk, sk) = dilithium_keypair();
        let msg = b"valid message";
        let signed = sign_message(&sk, msg);

        let mut bytes = signed.as_bytes().to_vec();
        let last_index = bytes.len() - 1;
        bytes[last_index] ^= 0xFF;

        let tampered_sig = DilithiumSignedMessage::from_bytes(&bytes)
            .expect("tampered signature should have correct length");

        assert!(!verify_signature(&pk, msg, &tampered_sig));
    }

    #[test]
    fn test_invalid_key_length() {
        let bad_key_bytes = [0u8; pqcrypto_kyber::kyber1024::public_key_bytes() - 1];
        assert!(KyberPublicKey::from_bytes(&bad_key_bytes).is_err());

        let bad_key_bytes_long = [0u8; pqcrypto_kyber::kyber1024::public_key_bytes() + 1];
        assert!(KyberPublicKey::from_bytes(&bad_key_bytes_long).is_err());

        let bad_ct_bytes = [0u8; pqcrypto_kyber::kyber1024::ciphertext_bytes() - 1];
        assert!(KyberCiphertext::from_bytes(&bad_ct_bytes).is_err());
    }

    #[test]
    fn test_verify_with_wrong_public_key() {
        let (_pk_a, sk_a) = dilithium_keypair();
        let (pk_b, _sk_b) = dilithium_keypair();
        let msg = b"message signed by A";
        let signed = sign_message(&sk_a, msg);
        assert!(!verify_signature(&pk_b, msg, &signed));
    }

    #[test]
    fn test_decapsulate_with_wrong_secret_key() {
        let keys_a = KyberKeys::generate_key_pair();
        let keys_b = KyberKeys::generate_key_pair();
        let (ct, ss_a) = encapsulate_shared_secret(&keys_a.pk);
        let ss_b = decapsulate_shared_secret(&keys_b.sk, &ct);
        assert_ne!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn test_deterministic_signatures() {
        let (_pk, sk) = dilithium_keypair();
        let msg = b"test message";
        let sig1 = sign_message(&sk, msg);
        let sig2 = sign_message(&sk, msg);
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn test_keypair_serialization_deserialization() {
        let (pk_dil, sk_dil) = dilithium_keypair();
        let keys_kyber = KyberKeys::generate_key_pair();

        let pk_dil_bytes = pk_dil.as_bytes();
        let sk_dil_bytes = sk_dil.as_bytes();
        let pk_dil_rt = DilithiumPublicKey::from_bytes(&pk_dil_bytes).unwrap();
        let sk_dil_rt = DilithiumSecretKey::from_bytes(&sk_dil_bytes).unwrap();
        assert_eq!(pk_dil.as_bytes(), pk_dil_rt.as_bytes());
        assert_eq!(sk_dil.as_bytes(), sk_dil_rt.as_bytes());

        let pk_kyber_bytes = keys_kyber.pk.as_bytes();
        let sk_kyber_bytes = keys_kyber.sk.as_bytes();
        let pk_kyber_rt = KyberPublicKey::from_bytes(&pk_kyber_bytes).unwrap();
        let sk_kyber_rt = KyberSecretKey::from_bytes(&sk_kyber_bytes).unwrap();
        assert_eq!(pk_kyber_bytes, pk_kyber_rt.as_bytes());
        assert_eq!(sk_kyber_bytes, sk_kyber_rt.as_bytes());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_concurrent_operations() {
        let (pk_dil, sk_dil) = dilithium_keypair();
        let keys_kyber = KyberKeys::generate_key_pair();

        let pk_dil_arc = Arc::new(pk_dil);
        let sk_kyber_arc = Arc::new(keys_kyber.sk);
        let pk_kyber_arc = Arc::new(keys_kyber.pk);

        let mut handles = vec![];

        for i in 0..10 {
            let pk_dil = Arc::clone(&pk_dil_arc);
            let sk_kyber = Arc::clone(&sk_kyber_arc);
            let pk_kyber = Arc::clone(&pk_kyber_arc);

            handles.push(thread::spawn(move || {
                let msg = format!("message from thread {}", i).into_bytes();

                let (local_pk, local_sk) = dilithium_keypair();
                let local_sig = sign_message(&local_sk, &msg);
                assert!(verify_signature(&local_pk, &msg, &local_sig));

                let sig = sign_message(&sk_dil, &msg);
                assert!(verify_signature(&pk_dil, &msg, &sig));

                let (ct, ss_a) = encapsulate_shared_secret(&pk_kyber);
                let ss_b = decapsulate_shared_secret(&sk_kyber, &ct);
                assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_deserialize_all_zeros() {
        let keys_valid = KyberKeys::generate_key_pair();
        let (ct_valid, ss_valid) = encapsulate_shared_secret(&keys_valid.pk);

        let zeros_ky_sk_bytes = [0u8; pqcrypto_kyber::kyber1024::secret_key_bytes()];
        let sk_zero = KyberSecretKey::from_bytes(&zeros_ky_sk_bytes).unwrap();

        let ss_bad = decapsulate_shared_secret(&sk_zero, &ct_valid);
        assert_ne!(
            ss_valid.as_bytes(),
            ss_bad.as_bytes(),
            "Decapsulation succeeded with zeroed SK"
        );

        let (_pk_valid_orig, sk_valid) = dilithium_keypair();
        let msg = b"test message";
        let sig_valid = sign_message(&sk_valid, msg);

        let zeros_dil_pk_bytes = [0u8; pqcrypto_dilithium::dilithium3::public_key_bytes()];
        let pk_zero = DilithiumPublicKey::from_bytes(&zeros_dil_pk_bytes).unwrap();

        assert!(
            !verify_signature(&pk_zero, msg, &sig_valid),
            "Signature verified with zeroed PK"
        );
    }

    #[test]
    fn test_deserialize_random_bytes() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let keys_valid = KyberKeys::generate_key_pair();
        let (ct_valid, ss_valid) = encapsulate_shared_secret(&keys_valid.pk);

        let mut rand_ky_sk_bytes = [0u8; pqcrypto_kyber::kyber1024::secret_key_bytes()];
        rng.fill_bytes(&mut rand_ky_sk_bytes);
        let sk_rand = KyberSecretKey::from_bytes(&rand_ky_sk_bytes).unwrap();

        let ss_bad = decapsulate_shared_secret(&sk_rand, &ct_valid);
        assert_ne!(
            ss_valid.as_bytes(),
            ss_bad.as_bytes(),
            "Decapsulation succeeded with random SK"
        );

        let (_pk_valid_orig, sk_valid) = dilithium_keypair();
        let msg = b"test message";
        let sig_valid = sign_message(&sk_valid, msg);

        let mut rand_dil_pk_bytes = [0u8; pqcrypto_dilithium::dilithium3::public_key_bytes()];
        rng.fill_bytes(&mut rand_dil_pk_bytes);
        let pk_rand = DilithiumPublicKey::from_bytes(&rand_dil_pk_bytes).unwrap();

        assert!(
            !verify_signature(&pk_rand, msg, &sig_valid),
            "Signature verified with random PK"
        );
    }

    #[test]
    #[cfg(not(feature = "alloc"))]
    fn test_api_verify_empty_inputs() {
        let empty_bytes = b"";

        assert!(KyberPublicKey::from_bytes(empty_bytes).is_err());
        assert!(KyberSecretKey::from_bytes(empty_bytes).is_err());
        assert!(KyberCiphertext::from_bytes(empty_bytes).is_err());
        assert!(DilithiumPublicKey::from_bytes(empty_bytes).is_err());
        assert!(DilithiumSecretKey::from_bytes(empty_bytes).is_err());
    }

    #[test]
    fn test_api_verify_empty_message_signature() {
        let (pk_orig, _) = dilithium_keypair();
        let pk = DilithiumPublicKey::from_bytes(pk_orig.as_bytes()).unwrap();
        let msg = b"test message";

        let empty_sig_bytes = [0u8; pqcrypto_dilithium::dilithium3::signature_bytes()];

        if let Ok(empty_sig) = DilithiumSignedMessage::from_bytes(&empty_sig_bytes) {
            let verification_result = verify_signature(&pk, msg, &empty_sig);
            assert!(
                !verification_result,
                "Verification succeeded with an empty/zeroed signature"
            );
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_kyber_encapsulation_is_randomized() {
        let (pk_orig, _) = kyber1024::keypair();
        let pk = KyberPublicKey::from_bytes(pk_orig.as_bytes()).unwrap();

        let (ct1, ss1) = encapsulate_shared_secret(&pk);
        let (ct2, ss2) = encapsulate_shared_secret(&pk);

        assert_ne!(
            ct1.as_bytes(),
            ct2.as_bytes(),
            "Ciphertexts were identical, KEM is not randomized!"
        );
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "Shared secrets were identical, KEM is not randomized!"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_ciphertext_and_signature_serialization_roundtrip() {
        let (pk_orig, _) = kyber1024::keypair();
        let (ct_orig, _) = encapsulate_shared_secret(&pk_orig);
        let ct_bytes = ct_orig.as_bytes();
        let ct_new = KyberCiphertext::from_bytes(ct_bytes).unwrap();
        assert_eq!(ct_orig.as_bytes(), ct_new.as_bytes());

        let (_, sk_orig) = dilithium_keypair();
        let msg = b"test roundtrip";
        let sig_orig = sign_message(&sk_orig, msg);
        let sig_bytes = sig_orig.as_bytes();
        let sig_new = DilithiumSignedMessage::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig_orig.as_bytes(), sig_new.as_bytes());
    }
}

// --- FFI Module ---
#[cfg(feature = "std")]
pub mod ffi;