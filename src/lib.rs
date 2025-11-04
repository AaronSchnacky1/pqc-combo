#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "alloc", allow(unused_imports))]

#[cfg(feature = "alloc")]
extern crate alloc;

// --- Imports for Kyber ---
use pqcrypto_kyber::kyber1024::{
    self, Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
    SharedSecret as KyberSharedSecret,
};

// --- Imports for Dilithium ---
use pqcrypto_dilithium::dilithium3::{
    open, sign, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};

// Import Ciphertext ONLY when alloc is enabled (used in tampering test)
#[cfg(feature = "alloc")]
use pqcrypto_traits::kem::Ciphertext;

// Import SharedSecret trait for .as_bytes()
use pqcrypto_traits::kem::SharedSecret;

// --- Imports for AES-GCM (NEW) ---
#[cfg(feature = "aes-gcm")]
use aes_gcm_crate::{
    // Import all traits and types from the `aead` module
    aead::{AeadInPlace, Key, KeyInit, Nonce, Tag},
    // Import the concrete cipher type
    Aes256Gcm,
};

// Import Aead trait only when alloc is enabled
#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
use aes_gcm_crate::aead::Aead;

// Import OsRng for nonce generation ONLY when std is on
#[cfg(all(feature = "aes-gcm", feature = "std"))]
use rand_core::{OsRng, RngCore}; // Import RngCore

// Import Vec for alloc-based AES functions
#[cfg(all(feature = "aes-gcm", feature = "alloc"))]
use alloc::vec::Vec;

// (GenericArray is imported via the `Key`, `Nonce`, `Tag` type aliases)

pub mod error;
// RE-ENABLE: Make error types public for new AES functions
pub use error::{PqcError, Result};

// --- Structs and KEM Functions ---

pub struct KyberKeys {
    pub pk: KyberPublicKey,
    pub sk: KyberSecretKey,
}

impl KyberKeys {
    pub fn generate_key_pair() -> Self {
        let (pk, sk) = kyber1024::keypair();
        KyberKeys { pk, sk }
    }
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

// --- NEW: AES-GCM Constants ---

#[cfg(feature = "aes-gcm")]
pub const AES_KEY_BYTES: usize = 32;
#[cfg(feature = "aes-gcm")]
pub const AES_NONCE_BYTES: usize = 12; // 96 bits, standard for GCM
#[cfg(feature = "aes-gcm")]
pub const AES_TAG_BYTES: usize = 16; // 128 bits, standard for GCM

// --- NEW: AES-GCM Helper Functions ---

/// Generates a cryptographically secure 12-byte nonce.
/// REQUIRES: `std` feature (for `OsRng`).
#[cfg(all(feature = "aes-gcm", feature = "std"))]
pub fn generate_aes_nonce() -> [u8; AES_NONCE_BYTES] {
    // Call OsRng manually instead of AeadCore::generate_nonce
    // This avoids the dependency on the `getrandom` feature flag in `aead`.
    let mut nonce_bytes = [0u8; AES_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

/// (alloc feature) Encrypts data using AES-256-GCM.
///
/// This function allocates a new `Vec` for the ciphertext.
/// The ciphertext is `plaintext.len() + 16` bytes (16 bytes for the auth tag).
///
/// # Arguments
/// * `key`: The 32-byte shared secret (e.g., from `decapsulate_shared_secret`).
/// * `nonce`: The 12-byte (96-bit) nonce. **MUST be unique** for every encryption.
/// * `plaintext`: The data to encrypt.
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

/// (alloc feature) Decrypts data using AES-256-GCM.
///
/// This function allocates a new `Vec` for the plaintext.
///
/// # Arguments
/// * `key`: The 32-byte shared secret.
/// * `nonce`: The 12-byte (96-bit) nonce used during encryption.
/// * `ciphertext`: The encrypted data (including 16-byte auth tag).
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

/// (no_alloc) Encrypts data in-place using AES-256-GCM.
///
/// # Arguments
/// * `key`: The 32-byte shared secret.
/// * `nonce`: The 12-byte (96-bit) nonce. **MUST be unique**.
/// * `buffer`: A mutable buffer containing the plaintext.
///   The buffer must be `plaintext.len() + 16` bytes long.
/// * `plaintext_len`: The length of the original plaintext.
///
/// # Returns
/// On success, the buffer's first `plaintext_len` bytes are overwritten
/// with ciphertext, and the final `16` bytes contain the authentication tag.
/// Returns the total ciphertext length (`plaintext_len + 16`).
#[cfg(feature = "aes-gcm")]
#[allow(deprecated)]
pub fn encrypt_aes_gcm_in_place(
    key: &KyberSharedSecret,
    nonce: &[u8; AES_NONCE_BYTES],
    buffer: &mut [u8],
    plaintext_len: usize,
) -> Result<usize> {
    if buffer.len() < plaintext_len + AES_TAG_BYTES {
        // Not enough space for plaintext + tag
        return Err(PqcError::AesGcmOperationFailed);
    }

    let key_array = Key::<Aes256Gcm>::clone_from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(&key_array);
    let nonce_array = Nonce::<Aes256Gcm>::clone_from_slice(nonce);

    // Split buffer into plaintext and tag storage
    let (plaintext_buf, tag_buf) = buffer.split_at_mut(plaintext_len);
    let tag = cipher
        .encrypt_in_place_detached(&nonce_array, b"", plaintext_buf) // b"" = associated data
        .map_err(|_| PqcError::AesGcmOperationFailed)?;

    tag_buf[..AES_TAG_BYTES].copy_from_slice(&tag);

    Ok(plaintext_len + AES_TAG_BYTES)
}

/// (no_alloc) Decrypts data in-place using AES-256-GCM.
///
/// # Arguments
/// * `key`: The 32-byte shared secret.
/// * `nonce`: The 12-byte (96-bit) nonce.
/// * `buffer`: A mutable buffer containing the `ciphertext + 16-byte tag`.
///
/// # Returns
/// Returns a slice `&[u8]` to the plaintext on success.
/// On success, the ciphertext portion of the buffer is overwritten with the plaintext.
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

    // Split buffer into ciphertext and tag
    let ciphertext_len = buffer.len() - AES_TAG_BYTES;
    let (ciphertext_buf, tag_buf) = buffer.split_at_mut(ciphertext_len);
    let tag_array = Tag::<Aes256Gcm>::clone_from_slice(tag_buf);

    cipher
        .decrypt_in_place_detached(&nonce_array, b"", ciphertext_buf, &tag_array)
        .map_err(|_| PqcError::AesGcmOperationFailed)?;

    Ok(ciphertext_buf) // `ciphertext_buf` is now plaintext
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium3::keypair as dilithium_keypair;

    // Import error for new AES tests
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    use super::error::PqcError;

    // --- Imports for advanced tests ---
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
    use rand_core::{RngCore, SeedableRng};

    // --- NEW: AES-GCM Tests (gated) ---

    #[cfg(feature = "aes-gcm")]
    #[test]
    fn test_aes_gcm_round_trip_alloc() {
        // This test runs only when `alloc` (and `aes-gcm`) are on,
        // as it uses the `Vec`-based functions.
        #[cfg(feature = "alloc")]
        {
            // 1. Generate Kyber key to use as AES key
            let keys = KyberKeys::generate_key_pair();
            let (_, shared_secret) = encapsulate_shared_secret(&keys.pk);

            // 2. Define a deterministic nonce and message
            let nonce = [0x42u8; AES_NONCE_BYTES];
            let msg = b"This is a secret message.";

            // 3. Encrypt
            let ciphertext = encrypt_aes_gcm(&shared_secret, &nonce, msg)
                .expect("AES-GCM encryption failed");

            assert_ne!(msg, &ciphertext[..]);
            assert_eq!(ciphertext.len(), msg.len() + AES_TAG_BYTES);

            // 4. Decrypt
            let plaintext = decrypt_aes_gcm(&shared_secret, &nonce, &ciphertext)
                .expect("AES-GCM decryption failed");

            // 5. Verify
            assert_eq!(msg, &plaintext[..]);
        }
    }

    #[cfg(feature = "aes-gcm")]
    #[test]
    fn test_aes_gcm_round_trip_in_place() {
        // This test runs *always* when `aes-gcm` is on (no_alloc).

        // 1. Generate key
        let keys = KyberKeys::generate_key_pair();
        let (_, shared_secret) = encapsulate_shared_secret(&keys.pk);

        // 2. Define nonce and message
        let nonce = [0xABu8; AES_NONCE_BYTES];
        let msg = b"no_alloc secret";
        let msg_len = msg.len();

        // 3. Create buffer on the stack
        let mut buffer = [0u8; 100]; // 100-byte buffer
        buffer[..msg_len].copy_from_slice(msg);

        // 4. Encrypt in place
        let ciphertext_len =
            encrypt_aes_gcm_in_place(&shared_secret, &nonce, &mut buffer, msg_len)
                .expect("in-place encryption failed");

        assert_eq!(ciphertext_len, msg_len + AES_TAG_BYTES);
        assert_ne!(&buffer[..msg_len], msg); // Plaintext should be overwritten

        // 5. Decrypt in place
        // We pass the slice containing [ciphertext | tag]
        let plaintext_slice =
            decrypt_aes_gcm_in_place(&shared_secret, &nonce, &mut buffer[..ciphertext_len])
                .expect("in-place decryption failed");

        // 6. Verify
        assert_eq!(plaintext_slice.len(), msg_len);
        assert_eq!(plaintext_slice, msg);
    }

    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    #[test]
    fn test_aes_gcm_tamper_failure() {
        // Test that decryption fails if ciphertext is tampered
        let keys = KyberKeys::generate_key_pair();
        let (_, shared_secret) = encapsulate_shared_secret(&keys.pk);
        let nonce = [0x01u8; AES_NONCE_BYTES];
        let msg = b"don't tamper with me";

        let mut ciphertext = encrypt_aes_gcm(&shared_secret, &nonce, msg).unwrap();

        // Tamper the ciphertext (flip a bit in the tag)
        let last_byte_index = ciphertext.len() - 1;
        ciphertext[last_byte_index] ^= 0xFF;

        let result = decrypt_aes_gcm(&shared_secret, &nonce, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PqcError::AesGcmOperationFailed);
    }

    // --- Original Tests (Grouped) ---

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

    // --- Category 1: Input Length Variation Tests ---

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

    // --- Category 2: Malformed and Edge-Case Input Tests ---

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

    // --- Category 3: Mismatched Key/Data Tests ---

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

    // --- Category 6: Security and Side-Channel Tests ---

    #[test]
    fn test_deterministic_signatures() {
        let (_pk, sk) = dilithium_keypair();
        let msg = b"test message";
        let sig1 = sign_message(&sk, msg);
        let sig2 = sign_message(&sk, msg);
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }

    // --- Category 7: State and Lifecycle Tests ---

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

    // --- Category 9: Concurrency and Multithreading Tests ---

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

    // --- NEW PRIORITY 1 TESTS (from tests/kats.rs) ---

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

        // --- Kyber ---
        // 1. Generate a valid keypair and SS
        let keys_valid = KyberKeys::generate_key_pair();

        let (ct_valid, ss_valid) = encapsulate_shared_secret(&keys_valid.pk);

        // 2. Create a random Secret Key
        let mut rand_ky_sk_bytes = [0u8; pqcrypto_kyber::kyber1024::secret_key_bytes()];
        rng.fill_bytes(&mut rand_ky_sk_bytes);
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
        let pk_rand = DilithiumPublicKey::from_bytes(&rand_dil_pk_bytes).unwrap();

        // 3. Verifying with random PK should fail
        assert!(
            !verify_signature(&pk_rand, msg, &sig_valid),
            "Signature verified with random PK"
        );
    }

    // --- Category 4: API Misuse (2 Tests) ---

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

    // --- Category 6: Security (1 Test) ---

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

    // --- Category 7: Lifecycle (1 Test) ---

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