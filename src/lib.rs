// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7 - Pure Rust Core
// FIPS 140-3 Compliant Post-Quantum Cryptography
// ------------------------------------------------------------------------
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "alloc", any(feature = "aes-gcm")))]
use alloc::vec::Vec;

// === Public Modules ===
pub mod error;
pub mod rng;
pub mod cast;
pub mod state;
pub mod pct;
pub mod preop;

#[cfg(feature = "fips_140_3")]
pub mod csp;

// KAT modules (internal to FIPS POST, not public API)
#[cfg(all(feature = "ml-kem", feature = "fips_140_3"))]
pub(crate) mod kat_kyber;

#[cfg(all(feature = "ml-dsa", feature = "fips_140_3"))]
pub(crate) mod kat_dilithium;

// === Re-exports ===
pub use error::{PqcError, Result};
pub use state::{FipsState, get_fips_state, is_operational, reset_fips_state};
pub use preop::{run_post, run_post_or_panic};

#[cfg(feature = "fips_140_3")]
pub use csp::{CspExportPolicy, get_csp_export_policy};

// === Constants ===
pub const ML_KEM_1024_PK_BYTES: usize = 1568;
pub const ML_KEM_1024_SK_BYTES: usize = 3168;
pub const ML_KEM_1024_CT_BYTES: usize = 1568;
pub const ML_KEM_1024_SS_BYTES: usize = 32;
pub const ML_KEM_KEYGEN_SEED_BYTES: usize = 64;
pub const ML_KEM_ENCAP_SEED_BYTES: usize = 32;

pub const ML_DSA_65_PK_BYTES: usize = 1952;
pub const ML_DSA_65_SK_BYTES: usize = 4032; // Note: libcrux uses 4032, not 4000
pub const ML_DSA_65_SIG_BYTES: usize = 3309; // Note: libcrux uses 3309, not 3293
pub const ML_DSA_KEYGEN_SEED_BYTES: usize = 32; // ML-DSA uses 32-byte seed
pub const ML_DSA_SIGN_SEED_BYTES: usize = 32;

#[cfg(feature = "aes-gcm")]
pub const AES_KEY_BYTES: usize = 32;
#[cfg(feature = "aes-gcm")]
pub const AES_NONCE_BYTES: usize = 12;

// === ML-KEM (Kyber) Types ===
#[cfg(feature = "ml-kem")]
use libcrux_ml_kem::mlkem1024::{
    MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
    generate_key_pair, encapsulate, decapsulate,
};

#[cfg(feature = "ml-kem")]
pub type KyberPublicKey = MlKem1024PublicKey;
#[cfg(feature = "ml-kem")]
pub type KyberSecretKey = MlKem1024PrivateKey;
#[cfg(feature = "ml-kem")]
pub type KyberCiphertext = MlKem1024Ciphertext;
#[cfg(feature = "ml-kem")]
pub type KyberSharedSecret = [u8; 32]; // ML-KEM shared secret is 32 bytes

/// Kyber key pair wrapper
#[cfg(feature = "ml-kem")]
pub struct KyberKeys {
    pub pk: KyberPublicKey,
    pub sk: KyberSecretKey,
}

#[cfg(feature = "ml-kem")]
impl KyberKeys {
    /// Generate a new Kyber key pair (requires std feature)
    #[cfg(feature = "std")]
    pub fn generate_key_pair() -> Self {
        let seed = rng::generate_seed_64();
        Self::generate_key_pair_with_seed(seed)
    }

    /// Generate key pair from provided seed
    pub fn generate_key_pair_with_seed(seed: [u8; ML_KEM_KEYGEN_SEED_BYTES]) -> Self {
        rng::validate_seed_64(&seed);
        let _secure = rng::SecureSeed(seed);
        let keypair = generate_key_pair(seed);
        // Clone returns arrays, use .into() to convert to wrapper types
        Self { 
            pk: keypair.pk().clone().into(),
            sk: keypair.sk().clone().into(),
        }
    }

    /// Generate key pair with PCT validation (FIPS mode)
    #[cfg(feature = "std")]
    pub fn generate_key_pair_with_pct() -> Result<Self> {
        let keys = Self::generate_key_pair();
        pct::kyber_pct(&keys)?;
        Ok(keys)
    }

    /// Generate key pair with seed and PCT validation
    pub fn generate_key_pair_with_seed_and_pct(
        seed: [u8; ML_KEM_KEYGEN_SEED_BYTES]
    ) -> Result<Self> {
        let keys = Self::generate_key_pair_with_seed(seed);
        pct::kyber_pct(&keys)?;
        Ok(keys)
    }
}

// === ML-DSA (Dilithium) Types ===
#[cfg(feature = "ml-dsa")]
use libcrux_ml_dsa::ml_dsa_65::{
    MLDSA65SigningKey, MLDSA65VerificationKey, MLDSA65Signature,
    generate_key_pair as dsa_generate_key_pair,
    sign as dsa_sign,
    verify as dsa_verify,
};

#[cfg(feature = "ml-dsa")]
pub type DilithiumPublicKey = MLDSA65VerificationKey;
#[cfg(feature = "ml-dsa")]
pub type DilithiumSecretKey = MLDSA65SigningKey;
#[cfg(feature = "ml-dsa")]
pub type DilithiumSignature = MLDSA65Signature;

// === ML-KEM Functions ===

#[cfg(feature = "ml-kem")]
pub fn encapsulate_shared_secret(
    _pk: &KyberPublicKey
) -> (KyberCiphertext, KyberSharedSecret) {
    #[cfg(feature = "std")]
    {
        let randomness = rng::generate_seed_32();
        encapsulate_shared_secret_with_randomness(_pk, randomness)
    }
    #[cfg(not(feature = "std"))]
    {
        panic!("encapsulate_shared_secret requires std feature or use encapsulate_shared_secret_with_randomness");
    }
}

#[cfg(feature = "ml-kem")]
pub fn encapsulate_shared_secret_with_randomness(
    pk: &KyberPublicKey,
    randomness: [u8; ML_KEM_ENCAP_SEED_BYTES]
) -> (KyberCiphertext, KyberSharedSecret) {
    rng::validate_seed_32(&randomness);
    let _secure = rng::SecureSeed32(randomness);
    encapsulate(pk, randomness)
}

#[cfg(feature = "ml-kem")]
pub fn decapsulate_shared_secret(
    sk: &KyberSecretKey,
    ct: &KyberCiphertext
) -> KyberSharedSecret {
    decapsulate(sk, ct)
}

// === ML-DSA Functions ===

#[cfg(feature = "ml-dsa")]
pub fn generate_dilithium_keypair() -> (DilithiumPublicKey, DilithiumSecretKey) {
    #[cfg(feature = "std")]
    {
        let seed = rng::generate_seed_32(); // ML-DSA uses 32-byte seed
        generate_dilithium_keypair_with_seed(seed)
    }
    #[cfg(not(feature = "std"))]
    {
        panic!("generate_dilithium_keypair requires std feature or use generate_dilithium_keypair_with_seed");
    }
}

#[cfg(feature = "ml-dsa")]
pub fn generate_dilithium_keypair_with_seed(
    seed: [u8; ML_DSA_KEYGEN_SEED_BYTES]
) -> (DilithiumPublicKey, DilithiumSecretKey) {
    rng::validate_seed_32(&seed);
    let _secure = rng::SecureSeed32(seed);
    let keypair = dsa_generate_key_pair(seed);
    // ML-DSA keypair fields are public, just clone them directly
    // No need to convert through bytes
    (keypair.verification_key, keypair.signing_key)
}

#[cfg(feature = "ml-dsa")]
pub fn generate_dilithium_keypair_with_pct() -> Result<(DilithiumPublicKey, DilithiumSecretKey)> {
    let (pk, sk) = generate_dilithium_keypair();
    pct::dilithium_pct(&pk, &sk)?;
    Ok((pk, sk))
}

#[cfg(feature = "ml-dsa")]
pub fn sign_message(_sk: &DilithiumSecretKey, _msg: &[u8]) -> DilithiumSignature {
    #[cfg(feature = "std")]
    {
        let randomness = rng::generate_seed_32();
        sign_message_with_randomness(_sk, _msg, randomness)
    }
    #[cfg(not(feature = "std"))]
    {
        panic!("sign_message requires std feature or use sign_message_with_randomness");
    }
}

#[cfg(feature = "ml-dsa")]
pub fn sign_message_with_randomness(
    sk: &DilithiumSecretKey,
    msg: &[u8],
    randomness: [u8; ML_DSA_SIGN_SEED_BYTES]
) -> DilithiumSignature {
    rng::validate_seed_32(&randomness);
    let _secure = rng::SecureSeed32(randomness);
    // libcrux sign takes: signing_key, message, context, randomness
    // context is typically empty for standard usage
    dsa_sign(sk, msg, &[], randomness)
        .expect("Signing failed - this should not happen with valid keys")
}

#[cfg(feature = "ml-dsa")]
pub fn verify_signature(
    pk: &DilithiumPublicKey,
    msg: &[u8],
    sig: &DilithiumSignature
) -> bool {
    // libcrux verify takes: verification_key, message, context, signature
    dsa_verify(pk, msg, &[], sig).is_ok()
}

// === AES-GCM Functions ===

#[cfg(feature = "aes-gcm")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

#[cfg(feature = "aes-gcm")]
pub fn encrypt_aes_gcm(
    key_bytes: &[u8; AES_KEY_BYTES],
    nonce_bytes: &[u8; AES_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, plaintext)
        .map_err(|_| PqcError::AesGcmOperationFailed)
}

#[cfg(feature = "aes-gcm")]
pub fn decrypt_aes_gcm(
    key_bytes: &[u8; AES_KEY_BYTES],
    nonce_bytes: &[u8; AES_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| PqcError::AesGcmOperationFailed)
}

// === Tests ===
#[cfg(test)]
mod tests {
    #[cfg(any(feature = "ml-kem", feature = "ml-dsa", feature = "aes-gcm"))]
    use super::*;

    #[test]
    #[cfg(all(feature = "ml-kem", feature = "std"))]
    fn test_kyber_roundtrip() {
        let keys = KyberKeys::generate_key_pair();
        let (ct, ss1) = encapsulate_shared_secret(&keys.pk);
        let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
        
        // Compare shared secrets (they're both [u8; 32])
        assert_eq!(ss1, ss2);
    }

    #[test]
    #[cfg(all(feature = "ml-dsa", feature = "std"))]
    fn test_dilithium_sign_verify() {
        let (pk, sk) = generate_dilithium_keypair();
        let msg = b"test message";
        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
    }

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    fn test_aes_gcm_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"secret data";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
}