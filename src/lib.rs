// src/lib.rs
#![no_std]
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

    #[test]
    fn test_kyber_kem_round_trip_success() {
        let mut rng = OsRng;
        let keys = KyberKeys::generate_key_pair(&mut rng).unwrap();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk, &mut rng).unwrap();
        let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn test_dilithium_sign_verify_success() {
        let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
        let msg = b"The secure PQC core is audited.";
        let signed = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &signed));

        let bad = b"The secure PQC core is tampered.";
        assert!(!verify_signature(&pk, bad, &signed));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_decapsulation_failure_on_tampering() {
        let mut rng = OsRng;
        let keys = KyberKeys::generate_key_pair(&mut rng).unwrap();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk, &mut rng).unwrap();

        let mut bytes = ct.as_bytes().to_vec();
        bytes[0] ^= 0xFF;

        let tampered = KyberCiphertext::from_bytes(&bytes)
            .expect("tampered ciphertext length");

        let ss_t = decapsulate_shared_secret(&keys.sk, &tampered);
        assert_ne!(ss_a.as_bytes(), ss_t.as_bytes());
    }
}