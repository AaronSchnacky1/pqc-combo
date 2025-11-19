// ------------------------------------------------------------------------
// PQC-COMBO Integration Tests
// Basic crypto operation tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "ml-kem", feature = "ml-dsa", feature = "aes-gcm"))]
    use pqc_combo::*;

    #[test]
    #[cfg(all(feature = "ml-kem", feature = "std"))]
    fn test_ml_kem_roundtrip() {
        let keys = KyberKeys::generate_key_pair();
        let (ct, ss1) = encapsulate_shared_secret(&keys.pk);
        let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    #[cfg(all(feature = "ml-dsa", feature = "std"))]
    fn test_ml_dsa_sign_verify() {
        let (pk, sk) = generate_dilithium_keypair();
        let msg = b"hello pqc";
        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
    }

    #[test]
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    fn test_aes_gcm_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let pt = b"secret";
        let ct = encrypt_aes_gcm(&key, &nonce, pt).unwrap();
        let pt2 = decrypt_aes_gcm(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, &pt2[..]);
    }
}