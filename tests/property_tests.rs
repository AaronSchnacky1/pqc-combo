use proptest::prelude::*;
use pqc_combo::*;

// Strategy for generating valid 64-byte seeds
fn valid_seed_64() -> impl Strategy<Value = [u8; 64]> {
    prop::collection::vec(any::<u8>(), 64..=64)
        .prop_filter("seed must not be all zeros", |v| {
            v.iter().any(|&b| b != 0)
        })
        .prop_map(|v| {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&v);
            arr
        })
}

// Strategy for generating valid 32-byte seeds
fn valid_seed_32() -> impl Strategy<Value = [u8; 32]> {
    prop::collection::vec(any::<u8>(), 32..=32)
        .prop_filter("seed must not be all zeros", |v| {
            v.iter().any(|&b| b != 0)
        })
        .prop_map(|v| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // ======== ML-KEM Properties ========

    #[test]
    fn prop_kyber_roundtrip(seed in valid_seed_64()) {
        let keys = KyberKeys::generate_key_pair_with_seed(seed);
        let (ct, ss1) = encapsulate_shared_secret(&keys.pk);
        let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
        prop_assert_eq!(ss1, ss2);
    }

    #[test]
    fn prop_kyber_deterministic(
        keygen_seed in valid_seed_64(),
        encap_seed in valid_seed_32()
    ) {
        let keys1 = KyberKeys::generate_key_pair_with_seed(keygen_seed);
        let keys2 = KyberKeys::generate_key_pair_with_seed(keygen_seed);
        
        prop_assert_eq!(keys1.pk.as_slice(), keys2.pk.as_slice());
        prop_assert_eq!(keys1.sk.as_slice(), keys2.sk.as_slice());
        
        let (ct1, ss1) = encapsulate_shared_secret_with_randomness(&keys1.pk, encap_seed);
        let (ct2, ss2) = encapsulate_shared_secret_with_randomness(&keys2.pk, encap_seed);
        
        prop_assert_eq!(ct1.as_slice(), ct2.as_slice());
        prop_assert_eq!(ss1, ss2);
    }

    #[test]
    fn prop_kyber_different_seeds_different_keys(
        seed1 in valid_seed_64(),
        seed2 in valid_seed_64()
    ) {
        prop_assume!(seed1 != seed2);
        
        let keys1 = KyberKeys::generate_key_pair_with_seed(seed1);
        let keys2 = KyberKeys::generate_key_pair_with_seed(seed2);
        
        prop_assert_ne!(keys1.pk.as_slice(), keys2.pk.as_slice());
        prop_assert_ne!(keys1.sk.as_slice(), keys2.sk.as_slice());
    }

    #[test]
    fn prop_kyber_wrong_key(
        seed1 in valid_seed_64(),
        seed2 in valid_seed_64()
    ) {
        prop_assume!(seed1 != seed2);
        
        let keys1 = KyberKeys::generate_key_pair_with_seed(seed1);
        let keys2 = KyberKeys::generate_key_pair_with_seed(seed2);
        
        let (ct, ss_correct) = encapsulate_shared_secret(&keys1.pk);
        let ss_wrong = decapsulate_shared_secret(&keys2.sk, &ct);
        
        prop_assert_ne!(ss_correct, ss_wrong);
    }

    #[test]
    fn prop_kyber_key_sizes(seed in valid_seed_64()) {
        let keys = KyberKeys::generate_key_pair_with_seed(seed);
        prop_assert_eq!(keys.pk.as_slice().len(), ML_KEM_1024_PK_BYTES);
        prop_assert_eq!(keys.sk.as_slice().len(), ML_KEM_1024_SK_BYTES);
    }

    // ======== ML-DSA Properties ========

    #[test]
    fn prop_dilithium_roundtrip(
        seed in valid_seed_32(),
        msg in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let (pk, sk) = generate_dilithium_keypair_with_seed(seed);
        let sig = sign_message(&sk, &msg);
        prop_assert!(verify_signature(&pk, &msg, &sig));
    }

    #[test]
    fn prop_dilithium_deterministic(
        keygen_seed in valid_seed_32(),
        sign_seed in valid_seed_32(),
        msg in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let (pk1, sk1) = generate_dilithium_keypair_with_seed(keygen_seed);
        let (pk2, sk2) = generate_dilithium_keypair_with_seed(keygen_seed);
        
        prop_assert_eq!(pk1.as_slice(), pk2.as_slice());
        prop_assert_eq!(sk1.as_slice(), sk2.as_slice());
        
        let sig1 = sign_message_with_randomness(&sk1, &msg, sign_seed);
        let sig2 = sign_message_with_randomness(&sk2, &msg, sign_seed);
        
        prop_assert_eq!(sig1.as_slice(), sig2.as_slice());
    }

    #[test]
    fn prop_dilithium_tamper_detection(
        seed in valid_seed_32(),
        msg in prop::collection::vec(any::<u8>(), 1..1000),
        bit_to_flip in 0usize..8
    ) {
        let (pk, sk) = generate_dilithium_keypair_with_seed(seed);
        let sig = sign_message(&sk, &msg);
        
        let mut tampered = msg.clone();
        tampered[0] ^= 1 << bit_to_flip;
        
        if msg != tampered {
            prop_assert!(!verify_signature(&pk, &tampered, &sig));
        }
    }

    #[test]
    fn prop_dilithium_wrong_key(
        seed1 in valid_seed_32(),
        seed2 in valid_seed_32(),
        msg in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        prop_assume!(seed1 != seed2);
        
        let (_, sk1) = generate_dilithium_keypair_with_seed(seed1);
        let (pk2, _) = generate_dilithium_keypair_with_seed(seed2);
        
        let sig = sign_message(&sk1, &msg);
        prop_assert!(!verify_signature(&pk2, &msg, &sig));
    }

    #[test]
    fn prop_dilithium_key_sizes(seed in valid_seed_32()) {
        let (pk, sk) = generate_dilithium_keypair_with_seed(seed);
        prop_assert_eq!(pk.as_slice().len(), ML_DSA_65_PK_BYTES);
        prop_assert_eq!(sk.as_slice().len(), ML_DSA_65_SK_BYTES);
    }

    #[test]
    fn prop_dilithium_sig_size(
        seed in valid_seed_32(),
        msg in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let (_, sk) = generate_dilithium_keypair_with_seed(seed);
        let sig = sign_message(&sk, &msg);
        prop_assert_eq!(sig.as_slice().len(), ML_DSA_65_SIG_BYTES);
    }

    // ======== PCT Properties ========

    #[test]
    fn prop_pct_kyber_always_passes_valid_keys(seed in valid_seed_64()) {
        let keys = KyberKeys::generate_key_pair_with_seed(seed);
        prop_assert!(crate::pct::kyber_pct(&keys).is_ok());
    }

    #[test]
    fn prop_pct_dilithium_always_passes(seed in valid_seed_32()) {
        let (pk, sk) = generate_dilithium_keypair_with_seed(seed);
        prop_assert!(crate::pct::dilithium_pct(&pk, &sk).is_ok());
    }
}

#[cfg(feature = "aes-gcm")]
mod aes_properties {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_aes_gcm_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 0..1000)
        ) {
            let ciphertext = encrypt_aes_gcm(&key, &nonce, &plaintext).unwrap();
            let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn prop_aes_gcm_wrong_key_fails(
            key1 in prop::array::uniform32(any::<u8>()),
            key2 in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 1..1000)
        ) {
            prop_assume!(key1 != key2);
            
            let ciphertext = encrypt_aes_gcm(&key1, &nonce, &plaintext).unwrap();
            let result = decrypt_aes_gcm(&key2, &nonce, &ciphertext);
            
            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_aes_gcm_tamper_detection(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            plaintext in prop::collection::vec(any::<u8>(), 1..1000),
            byte_to_flip in 0usize..10
        ) {
            let ciphertext = encrypt_aes_gcm(&key, &nonce, &plaintext).unwrap();
            
            let mut tampered = ciphertext.clone();
            if byte_to_flip < tampered.len() {
                tampered[byte_to_flip] ^= 0xFF;
                
                let result = decrypt_aes_gcm(&key, &nonce, &tampered);
                prop_assert!(result.is_err());
            }
        }
    }
}
