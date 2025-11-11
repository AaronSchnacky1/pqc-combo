#![cfg(feature = "std")]
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
//! FIPS 140-3 Compliance Tests
//! 
//! Tests for Conditional Self-Tests (CSTs):
//! - Pair-wise Consistency Test (PCT) for key generation
//! - PCT integration with key generation functions
//! - PCT failure scenarios

use pqc_combo::*;
use pqcrypto_traits::kem::SharedSecret;

#[test]
fn test_kyber_pct_validates_correct_keypair() {
    let keys = KyberKeys::generate_key_pair();
    let result = kyber_pct(&keys);
    assert!(result.is_ok(), "PCT should pass for correctly generated Kyber keys");
}

#[test]
fn test_dilithium_pct_validates_correct_keypair() {
    let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
    let result = dilithium_pct(&pk, &sk);
    assert!(result.is_ok(), "PCT should pass for correctly generated Dilithium keys");
}

#[test]
fn test_kyber_pct_detects_mismatched_keys() {
    // Generate two separate key pairs
    let keys1 = KyberKeys::generate_key_pair();
    let keys2 = KyberKeys::generate_key_pair();
    
    // Create mismatched pair (pk from keys1, sk from keys2)
    let mismatched = KyberKeys {
        pk: keys1.pk,
        sk: keys2.sk,
    };
    
    let result = kyber_pct(&mismatched);
    assert!(result.is_err(), "PCT should fail for mismatched Kyber keys");
    assert_eq!(result.unwrap_err(), PqcError::PairwiseConsistencyTestFailure);
}

#[test]
fn test_dilithium_pct_detects_mismatched_keys() {
    let (pk1, _sk1) = pqcrypto_dilithium::dilithium3::keypair();
    let (_pk2, sk2) = pqcrypto_dilithium::dilithium3::keypair();
    
    let result = dilithium_pct(&pk1, &sk2);
    assert!(result.is_err(), "PCT should fail for mismatched Dilithium keys");
    assert_eq!(result.unwrap_err(), PqcError::PairwiseConsistencyTestFailure);
}

#[test]
fn test_generate_key_pair_with_pct_returns_valid_keys() {
    let result = KyberKeys::generate_key_pair_with_pct();
    assert!(result.is_ok(), "Key generation with PCT should succeed");
    
    let keys = result.unwrap();
    
    // Verify keys work in normal operations
    let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
    let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes(), "Generated keys should work correctly");
}

#[test]
fn test_generate_dilithium_keypair_with_pct_returns_valid_keys() {
    let result = generate_dilithium_keypair_with_pct();
    assert!(result.is_ok(), "Dilithium key generation with PCT should succeed");
    
    let (pk, sk) = result.unwrap();
    
    // Verify keys work in normal operations
    let msg = b"FIPS 140-3 test message";
    let sig = sign_message(&sk, msg);
    assert!(verify_signature(&pk, msg, &sig), "Generated keys should work correctly");
}

#[test]
fn test_pct_repeatable_across_multiple_generations() {
    // Verify PCT consistently passes for multiple key generations
    for i in 0..20 {
        let keys = KyberKeys::generate_key_pair_with_pct()
            .expect(&format!("Kyber PCT failed on iteration {}", i));
        
        // Double-check with explicit PCT call
        assert!(kyber_pct(&keys).is_ok(), "Explicit PCT should also pass");
        
        let (pk, sk) = generate_dilithium_keypair_with_pct()
            .expect(&format!("Dilithium PCT failed on iteration {}", i));
        
        // Double-check with explicit PCT call
        assert!(dilithium_pct(&pk, &sk).is_ok(), "Explicit PCT should also pass");
    }
}

#[test]
fn test_pct_integrated_workflow() {
    // Full workflow using PCT-validated keys
    
    // 1. Generate Kyber keys with PCT
    let kyber_keys = KyberKeys::generate_key_pair_with_pct()
        .expect("Kyber key generation with PCT failed");
    
    // 2. Generate Dilithium keys with PCT
    let (dil_pk, dil_sk) = generate_dilithium_keypair_with_pct()
        .expect("Dilithium key generation with PCT failed");
    
    // 3. Perform KEM operation
    let (ct, ss_sender) = encapsulate_shared_secret(&kyber_keys.pk);
    let ss_receiver = decapsulate_shared_secret(&kyber_keys.sk, &ct);
    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes(), "KEM operation should succeed");
    
    // 4. Perform signature operation
    let msg = b"FIPS 140-3 compliant cryptographic operation";
    let signature = sign_message(&dil_sk, msg);
    assert!(verify_signature(&dil_pk, msg, &signature), "Signature verification should succeed");
    
    // 5. Optional: AES-GCM encryption if feature is enabled
    #[cfg(all(feature = "aes-gcm", feature = "alloc"))]
    {
        let nonce = [0x42u8; AES_NONCE_BYTES];
        let plaintext = b"Encrypted with PCT-validated keys";
        
        let ciphertext = encrypt_aes_gcm(&ss_sender, &nonce, plaintext)
            .expect("AES-GCM encryption should succeed");
        
        let decrypted = decrypt_aes_gcm(&ss_receiver, &nonce, &ciphertext)
            .expect("AES-GCM decryption should succeed");
        
        assert_eq!(plaintext, &decrypted[..], "Decryption should recover original plaintext");
    }
}

#[cfg(feature = "std")]
#[test]
fn test_pct_concurrent_key_generation() {
    use std::thread;
    
    let mut handles = vec![];
    
    for i in 0..10 {
        handles.push(thread::spawn(move || {
            // Each thread generates keys with PCT
            let kyber_keys = KyberKeys::generate_key_pair_with_pct()
                .expect(&format!("Thread {} Kyber PCT failed", i));
            
            let (dil_pk, dil_sk) = generate_dilithium_keypair_with_pct()
                .expect(&format!("Thread {} Dilithium PCT failed", i));
            
            // Verify operations work
            let (ct, ss_a) = encapsulate_shared_secret(&kyber_keys.pk);
            let ss_b = decapsulate_shared_secret(&kyber_keys.sk, &ct);
            assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
            
            let msg = format!("Message from thread {}", i).into_bytes();
            let sig = sign_message(&dil_sk, &msg);
            assert!(verify_signature(&dil_pk, &msg, &sig));
        }));
    }
    
    for handle in handles {
        handle.join().expect("Thread panicked during PCT test");
    }
}

#[test]
fn test_pct_performance_overhead_acceptable() {
    use std::time::Instant;
    
    // Measure key generation with PCT
    let start = Instant::now();
    for _ in 0..10 {
        let _keys = KyberKeys::generate_key_pair_with_pct().unwrap();
    }
    let with_pct = start.elapsed();
    
    // PCT overhead should be minimal (single encap/decap cycle)
    // This is more of a sanity check than a strict requirement
    println!("10 Kyber key generations with PCT: {:?}", with_pct);
    
    let start = Instant::now();
    for _ in 0..10 {
        let _keys = generate_dilithium_keypair_with_pct().unwrap();
    }
    let with_pct_dil = start.elapsed();
    
    println!("10 Dilithium key generations with PCT: {:?}", with_pct_dil);
    
    // Just verify they complete in reasonable time (not strict performance test)
    assert!(with_pct.as_secs() < 5, "Kyber PCT should complete quickly");
    assert!(with_pct_dil.as_secs() < 5, "Dilithium PCT should complete quickly");
}