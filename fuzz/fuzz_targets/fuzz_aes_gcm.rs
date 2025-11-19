#![no_main]
//! Fuzzing for AES-256-GCM operations
//! 
//! Tests encryption/decryption with various inputs

use libfuzzer_sys::fuzz_target;
use pqc_combo::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 44 {
        return; // Need at least key + nonce
    }
    
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let plaintext = &data[44..];
    
    // Test encryption/decryption roundtrip
    if let Ok(ciphertext) = encrypt_aes_gcm(&key, &nonce, plaintext) {
        if let Ok(decrypted) = decrypt_aes_gcm(&key, &nonce, &ciphertext) {
            assert_eq!(
                plaintext,
                &decrypted[..],
                "Decrypted plaintext doesn't match original"
            );
        }
    }
    
    // Test with wrong key (should fail)
    if let Ok(ciphertext) = encrypt_aes_gcm(&key, &nonce, plaintext) {
        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        
        let result = decrypt_aes_gcm(&wrong_key, &nonce, &ciphertext);
        assert!(
            result.is_err(),
            "Decryption with wrong key should fail"
        );
    }
    
    // Test with modified ciphertext (should fail)
    if let Ok(mut ciphertext) = encrypt_aes_gcm(&key, &nonce, plaintext) {
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
            
            let result = decrypt_aes_gcm(&key, &nonce, &ciphertext);
            assert!(
                result.is_err(),
                "Decryption of tampered ciphertext should fail"
            );
        }
    }
    
    // Test with wrong nonce (should fail or produce different plaintext)
    if let Ok(ciphertext) = encrypt_aes_gcm(&key, &nonce, plaintext) {
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0xFF;
        
        let result = decrypt_aes_gcm(&key, &wrong_nonce, &ciphertext);
        if let Ok(decrypted) = result {
            // If it doesn't fail, it should produce different plaintext
            assert_ne!(
                plaintext,
                &decrypted[..],
                "Wrong nonce produced correct plaintext"
            );
        }
    }
    
    // Test empty plaintext
    if let Ok(ciphertext) = encrypt_aes_gcm(&key, &nonce, b"") {
        if let Ok(decrypted) = decrypt_aes_gcm(&key, &nonce, &ciphertext) {
            assert!(decrypted.is_empty(), "Empty plaintext should decrypt to empty");
        }
    }
});
