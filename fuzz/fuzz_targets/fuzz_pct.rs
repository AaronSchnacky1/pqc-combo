#![no_main]
//! Fuzzing for Pair-wise Consistency Tests
//! 
//! Tests that PCTs always pass for valid keys and always fail for mismatched keys

use libfuzzer_sys::fuzz_target;
use pqc_combo::*;
use pqc_combo::pct::{kyber_pct, dilithium_pct};

fuzz_target!(|data: &[u8]| {
    if data.len() >= 96 {
        // Split data for different seeds
        let kem_seed: [u8; 64] = data[..64].try_into().unwrap();
        let dsa_seed: [u8; 32] = data[64..96].try_into().unwrap();
        
        // Validate seeds
        if kem_seed.iter().any(|&b| b != 0) {
            // Test Kyber PCT
            let keys = KyberKeys::generate_key_pair_with_seed(kem_seed);
            
            // PCT should pass for valid keys
            assert!(
                kyber_pct(&keys).is_ok(),
                "PCT failed for valid Kyber keys"
            );
            
            // Test with mismatched keys
            if data.len() >= 160 {
                let mut other_seed = kem_seed;
                other_seed[0] ^= 0xFF;
                let other_keys = KyberKeys::generate_key_pair_with_seed(other_seed);
                
                let mismatched = KyberKeys {
                    pk: keys.pk,
                    sk: other_keys.sk,
                };
                
                // PCT should fail for mismatched keys
                assert!(
                    kyber_pct(&mismatched).is_err(),
                    "PCT passed for mismatched Kyber keys!"
                );
            }
        }
        
        if dsa_seed.iter().any(|&b| b != 0) {
            // Test Dilithium PCT
            let (pk, sk) = generate_dilithium_keypair_with_seed(dsa_seed);
            
            // PCT should pass for valid keys
            assert!(
                dilithium_pct(&pk, &sk).is_ok(),
                "PCT failed for valid Dilithium keys"
            );
            
            // Test with mismatched keys
            if data.len() >= 128 {
                let mut other_seed = dsa_seed;
                other_seed[0] ^= 0xFF;
                let (_, sk_other) = generate_dilithium_keypair_with_seed(other_seed);
                
                // PCT should fail for mismatched keys
                assert!(
                    dilithium_pct(&pk, &sk_other).is_err(),
                    "PCT passed for mismatched Dilithium keys!"
                );
            }
        }
    }
});
