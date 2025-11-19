#![no_main]
//! Structure-Aware Fuzzing for ML-KEM
//! 
//! This fuzzer uses structured input to test specific code paths
//! rather than purely random data.

use libfuzzer_sys::{fuzz_target, arbitrary::{Arbitrary, Unstructured}};
use pqc_combo::*;

/// Structured fuzzing input for ML-KEM operations
#[derive(Debug)]
struct KemFuzzInput {
    keygen_seed: [u8; 64],
    encap_seed: [u8; 32],
    operation: KemOperation,
}

#[derive(Debug, Clone, Copy)]
enum KemOperation {
    NormalFlow,
    CrossKeyDecap,
    RepeatedEncap,
    ModifiedCiphertext,
}

impl<'a> Arbitrary<'a> for KemFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate valid seeds (not all zeros)
        let mut keygen_seed = [0u8; 64];
        u.fill_buffer(&mut keygen_seed)?;
        if keygen_seed.iter().all(|&b| b == 0) {
            keygen_seed[0] = 1; // Ensure not all zeros
        }
        
        let mut encap_seed = [0u8; 32];
        u.fill_buffer(&mut encap_seed)?;
        if encap_seed.iter().all(|&b| b == 0) {
            encap_seed[0] = 1;
        }
        
        let operation = match u.int_in_range(0..=3)? {
            0 => KemOperation::NormalFlow,
            1 => KemOperation::CrossKeyDecap,
            2 => KemOperation::RepeatedEncap,
            3 => KemOperation::ModifiedCiphertext,
            _ => unreachable!(),
        };
        
        Ok(KemFuzzInput {
            keygen_seed,
            encap_seed,
            operation,
        })
    }
}

fuzz_target!(|input: KemFuzzInput| {
    match input.operation {
        KemOperation::NormalFlow => {
            // Test normal encap/decap flow
            let keys = KyberKeys::generate_key_pair_with_seed(input.keygen_seed);
            let (ct, ss1) = encapsulate_shared_secret_with_randomness(&keys.pk, input.encap_seed);
            let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
            
            assert_eq!(ss1, ss2, "Normal flow: shared secrets don't match");
        },
        
        KemOperation::CrossKeyDecap => {
            // Test decapsulation with wrong key (should produce different SS)
            let keys1 = KyberKeys::generate_key_pair_with_seed(input.keygen_seed);
            
            // Generate second key from modified seed
            let mut seed2 = input.keygen_seed;
            seed2[0] ^= 0xFF;
            let keys2 = KyberKeys::generate_key_pair_with_seed(seed2);
            
            let (ct, ss_correct) = encapsulate_shared_secret_with_randomness(&keys1.pk, input.encap_seed);
            let ss_wrong = decapsulate_shared_secret(&keys2.sk, &ct);
            
            // Wrong key should produce different shared secret
            assert_ne!(ss_correct, ss_wrong, "Wrong key produced same shared secret!");
        },
        
        KemOperation::RepeatedEncap => {
            // Test that repeated encapsulation with same seed is deterministic
            let keys = KyberKeys::generate_key_pair_with_seed(input.keygen_seed);
            
            let (ct1, ss1) = encapsulate_shared_secret_with_randomness(&keys.pk, input.encap_seed);
            let (ct2, ss2) = encapsulate_shared_secret_with_randomness(&keys.pk, input.encap_seed);
            
            assert_eq!(ct1.as_slice(), ct2.as_slice(), "Encapsulation not deterministic!");
            assert_eq!(ss1, ss2, "Shared secrets not deterministic!");
        },
        
        KemOperation::ModifiedCiphertext => {
            // Test that modified ciphertext produces different shared secret
            let keys = KyberKeys::generate_key_pair_with_seed(input.keygen_seed);
            let (ct, ss_original) = encapsulate_shared_secret_with_randomness(&keys.pk, input.encap_seed);
            
            // Modify ciphertext
            let mut ct_bytes: Vec<u8> = ct.as_slice().to_vec();
            if !ct_bytes.is_empty() {
                ct_bytes[0] ^= 0xFF;
            }
            
            // Reconstruct ciphertext
            if let Ok(ct_array) = <[u8; ML_KEM_1024_CT_BYTES]>::try_from(ct_bytes.as_slice()) {
                let ct_modified = KyberCiphertext::from(ct_array);
                let ss_modified = decapsulate_shared_secret(&keys.sk, &ct_modified);
                
                // Modified ciphertext should produce different shared secret
                // (with very high probability)
                if ss_original == ss_modified {
                    // This is extremely unlikely but not impossible
                    // Just log it, don't panic
                    eprintln!("Warning: Modified ciphertext produced same shared secret (collision)");
                }
            }
        },
    }
});
