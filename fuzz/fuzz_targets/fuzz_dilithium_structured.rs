#![no_main]
//! Structure-Aware Fuzzing for ML-DSA
//! 
//! Tests signature operations with structured inputs

use libfuzzer_sys::{fuzz_target, arbitrary::{Arbitrary, Unstructured}};
use pqc_combo::*;

/// Structured fuzzing input for ML-DSA operations
#[derive(Debug)]
struct DsaFuzzInput {
    keygen_seed: [u8; 32],
    sign_seed: [u8; 32],
    message: Vec<u8>,
    operation: DsaOperation,
}

#[derive(Debug, Clone, Copy)]
enum DsaOperation {
    NormalSignVerify,
    WrongKey,
    ModifiedMessage,
    ModifiedSignature,
    EmptyMessage,
    LargeMessage,
    DeterministicCheck,
}

impl<'a> Arbitrary<'a> for DsaFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate valid seeds
        let mut keygen_seed = [0u8; 32];
        u.fill_buffer(&mut keygen_seed)?;
        if keygen_seed.iter().all(|&b| b == 0) {
            keygen_seed[0] = 1;
        }
        
        let mut sign_seed = [0u8; 32];
        u.fill_buffer(&mut sign_seed)?;
        if sign_seed.iter().all(|&b| b == 0) {
            sign_seed[0] = 1;
        }
        
        // Generate message (variable length)
        let msg_len = u.int_in_range(0..=1000)?;
        let message = (0..msg_len)
            .map(|_| u.arbitrary::<u8>())
            .collect::<arbitrary::Result<Vec<u8>>>()?;
        
        let operation = match u.int_in_range(0..=6)? {
            0 => DsaOperation::NormalSignVerify,
            1 => DsaOperation::WrongKey,
            2 => DsaOperation::ModifiedMessage,
            3 => DsaOperation::ModifiedSignature,
            4 => DsaOperation::EmptyMessage,
            5 => DsaOperation::LargeMessage,
            6 => DsaOperation::DeterministicCheck,
            _ => unreachable!(),
        };
        
        Ok(DsaFuzzInput {
            keygen_seed,
            sign_seed,
            message,
            operation,
        })
    }
}

fuzz_target!(|input: DsaFuzzInput| {
    match input.operation {
        DsaOperation::NormalSignVerify => {
            // Test normal sign/verify flow
            let (pk, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            let sig = sign_message_with_randomness(&sk, &input.message, input.sign_seed);
            
            assert!(
                verify_signature(&pk, &input.message, &sig),
                "Normal flow: signature verification failed"
            );
        },
        
        DsaOperation::WrongKey => {
            // Test verification with wrong public key
            let (_, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            
            // Generate different public key
            let mut seed2 = input.keygen_seed;
            seed2[0] ^= 0xFF;
            let (pk_wrong, _) = generate_dilithium_keypair_with_seed(seed2);
            
            let sig = sign_message_with_randomness(&sk, &input.message, input.sign_seed);
            
            // Wrong key should fail verification
            assert!(
                !verify_signature(&pk_wrong, &input.message, &sig),
                "Wrong key verified signature!"
            );
        },
        
        DsaOperation::ModifiedMessage => {
            // Test that modified message fails verification
            let (pk, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            let sig = sign_message_with_randomness(&sk, &input.message, input.sign_seed);
            
            if !input.message.is_empty() {
                let mut modified = input.message.clone();
                modified[0] ^= 0xFF;
                
                assert!(
                    !verify_signature(&pk, &modified, &sig),
                    "Modified message verified!"
                );
            }
        },
        
        DsaOperation::ModifiedSignature => {
            // Test that modified signature fails verification
            let (pk, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            let sig = sign_message_with_randomness(&sk, &input.message, input.sign_seed);
            
            // Modify signature
            let mut sig_bytes = sig.as_slice().to_vec();
            if !sig_bytes.is_empty() {
                sig_bytes[0] ^= 0xFF;
                
                if let Ok(sig_array) = <[u8; ML_DSA_65_SIG_BYTES]>::try_from(sig_bytes.as_slice()) {
                    let sig_modified = DilithiumSignature::from(sig_array);
                    
                    assert!(
                        !verify_signature(&pk, &input.message, &sig_modified),
                        "Modified signature verified!"
                    );
                }
            }
        },
        
        DsaOperation::EmptyMessage => {
            // Test signing empty message
            let (pk, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            let empty_msg = b"";
            let sig = sign_message_with_randomness(&sk, empty_msg, input.sign_seed);
            
            assert!(
                verify_signature(&pk, empty_msg, &sig),
                "Empty message signature failed"
            );
        },
        
        DsaOperation::LargeMessage => {
            // Test signing large message
            let (pk, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            let large_msg = vec![0x42u8; 10_000];
            let sig = sign_message_with_randomness(&sk, &large_msg, input.sign_seed);
            
            assert!(
                verify_signature(&pk, &large_msg, &sig),
                "Large message signature failed"
            );
        },
        
        DsaOperation::DeterministicCheck => {
            // Test deterministic signing
            let (pk, sk) = generate_dilithium_keypair_with_seed(input.keygen_seed);
            
            let sig1 = sign_message_with_randomness(&sk, &input.message, input.sign_seed);
            let sig2 = sign_message_with_randomness(&sk, &input.message, input.sign_seed);
            
            assert_eq!(
                sig1.as_slice(),
                sig2.as_slice(),
                "Signing not deterministic!"
            );
            
            // Both should verify
            assert!(verify_signature(&pk, &input.message, &sig1));
            assert!(verify_signature(&pk, &input.message, &sig2));
        },
    }
});
