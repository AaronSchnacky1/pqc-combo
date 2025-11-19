#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_combo::*;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let seed: [u8; 32] = data[..32].try_into().unwrap();
        
        if seed.iter().any(|&b| b != 0) {
            let (pk, sk) = generate_dilithium_keypair_with_seed(seed);
            
            let msg = if data.len() > 32 { &data[32..] } else { b"test" };
            let sig = sign_message(&sk, msg);
            assert!(verify_signature(&pk, msg, &sig));
        }
    }
});