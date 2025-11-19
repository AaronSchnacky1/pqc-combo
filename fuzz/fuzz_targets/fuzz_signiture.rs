#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_combo::*;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 64 {
        let keygen_seed: [u8; 32] = data[..32].try_into().unwrap();
        let sign_seed: [u8; 32] = data[32..64].try_into().unwrap();
        
        if keygen_seed.iter().any(|&b| b != 0) && sign_seed.iter().any(|&b| b != 0) {
            let (pk, sk) = generate_dilithium_keypair_with_seed(keygen_seed);
            let msg = if data.len() > 64 { &data[64..] } else { b"test" };
            let sig = sign_message_with_randomness(&sk, msg, sign_seed);
            assert!(verify_signature(&pk, msg, &sig));
        }
    }
});