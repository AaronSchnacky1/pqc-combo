#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_combo::*;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 96 {
        let keygen_seed: [u8; 64] = data[..64].try_into().unwrap();
        let encap_seed: [u8; 32] = data[64..96].try_into().unwrap();
        
        if keygen_seed.iter().any(|&b| b != 0) && encap_seed.iter().any(|&b| b != 0) {
            let keys = KyberKeys::generate_key_pair_with_seed(keygen_seed);
            let (ct, ss1) = encapsulate_shared_secret_with_randomness(&keys.pk, encap_seed);
            let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
            assert_eq!(ss1, ss2);
        }
    }
});