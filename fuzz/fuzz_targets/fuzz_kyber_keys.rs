#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_combo::*;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 64 {
        let seed: [u8; 64] = data[..64].try_into().unwrap();
        
        if seed.iter().any(|&b| b != 0) {
            let keys = KyberKeys::generate_key_pair_with_seed(seed);
            let (ct, ss1) = encapsulate_shared_secret(&keys.pk);
            let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
            assert_eq!(ss1, ss2);
        }
    }
});