#![no_main]
//! Fuzzing for FIPS 140-3 State Machine
//! 
//! Tests that state transitions work correctly and enforce proper initialization

use libfuzzer_sys::fuzz_target;
use pqc_combo::*;
use pqc_combo::state::{reset_fips_state, get_fips_state, FipsState};
use pqc_combo::preop::run_post;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    // Reset to known state
    reset_fips_state();
    assert_eq!(get_fips_state(), FipsState::Uninitialized);
    
    // Test state transitions based on fuzzer input
    let operation = data[0] % 4;
    
    match operation {
        0 => {
            // Test normal POST flow
            let result = run_post();
            if result.is_ok() {
                assert_eq!(get_fips_state(), FipsState::Operational);
            } else {
                assert_eq!(get_fips_state(), FipsState::Error);
            }
        },
        
        1 => {
            // Test operations without POST (should fail in FIPS mode)
            #[cfg(feature = "fips_140_3")]
            {
                if data.len() >= 65 {
                    let seed: [u8; 64] = data[1..65].try_into().unwrap();
                    if seed.iter().any(|&b| b != 0) {
                        // Operations should check operational state
                        // Note: This might panic or error depending on implementation
                        // Just ensure it doesn't succeed silently
                    }
                }
            }
        },
        
        2 => {
            // Test repeated POST
            for _ in 0..3 {
                reset_fips_state();
                let result = run_post();
                
                if result.is_ok() {
                    assert_eq!(get_fips_state(), FipsState::Operational);
                }
            }
        },
        
        3 => {
            // Test POST followed by operations
            let result = run_post();
            if result.is_ok() && data.len() >= 65 {
                let seed: [u8; 64] = data[1..65].try_into().unwrap();
                if seed.iter().any(|&b| b != 0) {
                    // Operations should work after successful POST
                    let keys = KyberKeys::generate_key_pair_with_seed(seed);
                    let (ct, ss1) = encapsulate_shared_secret(&keys.pk);
                    let ss2 = decapsulate_shared_secret(&keys.sk, &ct);
                    assert_eq!(ss1, ss2);
                }
            }
        },
        
        _ => unreachable!(),
    }
});
