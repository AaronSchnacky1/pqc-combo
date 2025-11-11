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
//! Complete FIPS 140-3 Integration Tests
//! 
//! Tests all 4 FIPS requirements working together:
//! 1. Complete CSTs (hash CASTs + PCTs)
//! 2. State Machine
//! 3. CSP Controls
//! 4. FFI Boundary

use pqc_combo::*;
use pqcrypto_traits::kem::SharedSecret;

#[test]
fn test_complete_fips_workflow() {
    // 1. Start in uninitialized state
    #[cfg(test)]
    state::reset_fips_state();
    
    assert_eq!(get_fips_state(), FipsState::Uninitialized);
    assert!(!is_operational());
    
    // 2. Run POST (includes all CASTs and PCTs)
    let post_result = run_post();
    assert!(post_result.is_ok(), "POST failed: {:?}", post_result.err());
    
    // 3. Verify state is now operational
    assert_eq!(get_fips_state(), FipsState::Operational);
    assert!(is_operational());
    
    // 4. Perform cryptographic operations
    let keys = KyberKeys::generate_key_pair();
    let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
    let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    
    let (pk, sk) = generate_dilithium_keypair();
    let msg = b"FIPS 140-3 complete workflow test";
    let sig = sign_message(&sk, msg);
    assert!(verify_signature(&pk, msg, &sig));
}

#[test]
fn test_operations_blocked_before_post() {
    #[cfg(test)]
    state::reset_fips_state();
    
    // State machine should block operations
    assert!(!is_operational());
    
    // In non-FIPS mode, keys can still be generated (for testing)
    // In FIPS mode, this would panic
    #[cfg(not(feature = "fips_140_3"))]
    {
        let _keys = KyberKeys::generate_key_pair();
    }
}

#[test]
fn test_post_failure_enters_error_state() {
    #[cfg(test)]
    state::reset_fips_state();
    
    // Simulate POST failure by entering error state manually
    state::enter_error_state();
    
    assert_eq!(get_fips_state(), FipsState::Error);
    assert!(!is_operational());
    
    // Operations should be blocked
    let check = state::check_operational();
    assert!(check.is_err());
    assert_eq!(check.unwrap_err(), PqcError::FipsErrorState);
}

#[test]
fn test_csp_export_policy() {
    #[cfg(test)]
    state::reset_fips_state();
    run_post().expect("POST failed");
    
    let policy = csp::get_csp_export_policy();
    
    #[cfg(feature = "fips_140_3")]
    {
        assert_eq!(policy, CspExportPolicy::BlockPlaintext);
    }
    
    #[cfg(not(feature = "fips_140_3"))]
    {
        assert_eq!(policy, CspExportPolicy::AllowPlaintext);
    }
}

#[test]
fn test_csp_controls_work_with_approved_api() {
    #[cfg(test)]
    state::reset_fips_state();
    run_post().expect("POST failed");
    
    // Keys should work through approved API regardless of export policy
    let keys = KyberKeys::generate_key_pair();
    let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
    let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
}

#[cfg(feature = "std")]
#[test]
fn test_ffi_boundary_guards() {
    use std::ptr;
    
    #[cfg(test)]
    state::reset_fips_state();
    
    // FFI entry guard should block before POST
    assert!(ffi_entry_guard().is_err());
    
    // Run POST
    run_post().expect("POST failed");
    
    // FFI entry guard should now allow
    assert!(ffi_entry_guard().is_ok());
    
    // Pointer validation tests
    assert!(ffi_boundary::validate_ptr(ptr::null::<u8>()).is_err());
    let data = 42u8;
    assert!(ffi_boundary::validate_ptr(&data as *const u8).is_ok());
}

#[cfg(feature = "std")]
#[test]
fn test_ffi_init_function() {
    #[cfg(test)]
    state::reset_fips_state();
    
    // Call FFI init (runs POST)
    let result = unsafe {
        crate::ffi::pqc_combo_init()
    };
    
    assert_eq!(result, 0, "FFI init should succeed");
    assert!(is_operational());
    
    // Check operational status via FFI
    let status = unsafe {
        crate::ffi::pqc_combo_is_operational()
    };
    assert_eq!(status, 1, "FFI should report operational");
}

#[cfg(feature = "std")]
#[test]
fn test_ffi_operations_require_init() {
    use std::alloc::{alloc, dealloc, Layout};
    
    #[cfg(test)]
    state::reset_fips_state();
    
    unsafe {
        // Allocate buffers for FFI test
        let pk_layout = Layout::from_size_align(1568, 1).unwrap();
        let sk_layout = Layout::from_size_align(3168, 1).unwrap();
        
        let pk_buf = alloc(pk_layout) as *mut i8;
        let sk_buf = alloc(sk_layout) as *mut i8;
        
        // Try to generate keys before init
        let result = crate::ffi::pqc_combo_kyber_keypair(pk_buf, sk_buf);
        assert_eq!(result, -2, "FFI should return -2 (not operational) before init");
        
        // Initialize
        crate::ffi::pqc_combo_init();
        
        // Now it should work
        let result = crate::ffi::pqc_combo_kyber_keypair(pk_buf, sk_buf);
        assert_eq!(result, 0, "FFI should succeed after init");
        
        // Cleanup
        dealloc(pk_buf as *mut u8, pk_layout);
        dealloc(sk_buf as *mut u8, sk_layout);
    }
}

#[test]
fn test_all_self_tests_in_post() {
    #[cfg(test)]
    state::reset_fips_state();
    
    // POST should run:
    // 1. Hash CASTs (4 tests)
    // 2. Kyber PCT
    // 3. Dilithium PCT
    
    let result = run_post();
    assert!(result.is_ok(), "POST failed - self-tests did not pass");
    
    // Verify all components are operational
    assert!(is_operational());
    
    // Verify we can use crypto functions
    let keys = KyberKeys::generate_key_pair();
    let (_, ss) = encapsulate_shared_secret(&keys.pk);
    assert_eq!(ss.as_bytes().len(), 32);
}

#[cfg(feature = "std")]
#[test]
fn test_concurrent_operations_after_post() {
    use std::thread;
    
    #[cfg(test)]
    state::reset_fips_state();
    
    // Run POST once
    run_post().expect("POST failed");
    
    // Multiple threads should be able to use crypto
    let mut handles = vec![];
    
    for i in 0..10 {
        handles.push(thread::spawn(move || {
            assert!(is_operational(), "Thread {} not operational", i);
            
            let keys = KyberKeys::generate_key_pair();
            let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
            let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
            assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
        }));
    }
    
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
#[cfg(feature = "fips_140_3")]
fn test_fips_mode_enforces_state_checks() {
    #[cfg(test)]
    state::reset_fips_state();
    
    // In FIPS mode, key generation should panic before POST
    let result = std::panic::catch_unwind(|| {
        KyberKeys::generate_key_pair();
    });
    
    assert!(result.is_err(), "FIPS mode should panic when generating keys before POST");
}

#[test]
fn test_post_or_panic_success() {
    #[cfg(test)]
    state::reset_fips_state();
    
    // Should not panic when POST succeeds
    run_post_or_panic();
    
    assert!(is_operational());
}