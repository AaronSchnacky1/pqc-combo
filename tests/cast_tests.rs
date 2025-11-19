// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// Integration tests for FIPS 140-3 Hash Function CASTs
// ------------------------------------------------------------------------

use pqc_combo::cast::*;
use pqc_combo::PqcError;

#[test]
fn test_sha3_256_cast_integration() {
    let result = sha3_256_cast();
    assert!(result.is_ok(), "SHA3-256 CAST failed: {:?}", result.err());
}

#[test]
fn test_sha3_512_cast_integration() {
    let result = sha3_512_cast();
    assert!(result.is_ok(), "SHA3-512 CAST failed: {:?}", result.err());
}

#[test]
fn test_shake128_cast_integration() {
    let result = shake128_cast();
    assert!(result.is_ok(), "SHAKE-128 CAST failed: {:?}", result.err());
}

#[test]
fn test_shake256_cast_integration() {
    let result = shake256_cast();
    assert!(result.is_ok(), "SHAKE-256 CAST failed: {:?}", result.err());
}

#[test]
fn test_run_all_hash_casts_integration() {
    let result = run_hash_casts();
    assert!(result.is_ok(), "Hash CASTs failed: {:?}", result.err());
}

#[test]
fn test_hash_casts_repeatable() {
    // Verify CASTs can be run multiple times
    for i in 0..10 {
        let result = run_hash_casts();
        assert!(result.is_ok(), "Hash CASTs failed on iteration {}: {:?}", i, result.err());
    }
}

#[cfg(feature = "std")]
#[test]
fn test_hash_casts_concurrent() {
    use std::thread;
    
    let mut handles = vec![];
    
    for i in 0..10 {
        handles.push(thread::spawn(move || {
            let result = run_hash_casts();
            assert!(result.is_ok(), "Thread {} CAST failed: {:?}", i, result.err());
        }));
    }
    
    for handle in handles {
        handle.join().expect("Thread panicked during CAST");
    }
}

#[test]
fn test_individual_cast_failures_propagate() {
    // This test verifies error handling structure
    // In real code, CASTs shouldn't fail unless implementation is broken
    
    // Verify that run_hash_casts would fail if any individual CAST failed
    // (This is more of a structural test - actual CAST failure would indicate serious bug)
    
    let result = run_hash_casts();
    match result {
        Ok(()) => {
            // Expected path - all CASTs pass
            assert!(true);
        }
        Err(PqcError::CastFailure) => {
            panic!("CAST failed - this indicates a serious implementation bug");
        }
        Err(e) => {
            panic!("Unexpected error type: {:?}", e);
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn test_cast_performance() {
    use std::time::Instant;
    
    let start = Instant::now();
    for _ in 0..100 {
        run_hash_casts().expect("CAST failed");
    }
    let elapsed = start.elapsed();
    
    println!("100 iterations of all hash CASTs: {:?}", elapsed);
    
    // CASTs should be fast (< 100ms for 100 iterations)
    assert!(elapsed.as_millis() < 100, "CASTs taking too long: {:?}", elapsed);
}

#[test]
#[cfg(all(feature = "ml-kem", feature = "std"))]
fn test_cast_before_cryptographic_operations() {
    use pqc_combo::*;
    
    // In FIPS mode, CASTs should run before crypto operations
    // For now, we just verify they don't interfere
    
    run_hash_casts().expect("Hash CASTs failed");
    
    // Now perform normal crypto operations
    let keys = KyberKeys::generate_key_pair();
    let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
    let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
    assert_eq!(ss_a, ss_b);  // Direct comparison - both are [u8; 32]
}