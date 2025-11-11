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
// ------------------------------------------------------------------------//! FFI Boundary Definition for FIPS 140-3
//! 
//! Defines the cryptographic module boundary for foreign function interface.
//! 
//! # FIPS 140-3 Boundary
//! 
//! ## Inside the Cryptographic Boundary:
//! - All Rust code in this crate (pqc-combo)
//! - PQClean C implementations (compiled into the module)
//! - Self-test functions (POST, CASTs, PCTs)
//! - State machine
//! - CSP storage (keys, shared secrets)
//! 
//! ## Outside the Cryptographic Boundary:
//! - Calling application code (C, Python, etc.)
//! - User-provided data (messages, plaintexts)
//! - File system, network, external storage
//! 
//! ## Entry Points (FFI Functions):
//! All FFI functions defined in `src/ffi.rs` are entry points to the module.
//! 
//! ## Data Flow Rules:
//! 1. **Input validation**: All FFI inputs must be validated before use
//! 2. **CSP protection**: Secret keys never cross boundary in plaintext
//! 3. **State enforcement**: All operations check operational state
//! 4. **Error handling**: All errors reported to caller
//! 
//! ## CSP Entry/Exit Rules:
//! - **Secret Keys (SK)**: Generated inside, never exit in plaintext
//! - **Public Keys (PK)**: Can exit safely (not secret)
//! - **Ciphertexts (CT)**: Can exit safely (not secret)
//! - **Shared Secrets (SS)**: Generated inside, should not exit in plaintext (use for encryption)
//! - **Signatures**: Can exit safely (not secret)

#![cfg(feature = "std")]

use crate::error::{PqcError, Result};
use crate::state::check_operational;
use crate::csp::check_csp_export_allowed;

/// FFI Entry Point Guard
/// 
/// All FFI functions MUST call this before performing operations.
/// Ensures:
/// 1. Module is in operational state (POST has passed)
/// 2. Operation is allowed by current policy
pub fn ffi_entry_guard() -> Result<()> {
    check_operational()
}

/// FFI CSP Export Guard
/// 
/// Call this before exporting any CSP through FFI.
/// In FIPS mode, this will block secret key exports.
pub fn ffi_csp_export_guard() -> Result<()> {
    check_operational()?;
    check_csp_export_allowed()
}

/// Validate FFI pointer is non-null
/// 
/// All FFI functions receiving pointers should validate them.
#[inline]
pub fn validate_ptr<T>(ptr: *const T) -> Result<()> {
    if ptr.is_null() {
        Err(PqcError::FfiNullPointer)
    } else {
        Ok(())
    }
}

/// Validate FFI mutable pointer is non-null
#[inline]
pub fn validate_mut_ptr<T>(ptr: *mut T) -> Result<()> {
    if ptr.is_null() {
        Err(PqcError::FfiNullPointer)
    } else {
        Ok(())
    }
}

/// Validate buffer length
/// 
/// Ensures output buffers are large enough.
#[inline]
pub fn validate_buffer_len(provided: usize, required: usize) -> Result<()> {
    if provided < required {
        Err(PqcError::FfiBufferTooSmall)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{reset_fips_state, enter_operational_state};
    use std::ptr;

    #[test]
    fn test_ffi_entry_guard_not_operational() {
        reset_fips_state();
        assert!(ffi_entry_guard().is_err());
    }

    #[test]
    fn test_ffi_entry_guard_operational() {
        reset_fips_state();
        enter_operational_state();
        assert!(ffi_entry_guard().is_ok());
    }

    #[test]
    fn test_validate_ptr_null() {
        let result = validate_ptr(ptr::null::<u8>());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PqcError::FfiNullPointer);
    }

    #[test]
    fn test_validate_ptr_valid() {
        let data = 42u8;
        let result = validate_ptr(&data as *const u8);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mut_ptr_null() {
        let result = validate_mut_ptr(ptr::null_mut::<u8>());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PqcError::FfiNullPointer);
    }

    #[test]
    fn test_validate_mut_ptr_valid() {
        let mut data = 42u8;
        let result = validate_mut_ptr(&mut data as *mut u8);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_buffer_len_too_small() {
        let result = validate_buffer_len(10, 20);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PqcError::FfiBufferTooSmall);
    }

    #[test]
    fn test_validate_buffer_len_exact() {
        let result = validate_buffer_len(20, 20);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_buffer_len_larger() {
        let result = validate_buffer_len(30, 20);
        assert!(result.is_ok());
    }
}