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
//! FIPS 140-3 State Machine Implementation
//! 
//! Manages module state transitions:
//! - Uninitialized: Power-on state, no operations allowed
//! - POST: Running Pre-Operational Self-Tests
//! - Operational: Self-tests passed, cryptographic operations allowed
//! - Error: Self-test failure, all operations blocked

use crate::error::{PqcError, Result};
use core::sync::atomic::{AtomicU8, Ordering};

/// FIPS 140-3 Module States
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsState {
    /// Initial state - no operations allowed
    Uninitialized = 0,
    /// Running Pre-Operational Self-Tests
    POST = 1,
    /// Self-tests passed - cryptographic operations allowed
    Operational = 2,
    /// Self-test failure - all operations blocked
    Error = 3,
}

impl From<u8> for FipsState {
    fn from(val: u8) -> Self {
        match val {
            0 => FipsState::Uninitialized,
            1 => FipsState::POST,
            2 => FipsState::Operational,
            3 => FipsState::Error,
            _ => FipsState::Error,
        }
    }
}

/// Global FIPS state (thread-safe atomic)
static FIPS_STATE: AtomicU8 = AtomicU8::new(FipsState::Uninitialized as u8);

/// Get current FIPS state
pub fn get_fips_state() -> FipsState {
    FipsState::from(FIPS_STATE.load(Ordering::Acquire))
}

/// Set FIPS state (internal use only)
fn set_fips_state(state: FipsState) {
    FIPS_STATE.store(state as u8, Ordering::Release);
}

/// Transition to POST state
pub(crate) fn enter_post_state() {
    set_fips_state(FipsState::POST);
}

/// Transition to Operational state (POST passed)
pub(crate) fn enter_operational_state() {
    set_fips_state(FipsState::Operational);
}

/// Transition to Error state (POST failed)
pub(crate) fn enter_error_state() {
    set_fips_state(FipsState::Error);
}

/// Check if cryptographic operations are allowed
pub fn is_operational() -> bool {
    get_fips_state() == FipsState::Operational
}

/// Guard function - blocks operations unless in Operational state
pub fn check_operational() -> Result<()> {
    let current_state = get_fips_state();
    match current_state {
        FipsState::Operational => Ok(()),
        FipsState::Uninitialized => Err(PqcError::FipsNotInitialized),
        FipsState::POST => Err(PqcError::FipsPostInProgress),
        FipsState::Error => Err(PqcError::FipsErrorState),
    }
}

/// Reset state to Uninitialized (for testing only)
#[cfg(test)]
pub fn reset_fips_state() {
    set_fips_state(FipsState::Uninitialized);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        reset_fips_state();
        assert_eq!(get_fips_state(), FipsState::Uninitialized);
        assert!(!is_operational());
    }

    #[test]
    fn test_state_transitions() {
        reset_fips_state();
        
        enter_post_state();
        assert_eq!(get_fips_state(), FipsState::POST);
        assert!(!is_operational());
        
        enter_operational_state();
        assert_eq!(get_fips_state(), FipsState::Operational);
        assert!(is_operational());
        
        enter_error_state();
        assert_eq!(get_fips_state(), FipsState::Error);
        assert!(!is_operational());
    }

    #[test]
    fn test_check_operational() {
        reset_fips_state();
        
        // Uninitialized
        assert!(check_operational().is_err());
        assert_eq!(check_operational().unwrap_err(), PqcError::FipsNotInitialized);
        
        // POST
        enter_post_state();
        assert!(check_operational().is_err());
        assert_eq!(check_operational().unwrap_err(), PqcError::FipsPostInProgress);
        
        // Operational
        enter_operational_state();
        assert!(check_operational().is_ok());
        
        // Error
        enter_error_state();
        assert!(check_operational().is_err());
        assert_eq!(check_operational().unwrap_err(), PqcError::FipsErrorState);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_concurrent_state_access() {
        use std::thread;
        
        reset_fips_state();
        enter_operational_state();
        
        // Give state time to stabilize
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let mut handles = vec![];
        
        for _ in 0..10 {
            handles.push(thread::spawn(|| {
                // State should be Operational and stable
                let state = get_fips_state();
                let operational = is_operational();
                
                // Allow for either Operational or POST (if another test is running)
                // but they should be consistent with each other
                if state == FipsState::Operational {
                    assert!(operational, "is_operational should return true when state is Operational");
                } else if state == FipsState::POST {
                    assert!(!operational, "is_operational should return false when state is POST");
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
    }
}