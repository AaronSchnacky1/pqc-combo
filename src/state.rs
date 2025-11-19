// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// FIPS 140-3 State Machine Implementation
// ------------------------------------------------------------------------

use crate::error::{PqcError, Result};
use core::sync::atomic::{AtomicU8, Ordering};

/// FIPS 140-3 Module States
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsState {
    Uninitialized = 0,
    POST = 1,
    Operational = 2,
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

static FIPS_STATE: AtomicU8 = AtomicU8::new(FipsState::Uninitialized as u8);

pub fn get_fips_state() -> FipsState {
    FipsState::from(FIPS_STATE.load(Ordering::Acquire))
}

fn set_fips_state(state: FipsState) {
    FIPS_STATE.store(state as u8, Ordering::Release);
}

pub(crate) fn enter_post_state() {
    set_fips_state(FipsState::POST);
}

pub(crate) fn enter_operational_state() {
    set_fips_state(FipsState::Operational);
}

pub(crate) fn enter_error_state() {
    set_fips_state(FipsState::Error);
}

pub fn is_operational() -> bool {
    get_fips_state() == FipsState::Operational
}

pub fn check_operational() -> Result<()> {
    let current_state = get_fips_state();
    match current_state {
        FipsState::Operational => Ok(()),
        FipsState::Uninitialized => Err(PqcError::FipsNotInitialized),
        FipsState::POST => Err(PqcError::FipsPostInProgress),
        FipsState::Error => Err(PqcError::FipsErrorState),
    }
}

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
        
        assert!(check_operational().is_err());
        assert_eq!(check_operational().unwrap_err(), PqcError::FipsNotInitialized);
        
        enter_post_state();
        assert!(check_operational().is_err());
        assert_eq!(check_operational().unwrap_err(), PqcError::FipsPostInProgress);
        
        enter_operational_state();
        assert!(check_operational().is_ok());
        
        enter_error_state();
        assert!(check_operational().is_err());
        assert_eq!(check_operational().unwrap_err(), PqcError::FipsErrorState);
    }
}