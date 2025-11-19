// ------------------------------------------------------------------------
// PQC-COMBO v0.0.7
// Critical Security Parameter (CSP) Controls for FIPS 140-3
// ------------------------------------------------------------------------

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{PqcError, Result};
use crate::state::check_operational;

#[cfg(feature = "ml-kem")]
use crate::{KyberSecretKey, KyberSharedSecret};

#[cfg(feature = "ml-dsa")]
use crate::DilithiumSecretKey;

/// CSP Export Policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspExportPolicy {
    /// Allow plaintext export (non-FIPS mode)
    AllowPlaintext,
    /// Block plaintext export (FIPS mode)
    BlockPlaintext,
}

/// Get current CSP export policy based on feature flags
pub fn get_csp_export_policy() -> CspExportPolicy {
    #[cfg(feature = "fips_140_3")]
    {
        CspExportPolicy::BlockPlaintext
    }
    #[cfg(not(feature = "fips_140_3"))]
    {
        CspExportPolicy::AllowPlaintext
    }
}

/// Check if CSP export is allowed
pub fn check_csp_export_allowed() -> Result<()> {
    match get_csp_export_policy() {
        CspExportPolicy::AllowPlaintext => Ok(()),
        CspExportPolicy::BlockPlaintext => Err(PqcError::CspExportBlocked),
    }
}

/// Guard function for Kyber secret key export
#[cfg(all(feature = "ml-kem", feature = "alloc"))]
pub fn guard_kyber_sk_export(sk: &KyberSecretKey) -> Result<Vec<u8>> {
    check_operational()?;
    check_csp_export_allowed()?;
    Ok(sk.as_slice().to_vec())
}

/// Guard function for Dilithium secret key export
#[cfg(all(feature = "ml-dsa", feature = "alloc"))]
pub fn guard_dilithium_sk_export(sk: &DilithiumSecretKey) -> Result<Vec<u8>> {
    check_operational()?;
    check_csp_export_allowed()?;
    Ok(sk.as_slice().to_vec())
}

/// Guard function for shared secret export
#[cfg(feature = "ml-kem")]
pub fn guard_shared_secret_export(ss: &KyberSharedSecret) -> Result<&[u8]> {
    check_operational()?;
    check_csp_export_allowed()?;
    Ok(ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_export_policy_non_fips() {
        #[cfg(not(feature = "fips_140_3"))]
        {
            assert_eq!(get_csp_export_policy(), CspExportPolicy::AllowPlaintext);
            assert!(check_csp_export_allowed().is_ok());
        }
    }

    #[test]
    fn test_csp_export_policy_fips() {
        #[cfg(feature = "fips_140_3")]
        {
            assert_eq!(get_csp_export_policy(), CspExportPolicy::BlockPlaintext);
            assert!(check_csp_export_allowed().is_err());
            assert_eq!(check_csp_export_allowed().unwrap_err(), PqcError::CspExportBlocked);
        }
    }

    #[test]
    #[cfg(all(feature = "ml-kem", feature = "ml-dsa", feature = "std", feature = "alloc"))]
    fn test_guard_functions_check_operational() {
        use crate::{generate_dilithium_keypair, KyberKeys};
        use crate::state::enter_operational_state;
        
        let _keys = KyberKeys::generate_key_pair();
        let (_pk, _sk_dil) = generate_dilithium_keypair();
        
        // Should fail when not operational
        #[cfg(not(feature = "fips_140_3"))]
        {
            use crate::state::reset_fips_state;
            reset_fips_state();
            let result = guard_kyber_sk_export(&_keys.sk);
            assert!(result.is_err(), "Should fail when not operational");
            
            reset_fips_state();
            let result = guard_dilithium_sk_export(&_sk_dil);
            assert!(result.is_err(), "Should fail when not operational");
        }
        
        // Should work when operational (non-FIPS)
        enter_operational_state();
        
        #[cfg(not(feature = "fips_140_3"))]
        {
            assert!(guard_kyber_sk_export(&_keys.sk).is_ok());
            assert!(guard_dilithium_sk_export(&_sk_dil).is_ok());
        }
    }

    #[test]
    #[cfg(all(feature = "fips_140_3", feature = "ml-kem", feature = "ml-dsa", feature = "std", feature = "alloc"))]
    fn test_fips_blocks_csp_export() {
        use crate::{generate_dilithium_keypair, KyberKeys};
        use crate::state::reset_fips_state;
        use crate::preop::run_post;
        
        // Reset state and run POST to become operational in FIPS mode
        reset_fips_state();
        run_post().expect("POST should succeed");
        
        let keys = KyberKeys::generate_key_pair();
        let (_, sk_dil) = generate_dilithium_keypair();
        
        // When operational, FIPS mode blocks export
        assert!(guard_kyber_sk_export(&keys.sk).is_err());
        assert_eq!(guard_kyber_sk_export(&keys.sk).unwrap_err(), PqcError::CspExportBlocked);
        
        assert!(guard_dilithium_sk_export(&sk_dil).is_err());
        assert_eq!(guard_dilithium_sk_export(&sk_dil).unwrap_err(), PqcError::CspExportBlocked);
    }

    #[test]
    #[cfg(all(feature = "ml-kem", feature = "ml-dsa", feature = "std"))]
    fn test_keys_use_approved_api() {
        use crate::{encapsulate_shared_secret, decapsulate_shared_secret};
        use crate::{sign_message, verify_signature};
        use crate::{generate_dilithium_keypair, KyberKeys};
        use crate::state::{reset_fips_state, enter_operational_state};
        
        reset_fips_state();
        enter_operational_state();
        
        // Keys should work through approved API regardless of export policy
        let keys = KyberKeys::generate_key_pair();
        let (ct, ss_a) = encapsulate_shared_secret(&keys.pk);
        let ss_b = decapsulate_shared_secret(&keys.sk, &ct);
        assert_eq!(ss_a, ss_b);
        
        let (pk, sk) = generate_dilithium_keypair();
        let msg = b"CSP control test";
        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
    }
}