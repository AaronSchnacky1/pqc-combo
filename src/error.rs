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
// ------------------------------------------------------------------------// src/error.rs
#[derive(Debug, PartialEq, Eq)]
pub enum PqcError {
    InvalidKeyLength,
    VerificationFailure,
    DecapsulationFailure,
    AesGcmOperationFailed,
    /// FIPS 140-3 Pair-wise Consistency Test (PCT) failure
    PairwiseConsistencyTestFailure,
    /// FIPS 140-3 Conditional Algorithm Self-Test (CAST) failure
    CastFailure,
    /// FIPS 140-3 State: Module not initialized (POST not run)
    FipsNotInitialized,
    /// FIPS 140-3 State: POST currently in progress
    FipsPostInProgress,
    /// FIPS 140-3 State: Module in error state (POST failed)
    FipsErrorState,
    /// FIPS 140-3 CSP: Plaintext export blocked in FIPS mode
    CspExportBlocked,
    /// FFI: Null pointer passed to FFI function
    FfiNullPointer,
    /// FFI: Output buffer too small
    FfiBufferTooSmall,
}

pub type Result<T> = core::result::Result<T, PqcError>;