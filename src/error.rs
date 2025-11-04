#[derive(Debug, PartialEq, Eq)]
pub enum PqcError {
    InvalidKeyLength,
    VerificationFailure,
    DecapsulationFailure,
    AesGcmOperationFailed, // NEW: For auth/encryption failures
}

pub type Result<T> = core::result::Result<T, PqcError>;