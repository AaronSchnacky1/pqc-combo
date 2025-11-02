#[derive(Debug, PartialEq, Eq)]
pub enum PqcError {
    InvalidKeyLength,
    VerificationFailure,
    DecapsulationFailure,
    RngFailure,
}

pub type Result<T> = core::result::Result<T, PqcError>;