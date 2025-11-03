#[derive(Debug, PartialEq, Eq)]
pub enum PqcError {
    InvalidKeyLength,
    VerificationFailure,
    DecapsulationFailure,
    // RngFailure is no longer possible as the API uses
    // the built-in RNG for `std` or is deterministic.
}

pub type Result<T> = core::result::Result<T, PqcError>;
