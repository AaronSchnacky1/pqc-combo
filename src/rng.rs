// src/rng.rs
use zeroize::Zeroize;

#[cfg(feature = "std")]
use rand::RngCore;

/// Generate 32-byte seed (std only; for encap/sign)
#[cfg(feature = "std")]
pub fn generate_seed_32() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut seed).expect("OsRng failed");
    seed
}

/// Generate 64-byte seed (std only; for keygen)
#[cfg(feature = "std")]
pub fn generate_seed_64() -> [u8; 64] {
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.try_fill_bytes(&mut seed).expect("OsRng failed");
    seed
}

/// Validate 32-byte seed
pub fn validate_seed_32(seed: &[u8; 32]) {
    if seed.iter().all(|&b| b == 0) {
        panic!("Zero seed invalid");
    }
}

/// Validate 64-byte seed
pub fn validate_seed_64(seed: &[u8; 64]) {
    if seed.iter().all(|&b| b == 0) {
        panic!("Zero seed invalid");
    }
}

/// Secure drop wrapper (pub field for constructor)
#[derive(Zeroize)]
pub struct SecureSeed(pub [u8; 64]);  // Use 64 for generality; adjust if needed
impl Drop for SecureSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secure drop for 32-byte (separate for encap)
#[derive(Zeroize)]
pub struct SecureSeed32(pub [u8; 32]);
impl Drop for SecureSeed32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}