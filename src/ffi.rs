// src/ffi.rs
#![cfg(feature = "std")]

use std::os::raw::c_int;
use libc::c_char;
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, SignedMessage};

#[no_mangle]
pub extern "C" fn pqc_combo_kyber_keypair(
    pk_out: *mut c_char,
    sk_out: *mut c_char,
) -> c_int {
    if pk_out.is_null() || sk_out.is_null() { return -1; }
    let (pk, sk) = kyber1024::keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), pk_out as *mut u8, pk.as_bytes().len());
        std::ptr::copy_nonoverlapping(sk.as_bytes().as_ptr(), sk_out as *mut u8, sk.as_bytes().len());
    }
    0
}

#[no_mangle]
pub extern "C" fn pqc_combo_kyber_encapsulate(
    ct_out: *mut c_char,
    ss_out: *mut c_char,
    pk_in: *const c_char,
) -> c_int {
    if ct_out.is_null() || ss_out.is_null() || pk_in.is_null() { return -1; }
    let pk = kyber1024::PublicKey::from_bytes(unsafe { std::slice::from_raw_parts(pk_in as *const u8, kyber1024::public_key_bytes()) }).unwrap();
    let (ct, ss) = kyber1024::encapsulate(&pk);
    unsafe {
        std::ptr::copy_nonoverlapping(ct.as_bytes().as_ptr(), ct_out as *mut u8, ct.as_bytes().len());
        std::ptr::copy_nonoverlapping(ss.as_bytes().as_ptr(), ss_out as *mut u8, ss.as_bytes().len());
    }
    0
}

#[no_mangle]
pub extern "C" fn pqc_combo_kyber_decapsulate(
    ss_out: *mut c_char,
    ct_in: *const c_char,
    sk_in: *const c_char,
) -> c_int {
    if ss_out.is_null() || ct_in.is_null() || sk_in.is_null() { return -1; }
    let sk = kyber1024::SecretKey::from_bytes(unsafe { std::slice::from_raw_parts(sk_in as *const u8, kyber1024::secret_key_bytes()) }).unwrap();
    let ct = kyber1024::Ciphertext::from_bytes(unsafe { std::slice::from_raw_parts(ct_in as *const u8, kyber1024::ciphertext_bytes()) }).unwrap();
    let ss = kyber1024::decapsulate(&ct, &sk);
    unsafe {
        std::ptr::copy_nonoverlapping(ss.as_bytes().as_ptr(), ss_out as *mut u8, ss.as_bytes().len());
    }
    0
}

#[no_mangle]
pub extern "C" fn pqc_combo_dilithium_keypair(
    pk_out: *mut c_char,
    sk_out: *mut c_char,
) -> c_int {
    if pk_out.is_null() || sk_out.is_null() { return -1; }
    let (pk, sk) = dilithium3::keypair();
    unsafe {
        std::ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), pk_out as *mut u8, pk.as_bytes().len());
        std::ptr::copy_nonoverlapping(sk.as_bytes().as_ptr(), sk_out as *mut u8, sk.as_bytes().len());
    }
    0
}

#[no_mangle]
pub extern "C" fn pqc_combo_dilithium_sign(
    sig_out: *mut c_char,
    msg: *const c_char,
    msg_len: usize,
    sk_in: *const c_char,
) -> c_int {
    if sig_out.is_null() || msg.is_null() || sk_in.is_null() { return -1; }
    let sk = dilithium3::SecretKey::from_bytes(unsafe { std::slice::from_raw_parts(sk_in as *const u8, dilithium3::secret_key_bytes()) }).unwrap();
    let message = unsafe { std::slice::from_raw_parts(msg as *const u8, msg_len) };
    let sig = dilithium3::sign(message, &sk);
    unsafe {
        std::ptr::copy_nonoverlapping(sig.as_bytes().as_ptr(), sig_out as *mut u8, sig.as_bytes().len());
    }
    0
}

#[no_mangle]
pub extern "C" fn pqc_combo_dilithium_verify(
    sig_in: *const c_char,
    msg: *const c_char,
    msg_len: usize,
    pk_in: *const c_char,
) -> c_int {
    if sig_in.is_null() || msg.is_null() || pk_in.is_null() { return -1; }
    let pk = dilithium3::PublicKey::from_bytes(unsafe { std::slice::from_raw_parts(pk_in as *const u8, dilithium3::public_key_bytes()) }).unwrap();
    let message = unsafe { std::slice::from_raw_parts(msg as *const u8, msg_len) };
    let sig = dilithium3::SignedMessage::from_bytes(unsafe { std::slice::from_raw_parts(sig_in as *const u8, dilithium3::signature_bytes()) }).unwrap();
    match dilithium3::open(&sig, &pk) {
        Ok(recovered) if recovered == message => 0,
        _ => 1,
    }
}