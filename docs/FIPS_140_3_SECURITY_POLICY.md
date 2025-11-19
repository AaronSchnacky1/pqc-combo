# FIPS 140-3 Security Policy

**Module Name:** pqc-combo  
**Module Version:** 0.1.0  
**Software Version:** 0.1.0  
**Date:** November 2024

---

## 1. Introduction

This document is the non-proprietary Security Policy for the **pqc-combo** cryptographic module. It describes how the module meets the security requirements of FIPS 140-3 (Federal Information Processing Standards Publication 140-3) and how to run the module in a secure FIPS 140-3 mode.

### 1.1 Module Overview

**pqc-combo** is a software library written in pure Rust that provides Post-Quantum Cryptography (PQC) algorithms and standard symmetric encryption. The module is designed to run on general-purpose computing systems.

**Cryptographic Boundary:** The physical boundary of the module is the physical perimeter of the general-purpose computer on which the module is installed. The logical boundary of the module is the `pqc-combo` software library (compiled crate).

### 1.2 Security Level

The module is intended to meet **Security Level 1** overall.

| Security Requirement | Level |
|----------------------|-------|
| Cryptographic Module Specification | 1 |
| Cryptographic Module Interfaces | 1 |
| Roles, Services, and Authentication | 1 |
| Software/Firmware Security | 1 |
| Operational Environment | 1 |
| Physical Security | N/A |
| Non-Invasive Security | N/A |
| Sensitive Security Parameter Management | 1 |
| Self-Tests | 1 |
| Life-Cycle Assurance | 1 |
| Mitigation of Other Attacks | N/A |

---

## 2. Modes of Operation

The module supports two modes of operation:
1.  **FIPS Approved Mode**: In this mode, only FIPS-approved algorithms and security functions are used. The module enforces self-tests and strict key management.
2.  **Non-Approved Mode**: This mode allows the use of non-approved algorithms or configurations (though this module primarily implements approved algorithms).

### 2.1 Approved Algorithms

The following algorithms are implemented in the module and are intended for FIPS validation:

| Algorithm | Standard | Usage | Key Sizes / Parameters |
|-----------|----------|-------|------------------------|
| **ML-KEM** | FIPS 203 | Key Encapsulation | ML-KEM-1024 |
| **ML-DSA** | FIPS 204 | Digital Signatures | ML-DSA-65 |
| **AES-GCM** | FIPS 197, SP 800-38D | Authenticated Encryption | AES-256 (256-bit keys) |
| **SHA-3** | FIPS 202 | Hashing (Internal) | SHA3-256, SHA3-512, SHAKE128, SHAKE256 |

### 2.2 Configuring FIPS Mode

To operate the module in FIPS Approved Mode, the consuming application **MUST**:
1.  Enable the `fips_140_3` Cargo feature when compiling.
2.  Call `pqc_combo::run_post()` or `pqc_combo::run_post_or_panic()` immediately upon initialization.
3.  Verify the function returns `Ok(())`.
4.  Only use keys generated via the `*_with_pct` or `*_with_seed` APIs (which perform Pair-wise Consistency Tests).

---

## 3. Ports and Interfaces

The module provides a logical interface via its Rust Application Programming Interface (API).

| FIPS Interface | Physical Port | Logical Interface |
|----------------|---------------|-------------------|
| **Data Input** | PC Input Devices (Network, USB, etc.) | API input parameters (plaintext, ciphertext, public keys, messages) |
| **Data Output** | PC Output Devices (Network, Screen, etc.) | API output parameters (ciphertext, shared secrets, signatures, plaintext) |
| **Control Input** | PC Input Devices | API function calls, Feature flags |
| **Status Output** | PC Output Devices | API return values (`Result`, `Ok`, `Err`), Log output |

---

## 4. Roles, Services, and Authentication

The module supports two roles: **User** and **Crypto Officer (CO)**. Since the module is Level 1, it does not require role-based authentication. The role is implicitly assumed based on the service requested.

### 4.1 Services

| Service | Role | Description | CSP Access |
|---------|------|-------------|------------|
| **Initialize** | User, CO | Run self-tests (`run_post`) | None |
| **Key Generation** | User, CO | Generate ML-KEM/ML-DSA keys | Write (Key Pair) |
| **Encapsulate** | User, CO | ML-KEM Encapsulation | Read (Public Key), Write (Shared Secret) |
| **Decapsulate** | User, CO | ML-KEM Decapsulation | Read (Private Key), Write (Shared Secret) |
| **Sign** | User, CO | ML-DSA Signing | Read (Private Key) |
| **Verify** | User, CO | ML-DSA Verification | Read (Public Key) |
| **Encrypt** | User, CO | AES-GCM Encryption | Read (Key) |
| **Decrypt** | User, CO | AES-GCM Decryption | Read (Key) |
| **Zeroize** | User, CO | Zeroize keys (Drop trait) | Overwrite (Key) |
| **Show Status** | User, CO | Return status via API | None |

---

## 5. Self-Tests

The module performs the following self-tests to ensure correct operation.

### 5.1 Pre-Operational Self-Tests (POST)

Executed automatically when `run_post()` is called.
1.  **Integrity Test**: (Implicit via Rust compiler checks and checksums).
2.  **Known Answer Tests (KATs)**:
    *   **ML-KEM-1024**: Encapsulate/Decapsulate KAT.
    *   **ML-DSA-65**: Sign/Verify KAT.
    *   **SHA-3**: Hash function KATs (SHA3-256, SHA3-512, SHAKE128, SHAKE256).

### 5.2 Conditional Self-Tests

Executed whenever a new key is generated.
1.  **Pair-wise Consistency Test (PCT)**:
    *   **ML-KEM**: Generates a key pair, performs encapsulation, then decapsulation, and verifies the shared secret matches.
    *   **ML-DSA**: Generates a key pair, signs a message, then verifies the signature.

If any self-test fails, the module enters an **Error State** and refuses all cryptographic operations.

---

## 6. Operational Environment

The module is written in Rust and is compatible with:
*   **Operating Systems**: Windows, Linux, macOS, and bare-metal (no_std).
*   **Hardware**: x86_64, ARM64, and other architectures supported by the Rust compiler.

For FIPS validation, the module is tested on:
*   **OS**: Windows 10 / 11
*   **Platform**: General Purpose Computer (x86_64)

---

## 7. Mitigation of Other Attacks

The module implements constant-time logic for ML-KEM and ML-DSA (via `libcrux`) to mitigate timing side-channel attacks. No other specific attack mitigations are claimed.

---

## 8. Contact

**Maintainer:** Aaron Schnacky  
**Email:** aaronschnacky@gmail.com  
**Website:** [www.pqc-combo.com](https://www.pqc-combo.com/)
