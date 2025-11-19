# libcrux API Reference for pqc-combo

## Key Findings from libcrux 0.0.4

### ML-KEM-1024 (mlkem1024 module)

**Types:**
- `MlKem1024PublicKey` - wraps `[u8; 1568]`
- `MlKem1024PrivateKey` - wraps `[u8; 3168]`
- `MlKem1024Ciphertext` - wraps `[u8; 1568]`
- `MlKemKeyPair<3168, 1568>` - keypair container
- Shared secret is just `[u8; 32]` (no wrapper type)

**Functions:**
```rust
// Returns a keypair struct, NOT a tuple
fn generate_key_pair(seed: [u8; 64]) -> MlKemKeyPair<3168, 1568>

// Access keys from keypair (methods, not fields)
keypair.pk() -> &MlKem1024PublicKey
keypair.sk() -> &MlKem1024PrivateKey

// Get bytes from keys
key.as_slice() -> &[u8]

// Create keys from bytes
MlKem1024PublicKey::from([u8; 1568])
MlKem1024PrivateKey::from([u8; 3168])

// Encapsulate/Decapsulate
fn encapsulate(pk: &MlKem1024PublicKey, randomness: [u8; 32]) 
    -> (MlKem1024Ciphertext, [u8; 32])

fn decapsulate(sk: &MlKem1024PrivateKey, ct: &MlKem1024Ciphertext) 
    -> [u8; 32]
```

### ML-DSA-65 (ml_dsa_65 module)

**Types:**
- `MLDSA65VerificationKey` - wraps `[u8; 1952]`
- `MLDSA65SigningKey` - wraps `[u8; 4032]` (NOT 4000!)
- `MLDSA65Signature` - wraps `[u8; 3309]` (NOT 3293!)
- `MLDSAKeyPair<1952, 4032>` - keypair container

**Functions:**
```rust
// Takes 32-byte seed (NOT 64!)
fn generate_key_pair(randomness: [u8; 32]) -> MLDSAKeyPair<1952, 4032>

// Access keys from keypair (PUBLIC FIELDS, not methods!)
keypair.verification_key -> MLDSA65VerificationKey
keypair.signing_key -> MLDSA65SigningKey

// Get bytes from keys
key.as_slice() -> &[u8]

// Create keys from bytes
MLDSA65VerificationKey::from([u8; 1952])
MLDSA65SigningKey::from([u8; 4032])

// Sign - takes 4 parameters (context is usually empty)
fn sign(
    signing_key: &MLDSA65SigningKey,
    message: &[u8],
    context: &[u8],  // Usually &[]
    randomness: [u8; 32]
) -> Result<MLDSA65Signature, SigningError>

// Verify - takes 4 parameters
fn verify(
    verification_key: &MLDSA65VerificationKey,
    message: &[u8],
    context: &[u8],  // Usually &[]
    signature: &MLDSA65Signature
) -> Result<(), VerificationError>
```

## Key Differences from Expected API

1. **KeyPair Return Types**: Functions return structs, not tuples
2. **ML-KEM Keypair**: Uses `.pk()` and `.sk()` methods
3. **ML-DSA Keypair**: Uses `.verification_key` and `.signing_key` PUBLIC FIELDS
4. **ML-DSA Seed Size**: Uses 32 bytes, not 64
5. **ML-DSA SK Size**: 4032 bytes, not 4000
6. **ML-DSA Signature Size**: 3309 bytes, not 3293
7. **Context Parameter**: ML-DSA sign/verify need empty context `&[]`
8. **Sign Returns Result**: Must handle with `.expect()` or `?`
9. **No Clone**: Key types don't implement Clone, must copy via bytes
10. **Type Inference**: Need explicit array types for `try_into()`

## Correct Constants

```rust
// ML-KEM
pub const ML_KEM_1024_PK_BYTES: usize = 1568;
pub const ML_KEM_1024_SK_BYTES: usize = 3168;
pub const ML_KEM_1024_CT_BYTES: usize = 1568;
pub const ML_KEM_1024_SS_BYTES: usize = 32;
pub const ML_KEM_KEYGEN_SEED_BYTES: usize = 64;
pub const ML_KEM_ENCAP_SEED_BYTES: usize = 32;

// ML-DSA
pub const ML_DSA_65_PK_BYTES: usize = 1952;
pub const ML_DSA_65_SK_BYTES: usize = 4032;  // Fixed!
pub const ML_DSA_65_SIG_BYTES: usize = 3309;  // Fixed!
pub const ML_DSA_KEYGEN_SEED_BYTES: usize = 32;  // Fixed!
pub const ML_DSA_SIGN_SEED_BYTES: usize = 32;
```

## Correct Key Extraction Pattern

```rust
// ML-KEM
let keypair = generate_key_pair(seed);
let pk_bytes: [u8; 1568] = keypair.pk().as_slice().try_into().unwrap();
let sk_bytes: [u8; 3168] = keypair.sk().as_slice().try_into().unwrap();
let pk = MlKem1024PublicKey::from(pk_bytes);
let sk = MlKem1024PrivateKey::from(sk_bytes);

// ML-DSA
let keypair = dsa_generate_key_pair(seed);
let pk_bytes: [u8; 1952] = keypair.verification_key().as_slice().try_into().unwrap();
let sk_bytes: [u8; 4032] = keypair.signing_key().as_slice().try_into().unwrap();
let pk = MLDSA65VerificationKey::from(pk_bytes);
let sk = MLDSA65SigningKey::from(sk_bytes);
```

## Testing Commands

```bash
# Test with verbose output to see sizes
cargo test --features "std,ml-kem,ml-dsa" -- --nocapture

# Build without tests
cargo build --features "std,ml-kem,ml-dsa"

# Check feature combinations
cargo build --no-default-features --features "ml-kem"
cargo build --no-default-features --features "ml-dsa"
cargo build --no-default-features --features "ml-kem,ml-dsa"
```