//! The pluggable crypto backend interface.
//!
//! TSS.Rust needs a handful of cryptographic primitives to build TPM structures on the host: to
//! hash a public area into a name, to derive session keys with KDFa, to wrap an activation
//! credential, and so on. Which library performs those primitives is a deployment decision, not a
//! protocol decision, so it is expressed here as a value the caller supplies.
//!
//! A provider is a plain struct of function pointers rather than a trait object. That keeps
//! [`CryptoProvider`] `Copy`, lets it be built in a `const` context, and means threading one
//! through a call chain costs no more than passing a pointer. This mirrors how `jsonwebtoken`
//! models its own pluggable backend.
//!
//! Deliberately, there is no process-wide default provider. TSS.Rust is built as a `cdylib` as
//! well as an `rlib`, and hosts that load and unload it repeatedly would have to reason about the
//! lifetime of any global. Requiring the provider at the call site also lets a single process use
//! two backends at once, which is what makes cross-provider equivalence testing possible.
//!
//! Only primitives belong here. Logic defined by the TPM 2.0 specification — digest sizes, KDFa,
//! signature validation — is built on top of these primitives by [`Crypto`](super::Crypto) and is
//! identical no matter which backend is in use.

use super::RsaKeyParts;
use crate::{error::TpmError, tpm_types::TPM_ALG_ID};

/// Signature of [`CryptoProvider::hash`].
pub type HashFn = fn(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Signature of [`CryptoProvider::hmac`].
pub type HmacFn = fn(alg: TPM_ALG_ID, key: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Signature of [`CryptoProvider::aes_cfb`].
pub type AesCfbFn =
    fn(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Signature of [`CryptoProvider::random`].
pub type RandomFn = fn(out: &mut [u8]) -> Result<(), TpmError>;

/// Signature of [`RsaOps::oaep_encrypt`].
pub type RsaOaepEncryptFn = fn(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    label: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TpmError>;

/// Signature of [`RsaOps::pkcs1v15_verify`].
pub type RsaPkcs1v15VerifyFn = fn(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError>;

/// Signature of [`RsaOps::generate_keypair`].
pub type RsaGenerateKeypairFn =
    fn(key_bits: usize, exponent: &[u8]) -> Result<RsaKeyParts, TpmError>;

/// Signature of [`RsaOps::pkcs1v15_sign`].
pub type RsaPkcs1v15SignFn =
    fn(key: &RsaKeyParts, hash_alg: TPM_ALG_ID, digest: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Returns the error reported by every primitive a provider leaves unimplemented.
fn unimplemented(operation: &str) -> TpmError {
    TpmError::NotSupported(format!(
        "The configured crypto provider does not implement {operation}"
    ))
}

/// The RSA primitives a provider supplies.
///
/// These are split out from [`CryptoProvider`] so that a backend able to offer only some of them
/// can start from [`RsaOps::new_unimplemented`] and fill in what it supports. That is not a
/// hypothetical: a provider built on Windows CNG cannot implement [`RsaOps::pkcs1v15_sign`],
/// because signing here has to recover the second prime by dividing the modulus by the first and
/// CNG exposes no big-integer division.
#[derive(Clone, Copy, Debug)]
pub struct RsaOps {
    /// RSA-OAEP encrypt `data` under the public key given by its big-endian components.
    ///
    /// `label` is passed through verbatim, so it must already include the trailing NUL that the
    /// TPM specification puts in labels such as `b"IDENTITY\0"`.
    pub oaep_encrypt: RsaOaepEncryptFn,

    /// Verify an RSASSA-PKCS1-v1_5 signature over an already computed digest.
    ///
    /// A `false` result means the signature did not verify. An `Err` means the verification could
    /// not be performed at all, for instance because the key or the hash algorithm was rejected.
    pub pkcs1v15_verify: RsaPkcs1v15VerifyFn,

    /// Generate an RSA key pair, returning the modulus and the first prime.
    pub generate_keypair: RsaGenerateKeypairFn,

    /// Sign an already computed digest with RSASSA-PKCS1-v1_5.
    pub pkcs1v15_sign: RsaPkcs1v15SignFn,
}

impl RsaOps {
    /// A set of RSA operations that all report [`TpmError::NotSupported`].
    ///
    /// Intended as a base for functional record update, so a backend states only what it provides:
    ///
    /// ```ignore
    /// RsaOps {
    ///     oaep_encrypt: my_oaep_encrypt,
    ///     ..RsaOps::new_unimplemented()
    /// }
    /// ```
    pub const fn new_unimplemented() -> Self {
        Self {
            oaep_encrypt: |_, _, _, _, _| Err(unimplemented("RSA-OAEP encryption")),
            pkcs1v15_verify: |_, _, _, _, _| Err(unimplemented("RSA PKCS#1 v1.5 verification")),
            generate_keypair: |_, _| Err(unimplemented("RSA key generation")),
            pkcs1v15_sign: |_, _, _| Err(unimplemented("RSA PKCS#1 v1.5 signing")),
        }
    }
}

/// The cryptographic primitives TSS.Rust needs from its host.
#[derive(Clone, Copy, Debug)]
pub struct CryptoProvider {
    /// Hash `data` with `alg`, returning a digest of exactly `Crypto::digestSize(alg)` bytes.
    pub hash: HashFn,

    /// HMAC `data` under `key` using `alg`. The key may be of any length.
    pub hmac: HmacFn,

    /// AES in CFB mode with a full 128-bit segment, as the TPM specification requires.
    ///
    /// `data` is not required to be a multiple of the block size; the final partial block is
    /// processed against a truncated key stream. Backends layered on an API whose CFB mode
    /// defaults to an 8-bit segment must not use that mode here.
    pub aes_cfb: AesCfbFn,

    /// Fill `out` with cryptographically secure random bytes.
    pub random: RandomFn,

    /// The RSA primitives.
    pub rsa: RsaOps,
}

impl CryptoProvider {
    /// A provider whose every primitive reports [`TpmError::NotSupported`].
    ///
    /// Intended as a base for functional record update, in the same way as
    /// [`RsaOps::new_unimplemented`].
    pub const fn new_unimplemented() -> Self {
        Self {
            hash: |_, _| Err(unimplemented("hashing")),
            hmac: |_, _, _| Err(unimplemented("HMAC")),
            aes_cfb: |_, _, _, _| Err(unimplemented("AES-CFB")),
            random: |_| Err(unimplemented("random number generation")),
            rsa: RsaOps::new_unimplemented(),
        }
    }
}
