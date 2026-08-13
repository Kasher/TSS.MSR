//! Cryptography used to build and check TPM structures on the host.
//!
//! This module is split into two layers. [`provider`] defines the primitives TSS.Rust needs from
//! a crypto backend, and [`software_provider`] supplies one built on the pure-Rust RustCrypto
//! crates.
//! [`Crypto`] sits on top and adds the logic that the TPM 2.0 specification defines in terms of
//! those primitives — digest sizes, KDFa, signature validation — which is the same regardless of
//! which backend is in use.
//!
//! There is no ambient default backend. Every operation that needs one takes a
//! [`CryptoProvider`](provider::CryptoProvider) from its caller, so which backend runs is always
//! visible at the call site. [`Tpm2`](crate::tpm2_impl::Tpm2) holds the provider it was built with
//! and supplies it to the command dispatch path on the caller's behalf.

pub mod provider;
#[cfg(feature = "software-crypto")]
pub mod software_provider;

use crate::{error::TpmError, tpm_types::*};
use provider::CryptoProvider;

/// The RSA public exponent the TPM 2.0 specification defines as the default (65537, "F4").
///
/// `TPMS_RSA_PARMS::exponent` encodes this value as zero, so it never travels on the wire.
/// Resolve a stored zero with `TPMS_RSA_PARMS::exponent_bytes` rather than reaching for this
/// constant directly, so that a key declaring a different exponent is honoured.
pub const RSA_DEFAULT_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// RSA private key material in the form `TSS_KEY` persists it: the modulus and the first prime,
/// plus the public exponent needed to reconstruct the key.
///
/// The second prime is recovered by dividing the modulus by the first, so it is not stored.
#[derive(Clone, Debug)]
pub struct RsaKeyParts {
    pub modulus: Vec<u8>,
    pub prime: Vec<u8>,
    /// The public exponent, big-endian and without leading zeros. Callers holding a
    /// `TPMS_RSA_PARMS` should populate this with `TPMS_RSA_PARMS::exponent_bytes`, which
    /// resolves the specification's zero-means-65537 encoding.
    pub exponent: Vec<u8>,
}

pub struct Crypto;

impl Crypto {
    /// The length in bytes of a digest produced by `alg`, or zero if `alg` is not a hash.
    ///
    /// This is fixed by the TPM 2.0 specification, so it does not depend on the backend.
    ///
    /// Returning zero rather than an error is deliberate, and there are two reasons not to
    /// "fix" it. `TPMT_HA` unmarshalling calls this to decide how many digest bytes to read,
    /// and a `TPMT_HA` selected by `TPM_ALG_NULL` carries no digest at all, so zero is the
    /// correct answer there rather than a failure. That call site also lives in a generated
    /// file, which cannot be hand edited, and it has no error path to return one through.
    ///
    /// Every other caller wants `digest_size_checked`, which turns the zero into an error.
    // The function is called from an auto-generated file that expects this specific (non snake_cased) name
    #[allow(non_snake_case)]
    pub fn digestSize(alg: TPM_ALG_ID) -> usize {
        match alg {
            TPM_ALG_ID::SHA1 => 20,
            TPM_ALG_ID::SHA256 => 32,
            TPM_ALG_ID::SHA384 => 48,
            TPM_ALG_ID::SHA512 => 64,
            TPM_ALG_ID::SM3_256 => 32,
            _ => 0,
        }
    }

    /// The length in bytes of a digest produced by `alg`, or an error if `alg` is not a hash.
    ///
    /// This is the variant to reach for by default. `digestSize` answers zero for a non-hash
    /// algorithm, which silently produces an empty seed, key or nonce wherever the result sizes
    /// a buffer. Use `digestSize` only where a zero length is a legitimate answer, which in
    /// practice means `TPMT_HA` unmarshalling.
    pub fn digest_size_checked(alg: TPM_ALG_ID) -> Result<usize, TpmError> {
        match Self::digestSize(alg) {
            0 => Err(TpmError::NotSupported(format!(
                "Not a hash algorithm: {alg:?}"
            ))),
            size => Ok(size),
        }
    }

    // Hash a byte buffer using the specified algorithm
    pub fn hash(
        provider: &CryptoProvider,
        alg: TPM_ALG_ID,
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.hash)(alg, data)
    }

    pub fn hmac(
        provider: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        key: &[u8],
        to_hash: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.hmac)(hash_alg, key, to_hash)
    }

    /// RSA-OAEP encrypt `data` under the public key given by its big-endian components.
    ///
    /// `label` is used verbatim, so callers must include the trailing NUL that the TPM
    /// specification puts in labels such as `b"IDENTITY\0"`.
    pub fn rsa_oaep_encrypt(
        provider: &CryptoProvider,
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        label: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.rsa.oaep_encrypt)(modulus, exponent, hash_alg, label, data)
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over an already computed digest.
    pub fn rsa_pkcs1v15_verify(
        provider: &CryptoProvider,
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        (provider.rsa.pkcs1v15_verify)(modulus, exponent, hash_alg, digest, signature)
    }

    /// Generate an RSA key pair with the given public exponent, returning the modulus and the
    /// first prime.
    ///
    /// `exponent` is big-endian. Callers holding a `TPMS_RSA_PARMS` should pass
    /// `TPMS_RSA_PARMS::exponent_bytes`, which resolves the zero-means-65537 encoding. A backend
    /// that cannot honour an arbitrary exponent must reject it rather than substitute its own.
    pub fn rsa_generate_keypair(
        provider: &CryptoProvider,
        key_bits: usize,
        exponent: &[u8],
    ) -> Result<RsaKeyParts, TpmError> {
        (provider.rsa.generate_keypair)(key_bits, exponent)
    }

    /// Sign an already computed digest with RSASSA-PKCS1-v1_5.
    pub fn rsa_pkcs1v15_sign(
        provider: &CryptoProvider,
        key: &RsaKeyParts,
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.rsa.pkcs1v15_sign)(key, hash_alg, digest)
    }

    pub fn validate_signature(
        provider: &CryptoProvider,
        public_key: &TPMT_PUBLIC,
        signed_blob_hash: Vec<u8>,
        signature: &Option<TPMU_SIGNATURE>,
    ) -> Result<bool, TpmError> {
        let rsa_params =
            if let Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) = &public_key.parameters {
                params
            } else {
                return Err(TpmError::NotSupported(
                    "ValidateSignature: Only RSA is supported".to_string(),
                ));
            };

        let signature = if let Some(TPMU_SIGNATURE::rsassa(signature)) = &signature {
            signature
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSASSA scheme is supported".to_string(),
            ));
        };

        let rsa_pub_key = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &public_key.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSA public key is supported".to_string(),
            ));
        };

        let expected_digest_size = Self::digest_size_checked(signature.hash)?;
        if signed_blob_hash.len() != expected_digest_size {
            return Err(TpmError::InvalidArraySize(format!(
                "ValidateSignature: digest length {} does not match {:?} length {}",
                signed_blob_hash.len(),
                signature.hash,
                expected_digest_size
            )));
        }

        Self::rsa_pkcs1v15_verify(
            provider,
            rsa_pub_key,
            &rsa_params.exponent_bytes(),
            signature.hash,
            &signed_blob_hash,
            &signature.sig,
        )
    }

    // KDFa implementation as specified in TPM 2.0 Part 1
    pub fn kdfa(
        provider: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        key: &[u8],
        label: &str,
        context_u: &[u8],
        context_v: &[u8],
        bits: usize,
    ) -> Result<Vec<u8>, TpmError> {
        // Zero bits would make the loop below exit immediately and hand back an empty key, which
        // every caller would then use as if it were real key material.
        if bits == 0 {
            return Err(TpmError::InvalidArraySize(
                "KDFa was asked to produce zero bits of key material".to_string(),
            ));
        }

        let bytes_needed = bits.div_ceil(8);
        let mut result = Vec::new();
        let mut counter = 1u32;

        while result.len() < bytes_needed {
            let mut to_hash = Vec::new();

            // Counter in big-endian
            to_hash.extend_from_slice(&counter.to_be_bytes());

            // Label
            to_hash.extend_from_slice(label.as_bytes());

            // 00 byte separator
            to_hash.push(0u8);

            // contextU
            to_hash.extend_from_slice(context_u);

            // contextV
            to_hash.extend_from_slice(context_v);

            // Number of bits in big-endian
            to_hash.extend_from_slice(&(bits as u32).to_be_bytes());

            // Perform HMAC
            let hmac_result = Self::hmac(provider, hash_alg, key, &to_hash)?;
            result.extend_from_slice(&hmac_result);

            counter = counter.checked_add(1).ok_or_else(|| {
                TpmError::InvalidArraySize("Counter overflow in KDFa".to_string())
            })?;
        }

        // Truncate to exact size needed
        result.truncate(bytes_needed);
        Ok(result)
    }

    // AES CFB encryption/decryption
    pub fn cfb_xcrypt(
        provider: &CryptoProvider,
        encrypt: bool,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.aes_cfb)(encrypt, key, iv, data)
    }

    /// Return `num_bytes` of cryptographically secure random data.
    pub fn get_random(provider: &CryptoProvider, num_bytes: usize) -> Result<Vec<u8>, TpmError> {
        let mut result = vec![0u8; num_bytes];
        (provider.random)(&mut result)?;
        Ok(result)
    }
}

// These tests exercise the software provider directly -- they verify against the `rsa` crate --
// so they only apply when that backend is compiled in.
#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey};
    use sha2::{Digest as Sha2Digest, Sha256};
    use software_provider::SOFTWARE_PROVIDER;

    #[test]
    fn validate_signature_uses_signature_hash_algorithm() -> Result<(), TpmError> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {e}")))?;
        let public_key = TPMT_PUBLIC {
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::default())),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: private_key.n().to_bytes_be(),
            })),
            ..Default::default()
        };

        let message = b"digest dispatch regression";
        let digest = Sha256::digest(message).to_vec();
        let sig = private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| TpmError::GenericError(format!("RSA signing failed: {e}")))?;
        let signature = Some(TPMU_SIGNATURE::rsassa(TPMS_SIGNATURE_RSASSA {
            hash: TPM_ALG_ID::SHA256,
            sig,
        }));

        assert!(Crypto::validate_signature(
            &SOFTWARE_PROVIDER,
            &public_key,
            digest,
            &signature
        )?);
        Ok(())
    }

    #[test]
    fn rsa_oaep_encrypt_round_trips_and_binds_the_label() -> Result<(), TpmError> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {e}")))?;
        let modulus = private_key.n().to_bytes_be();

        let plaintext = b"seed material";
        let ciphertext = Crypto::rsa_oaep_encrypt(
            &SOFTWARE_PROVIDER,
            &modulus,
            &RSA_DEFAULT_EXPONENT,
            TPM_ALG_ID::SHA256,
            b"IDENTITY\0",
            plaintext,
        )?;

        let decrypted = private_key
            .decrypt(Oaep::new_with_label::<Sha256, _>("IDENTITY\0"), &ciphertext)
            .map_err(|e| TpmError::GenericError(format!("OAEP decryption failed: {e}")))?;
        assert_eq!(decrypted, plaintext);

        // A different label must not recover the plaintext. This is what keeps the "IDENTITY\0"
        // and "SECRET\0" call sites distinct now that they share one implementation.
        assert!(private_key
            .decrypt(Oaep::new_with_label::<Sha256, _>("SECRET\0"), &ciphertext)
            .is_err());

        Ok(())
    }

    #[test]
    fn rsa_sign_round_trips_through_verify() -> Result<(), TpmError> {
        let key = Crypto::rsa_generate_keypair(&SOFTWARE_PROVIDER, 2048, &RSA_DEFAULT_EXPONENT)?;
        let digest = Sha256::digest(b"software key signing regression").to_vec();

        let signature =
            Crypto::rsa_pkcs1v15_sign(&SOFTWARE_PROVIDER, &key, TPM_ALG_ID::SHA256, &digest)?;

        assert!(Crypto::rsa_pkcs1v15_verify(
            &SOFTWARE_PROVIDER,
            &key.modulus,
            &RSA_DEFAULT_EXPONENT,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )?);
        Ok(())
    }

    #[test]
    fn rsa_sign_rejects_a_zero_prime_instead_of_dividing_by_it() {
        let key = RsaKeyParts {
            modulus: vec![0xff; 256],
            prime: vec![0u8; 128],
            exponent: RSA_DEFAULT_EXPONENT.to_vec(),
        };

        assert!(Crypto::rsa_pkcs1v15_sign(
            &SOFTWARE_PROVIDER,
            &key,
            TPM_ALG_ID::SHA256,
            &[0u8; 32]
        )
        .is_err());
    }

    #[test]
    fn rsa_sign_rejects_a_prime_that_does_not_divide_the_modulus() {
        // `from_p_q` recomputes the modulus as `p * q` rather than checking it against the one
        // supplied, so a prime that does not divide the modulus exactly would otherwise yield a
        // key with a silently different modulus whose signatures could never verify.
        let key = RsaKeyParts {
            modulus: vec![0xff; 256],
            prime: vec![0xfe; 128],
            exponent: RSA_DEFAULT_EXPONENT.to_vec(),
        };

        assert!(Crypto::rsa_pkcs1v15_sign(
            &SOFTWARE_PROVIDER,
            &key,
            TPM_ALG_ID::SHA256,
            &[0u8; 32]
        )
        .is_err());
    }

    #[test]
    fn rsa_round_trips_with_a_non_default_exponent() -> Result<(), TpmError> {
        // Generating with an exponent other than the default proves that generation, signing and
        // verification all read the caller's exponent instead of assuming 65537.
        let exponent: [u8; 3] = [0x00, 0x00, 0x03];
        let key = Crypto::rsa_generate_keypair(&SOFTWARE_PROVIDER, 2048, &exponent)?;
        assert_eq!(key.exponent, vec![0x03]);

        let digest = Sha256::digest(b"non default exponent").to_vec();
        let signature =
            Crypto::rsa_pkcs1v15_sign(&SOFTWARE_PROVIDER, &key, TPM_ALG_ID::SHA256, &digest)?;

        assert!(Crypto::rsa_pkcs1v15_verify(
            &SOFTWARE_PROVIDER,
            &key.modulus,
            &key.exponent,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )?);

        // The default exponent must not verify a signature made with this key.
        assert!(!Crypto::rsa_pkcs1v15_verify(
            &SOFTWARE_PROVIDER,
            &key.modulus,
            &RSA_DEFAULT_EXPONENT,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )?);
        Ok(())
    }

    #[test]
    fn hash_of_empty_input_is_the_real_digest() -> Result<(), TpmError> {
        // The empty string has a well known SHA-256 digest. Returning zeros of the right length
        // instead looks plausible but never matches what a TPM computes.
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &[])?,
            expected
        );
        Ok(())
    }

    #[test]
    fn hash_of_empty_input_still_rejects_an_unsupported_algorithm() {
        assert!(Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::NULL, &[]).is_err());
    }

    #[test]
    fn digest_size_checked_rejects_a_non_hash_algorithm() {
        assert_eq!(
            Crypto::digest_size_checked(TPM_ALG_ID::SHA256).ok(),
            Some(32)
        );
        assert!(Crypto::digest_size_checked(TPM_ALG_ID::NULL).is_err());
        assert!(Crypto::digest_size_checked(TPM_ALG_ID::RSA).is_err());
    }

    #[test]
    fn kdfa_rejects_a_request_for_zero_bits() {
        // Sizing a KDFa request from `digestSize` of a non-hash algorithm used to ask for zero
        // bits, and KDFa answered with an empty key instead of failing.
        assert!(Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            b"key",
            "ATH",
            &[],
            &[],
            0
        )
        .is_err());
    }

    #[test]
    fn kdfa_produces_the_requested_length() -> Result<(), TpmError> {
        let derived = Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            b"key",
            "ATH",
            &[],
            &[],
            256,
        )?;
        assert_eq!(derived.len(), 32);
        Ok(())
    }

    #[test]
    fn aes_cfb_round_trips_at_every_key_size() -> Result<(), TpmError> {
        // AES-192 and AES-256 keys used to be handed to an AES-128 cipher, which panicked.
        let iv = [0x5au8; 16];
        // Deliberately not a multiple of the block size, to cover the trailing partial block.
        let plaintext = b"CFB spans partial blocks too";

        for key_size in [16usize, 24, 32] {
            let key = vec![0xa5u8; key_size];
            let ciphertext = Crypto::cfb_xcrypt(&SOFTWARE_PROVIDER, true, &key, &iv, plaintext)?;
            assert_eq!(ciphertext.len(), plaintext.len());
            assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

            let recovered = Crypto::cfb_xcrypt(&SOFTWARE_PROVIDER, false, &key, &iv, &ciphertext)?;
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
        Ok(())
    }

    #[test]
    fn aes_cfb_rejects_an_unsupported_key_size() {
        assert!(
            Crypto::cfb_xcrypt(&SOFTWARE_PROVIDER, true, &[0u8; 20], &[0u8; 16], b"data").is_err()
        );
    }
}
