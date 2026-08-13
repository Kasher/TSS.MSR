//! Cryptography used to build and check TPM structures on the host.
//!
//! This module is split into two layers. [`provider`] defines the primitives TSS.Rust needs from
//! a crypto backend, and [`software_provider`] supplies one built on the pure-Rust RustCrypto
//! crates.
//! [`Crypto`] sits on top and adds the logic that the TPM 2.0 specification defines in terms of
//! those primitives — digest sizes, KDFa, signature validation — which is the same regardless of
//! which backend is in use.

pub mod provider;
pub mod software_provider;

use crate::{error::TpmError, tpm_types::*};
use provider::CryptoProvider;

/// The RSA public exponent used by every key this library creates or consumes (65537, "F4").
///
/// A TPM encodes this value as zero in `TPMS_RSA_PARMS::exponent`, so it never travels on the
/// wire and has to be supplied by the caller.
pub const RSA_DEFAULT_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// RSA private key material in the form `TSS_KEY` persists it: the modulus and the first prime.
///
/// The second prime is recovered by dividing the modulus by the first, so it is not stored.
#[derive(Clone, Debug)]
pub struct RsaKeyParts {
    pub modulus: Vec<u8>,
    pub prime: Vec<u8>,
}

pub struct Crypto;

impl Crypto {
    /// The backend every primitive is currently routed through.
    ///
    /// Callers will pass a [`CryptoProvider`] explicitly in a later change; until then the
    /// software backend is selected here so that this refactoring does not alter behaviour.
    fn provider() -> &'static CryptoProvider {
        &software_provider::SOFTWARE_PROVIDER
    }

    /// The length in bytes of a digest produced by `alg`, or zero if `alg` is not a hash.
    ///
    /// This is fixed by the TPM 2.0 specification, so it does not depend on the backend.
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

    // Hash a byte buffer using the specified algorithm
    pub fn hash(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        (Self::provider().hash)(alg, data)
    }

    pub fn hmac(hash_alg: TPM_ALG_ID, key: &[u8], to_hash: &[u8]) -> Result<Vec<u8>, TpmError> {
        (Self::provider().hmac)(hash_alg, key, to_hash)
    }

    /// RSA-OAEP encrypt `data` under the public key given by its big-endian components.
    ///
    /// `label` is used verbatim, so callers must include the trailing NUL that the TPM
    /// specification puts in labels such as `b"IDENTITY\0"`.
    pub fn rsa_oaep_encrypt(
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        label: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (Self::provider().rsa.oaep_encrypt)(modulus, exponent, hash_alg, label, data)
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over an already computed digest.
    pub fn rsa_pkcs1v15_verify(
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        (Self::provider().rsa.pkcs1v15_verify)(modulus, exponent, hash_alg, digest, signature)
    }

    /// Generate an RSA key pair, returning the modulus and the first prime.
    pub fn rsa_generate_keypair(key_bits: usize) -> Result<RsaKeyParts, TpmError> {
        (Self::provider().rsa.generate_keypair)(key_bits)
    }

    /// Sign an already computed digest with RSASSA-PKCS1-v1_5.
    pub fn rsa_pkcs1v15_sign(
        key: &RsaKeyParts,
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (Self::provider().rsa.pkcs1v15_sign)(key, hash_alg, digest)
    }

    pub fn validate_signature(
        public_key: &TPMT_PUBLIC,
        signed_blob_hash: Vec<u8>,
        signature: &Option<TPMU_SIGNATURE>,
    ) -> Result<bool, TpmError> {
        if !matches!(&public_key.parameters, Some(TPMU_PUBLIC_PARMS::rsaDetail(_))) {
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

        let expected_digest_size = Self::digestSize(signature.hash);
        if signed_blob_hash.len() != expected_digest_size {
            return Err(TpmError::InvalidArraySize(format!(
                "ValidateSignature: digest length {} does not match {:?} length {}",
                signed_blob_hash.len(),
                signature.hash,
                expected_digest_size
            )));
        }

        Self::rsa_pkcs1v15_verify(
            rsa_pub_key,
            &RSA_DEFAULT_EXPONENT,
            signature.hash,
            &signed_blob_hash,
            &signature.sig,
        )
    }

    // KDFa implementation as specified in TPM 2.0 Part 1
    pub fn kdfa(
        hash_alg: TPM_ALG_ID,
        key: &[u8],
        label: &str,
        context_u: &[u8],
        context_v: &[u8],
        bits: usize,
    ) -> Result<Vec<u8>, TpmError> {
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
            let hmac_result = Self::hmac(hash_alg, key, &to_hash)?;
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
        encrypt: bool,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (Self::provider().aes_cfb)(encrypt, key, iv, data)
    }

    /// Return `num_bytes` of cryptographically secure random data.
    pub fn get_random(num_bytes: usize) -> Result<Vec<u8>, TpmError> {
        let mut result = vec![0u8; num_bytes];
        (Self::provider().random)(&mut result)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey};
    use sha2::{Digest as Sha2Digest, Sha256};

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

        assert!(Crypto::validate_signature(&public_key, digest, &signature)?);
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
        let key = Crypto::rsa_generate_keypair(2048)?;
        let digest = Sha256::digest(b"software key signing regression").to_vec();

        let signature = Crypto::rsa_pkcs1v15_sign(&key, TPM_ALG_ID::SHA256, &digest)?;

        assert!(Crypto::rsa_pkcs1v15_verify(
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
        };

        assert!(Crypto::rsa_pkcs1v15_sign(&key, TPM_ALG_ID::SHA256, &[0u8; 32]).is_err());
    }
}
