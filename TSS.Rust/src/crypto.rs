use crate::{error::TpmError, tpm_types::*};
use hmac::{Hmac, Mac};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;
use rand::{rngs::OsRng, RngCore};
use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;

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
        // If the data is empty, return an empty digest of correct size
        if data.is_empty() {
            return Ok(vec![0; Self::digestSize(alg)]);
        }

        let digest = match alg {
            TPM_ALG_ID::SHA1 => {
                let mut hasher = Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SHA512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SM3_256 => {
                let mut hasher = Sm3::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported hash algorithm: {:?}",
                    alg
                )))
            }
        };

        let expected_size = Self::digestSize(alg);
        if (digest.len() != expected_size) {
            return Err(TpmError::InvalidArraySize(format!(
                "Hash output length mismatch: expected {}, got {}",
                expected_size,
                digest.len()
            )));
        }

        Ok(digest)
    }

    pub fn hmac(hash_alg: TPM_ALG_ID, key: &[u8], to_hash: &[u8]) -> Result<Vec<u8>, TpmError> {
        // Choose the appropriate HMAC algorithm based on the hash algorithm
        match hash_alg {
            TPM_ALG_ID::SHA1 => {
                let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SHA256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SHA384 => {
                let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SHA512 => {
                let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SM3_256 => {
                let mut mac =
                    <Hmac<Sm3> as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            _ => Err(TpmError::NotSupported(format!(
                "Unsupported hash algorithm: {:?}",
                hash_alg
            ))),
        }
    }

    fn pkcs1v15_sign_scheme(hash_alg: TPM_ALG_ID) -> Result<Pkcs1v15Sign, TpmError> {
        match hash_alg {
            TPM_ALG_ID::SHA1 => Ok(Pkcs1v15Sign::new::<Sha1>()),
            TPM_ALG_ID::SHA256 => Ok(Pkcs1v15Sign::new::<Sha256>()),
            TPM_ALG_ID::SHA384 => Ok(Pkcs1v15Sign::new::<Sha384>()),
            TPM_ALG_ID::SHA512 => Ok(Pkcs1v15Sign::new::<Sha512>()),
            _ => Err(TpmError::NotSupported(format!(
                "Unsupported RSASSA hash algorithm: {:?}",
                hash_alg
            ))),
        }
    }

    /// Build an RSA public key from its big-endian components.
    fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, TpmError> {
        RsaPublicKey::new(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(exponent),
        )
        .map_err(|_| TpmError::InvalidArraySize("Invalid RSA public key".to_string()))
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
        let rsa_key = Self::rsa_public_key(modulus, exponent)?;

        // The `rsa` crate models an OAEP label as a string rather than as bytes, so the label
        // has to be converted here. Callers work in bytes because that is what the TPM
        // specification and other crypto backends use.
        let label = std::str::from_utf8(label)
            .map_err(|_| TpmError::NotSupported("OAEP label must be valid UTF-8".to_string()))?;

        let padding = match hash_alg {
            TPM_ALG_ID::SHA1 => Oaep::new_with_label::<Sha1, _>(label),
            TPM_ALG_ID::SHA256 => Oaep::new_with_label::<Sha256, _>(label),
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported nameAlg for OAEP: {:?}",
                    hash_alg
                )))
            }
        };

        rsa_key
            .encrypt(&mut OsRng, padding, data)
            .map_err(|e| TpmError::GenericError(format!("RSA-OAEP encryption failed: {e}")))
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over an already computed digest.
    pub fn rsa_pkcs1v15_verify(
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        let rsa_key = Self::rsa_public_key(modulus, exponent)?;
        let scheme = Self::pkcs1v15_sign_scheme(hash_alg)?;
        Ok(rsa_key.verify(scheme, digest, signature).is_ok())
    }

    /// Generate an RSA key pair in software, returning the modulus and the first prime.
    pub fn rsa_generate_keypair(key_bits: usize) -> Result<RsaKeyParts, TpmError> {
        let priv_key = RsaPrivateKey::new(&mut OsRng, key_bits)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {}", e)))?;

        let prime = priv_key.primes().first().ok_or_else(|| {
            TpmError::GenericError("Generated RSA key exposes no primes".to_string())
        })?;

        Ok(RsaKeyParts {
            modulus: priv_key.n().to_bytes_be(),
            prime: prime.to_bytes_be(),
        })
    }

    /// Sign an already computed digest with RSASSA-PKCS1-v1_5.
    ///
    /// The second prime is recovered as `modulus / prime`.
    pub fn rsa_pkcs1v15_sign(
        key: &RsaKeyParts,
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        // Recovering the second prime divides by the first, so reject a zero prime up front
        // instead of letting the big-integer division panic.
        if key.prime.iter().all(|&byte| byte == 0) {
            return Err(TpmError::InvalidArraySize(
                "RSA private key prime is zero".to_string(),
            ));
        }

        let modulus = BigUint::from_bytes_be(&key.modulus);
        let first_prime = BigUint::from_bytes_be(&key.prime);
        let second_prime = &modulus / &first_prime;
        let exponent = BigUint::from_bytes_be(&RSA_DEFAULT_EXPONENT);

        let priv_key = RsaPrivateKey::from_p_q(first_prime, second_prime, exponent)
            .map_err(|e| TpmError::GenericError(format!("Failed to reconstruct RSA key: {}", e)))?;

        priv_key
            .sign(Self::pkcs1v15_sign_scheme(hash_alg)?, digest)
            .map_err(|e| TpmError::GenericError(format!("RSA signing failed: {}", e)))
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
        data: &[u8]
    ) -> Result<Vec<u8>, TpmError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(TpmError::InvalidArraySize("Invalid AES key length".to_string()));
        }
        
        if iv.len() != 16 {
            return Err(TpmError::InvalidArraySize("IV must be 16 bytes".to_string()));
        }

        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut result = Vec::with_capacity(data.len());
        let mut feedback = *GenericArray::from_slice(iv);

        for chunk in data.chunks(16) {
            // Encrypt the feedback (IV or previous ciphertext)
            let mut encrypted_feedback = feedback;
            cipher.encrypt_block(&mut encrypted_feedback);

            if encrypt {
                // CFB encrypt: ciphertext = plaintext XOR encrypt(feedback)
                // Next feedback = ciphertext
                let mut ct_block = [0u8; 16];
                for (i, &b) in chunk.iter().enumerate() {
                    ct_block[i] = b ^ encrypted_feedback[i];
                    result.push(ct_block[i]);
                }
                feedback.copy_from_slice(&ct_block);
            } else {
                // CFB decrypt: plaintext = ciphertext XOR encrypt(feedback)
                // Next feedback = ciphertext (input)
                let mut ct_block = [0u8; 16];
                ct_block[..chunk.len()].copy_from_slice(chunk);
                for (i, &b) in chunk.iter().enumerate() {
                    result.push(b ^ encrypted_feedback[i]);
                }
                feedback.copy_from_slice(&ct_block);
            }
        }

        result.truncate(data.len());
        Ok(result)
    }

    // Get random bytes
    pub fn get_random(num_bytes: usize) -> Vec<u8> {
        let mut result = vec![0u8; num_bytes];
        OsRng.fill_bytes(&mut result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

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
