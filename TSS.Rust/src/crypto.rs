use crate::{error::TpmError, tpm_types::*};
use hmac::{Hmac, Mac};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;
use rand::{rngs::OsRng, RngCore};
use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;

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
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported hash algorithm: {:?}",
                    hash_alg
                )))
            }
        }
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

        let rsa_public_key = RsaPublicKey::new(BigUint::from_bytes_be(rsa_pub_key), BigUint::from_bytes_be(&[1, 0, 1]))
            .map_err(|_| TpmError::InvalidArraySize("Invalid RSA public key".to_string()))?;

        Ok(rsa_public_key
            .verify(
                Pkcs1v15Sign::new::<Sha1>(),
                &signed_blob_hash,
                &signature.sig
            ).is_ok())
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
        let bytes_needed = (bits + 7) / 8;
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
        let mut feedback = GenericArray::from_slice(iv).clone();

        for chunk in data.chunks(16) {
            // Encrypt the feedback (IV or previous ciphertext)
            let mut encrypted_feedback = feedback.clone();
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
