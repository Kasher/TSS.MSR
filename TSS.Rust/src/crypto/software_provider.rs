//! A [`CryptoProvider`] built on the pure-Rust RustCrypto crates.
//!
//! This is the default backend and needs no platform support, so it works the same on every
//! target. Hosts that would rather not link a second implementation of primitives their operating
//! system already provides can disable the `software-crypto` feature and supply their own
//! provider instead.

use super::provider::{CryptoProvider, RsaOps};
use super::{Crypto, RsaKeyParts, RSA_DEFAULT_EXPONENT};
use crate::{error::TpmError, tpm_types::TPM_ALG_ID};

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;

/// The RustCrypto-backed provider.
pub static SOFTWARE_PROVIDER: CryptoProvider = CryptoProvider {
    hash,
    hmac,
    aes_cfb,
    random,
    rsa: RsaOps {
        oaep_encrypt: rsa_oaep_encrypt,
        pkcs1v15_verify: rsa_pkcs1v15_verify,
        generate_keypair: rsa_generate_keypair,
        pkcs1v15_sign: rsa_pkcs1v15_sign,
    },
};

fn hash(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    // If the data is empty, return an empty digest of correct size
    if data.is_empty() {
        return Ok(vec![0; Crypto::digestSize(alg)]);
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

    let expected_size = Crypto::digestSize(alg);
    if digest.len() != expected_size {
        return Err(TpmError::InvalidArraySize(format!(
            "Hash output length mismatch: expected {}, got {}",
            expected_size,
            digest.len()
        )));
    }

    Ok(digest)
}

fn hmac(hash_alg: TPM_ALG_ID, key: &[u8], to_hash: &[u8]) -> Result<Vec<u8>, TpmError> {
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
            let mut mac = <Hmac<Sm3> as Mac>::new_from_slice(key).map_err(|_| {
                TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
            })?;
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

fn rsa_oaep_encrypt(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    label: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TpmError> {
    let rsa_key = rsa_public_key(modulus, exponent)?;

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

fn rsa_pkcs1v15_verify(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError> {
    let rsa_key = rsa_public_key(modulus, exponent)?;
    let scheme = pkcs1v15_sign_scheme(hash_alg)?;
    Ok(rsa_key.verify(scheme, digest, signature).is_ok())
}

fn rsa_generate_keypair(key_bits: usize) -> Result<RsaKeyParts, TpmError> {
    let priv_key = RsaPrivateKey::new(&mut OsRng, key_bits)
        .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {}", e)))?;

    let prime = priv_key
        .primes()
        .first()
        .ok_or_else(|| TpmError::GenericError("Generated RSA key exposes no primes".to_string()))?;

    Ok(RsaKeyParts {
        modulus: priv_key.n().to_bytes_be(),
        prime: prime.to_bytes_be(),
    })
}

/// Sign an already computed digest with RSASSA-PKCS1-v1_5.
///
/// The second prime is recovered as `modulus / prime`.
fn rsa_pkcs1v15_sign(
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
        .sign(pkcs1v15_sign_scheme(hash_alg)?, digest)
        .map_err(|e| TpmError::GenericError(format!("RSA signing failed: {}", e)))
}

fn aes_cfb(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    if key.len() != 16 && key.len() != 24 && key.len() != 32 {
        return Err(TpmError::InvalidArraySize(
            "Invalid AES key length".to_string(),
        ));
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

fn random(out: &mut [u8]) -> Result<(), TpmError> {
    OsRng
        .try_fill_bytes(out)
        .map_err(|e| TpmError::GenericError(format!("Failed to obtain random bytes: {e}")))
}
