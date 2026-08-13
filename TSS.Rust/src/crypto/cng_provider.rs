//! A [`CryptoProvider`] built on Windows CNG.
//!
//! This backend adds no crates at all. Everything below is a call into `bcrypt.dll` through the
//! bindings the crate already depends on, so a Windows host can drop the `software-crypto`
//! feature and stop linking a second implementation of primitives the operating system already
//! ships, in FIPS validated form and under its own servicing.
//!
//! It does not replace [`software_provider`](super::software_provider) outright. Two of the nine
//! primitives are left unimplemented, for the reason recorded on
//! [`RsaOps`](super::provider::RsaOps): signing here needs the second prime recovered by dividing
//! the modulus by the first, and CNG exposes no big-integer division. A host that needs those two
//! keeps the software provider for them.
//!
//! Three things about this backend are worth knowing before reading it, because each is a place
//! where the obvious CNG call is the wrong one:
//!
//! * **No algorithm provider is ever opened.** Windows 8 introduced pseudo-handles, constants that
//!   stand in for an already-open provider, and the bindings expose one for every algorithm needed
//!   here. There is therefore no `BCryptOpenAlgorithmProvider`, no matching close, and no lifetime
//!   to manage for them.
//! * **AES-CFB is built on ECB rather than on `BCRYPT_CHAIN_MODE_CFB`.** See [`aes_cfb`].
//! * **The agreed ECDH value comes back byte reversed.** See [`raw_secret`].

use super::provider::{CryptoProvider, EccEphemeralAgreement, EccOps, RsaOps};
use super::Crypto;
use crate::{
    error::TpmError,
    tpm_types::{TPM_ALG_ID, TPM_ECC_CURVE},
};

use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{NTSTATUS, STATUS_INVALID_SIGNATURE};
use windows::Win32::Security::Cryptography::{
    BCryptDeriveKey, BCryptDestroyKey, BCryptDestroySecret, BCryptEncrypt, BCryptExportKey,
    BCryptFinalizeKeyPair, BCryptGenRandom, BCryptGenerateKeyPair, BCryptGenerateSymmetricKey,
    BCryptHash, BCryptImportKeyPair, BCryptSecretAgreement, BCryptVerifySignature,
    BCRYPTGENRANDOM_FLAGS, BCRYPT_AES_ECB_ALG_HANDLE, BCRYPT_ALG_HANDLE, BCRYPT_ECCKEY_BLOB,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE,
    BCRYPT_ECDH_P521_ALG_HANDLE, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PUBLIC_P384_MAGIC,
    BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_FLAGS, BCRYPT_HMAC_SHA1_ALG_HANDLE,
    BCRYPT_HMAC_SHA256_ALG_HANDLE, BCRYPT_HMAC_SHA384_ALG_HANDLE, BCRYPT_HMAC_SHA512_ALG_HANDLE,
    BCRYPT_KDF_RAW_SECRET, BCRYPT_KEY_HANDLE, BCRYPT_OAEP_PADDING_INFO, BCRYPT_PAD_OAEP,
    BCRYPT_PAD_PKCS1, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RNG_ALG_HANDLE, BCRYPT_RSAKEY_BLOB,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSA_ALG_HANDLE, BCRYPT_SECRET_HANDLE,
    BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA1_ALG_HANDLE, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA384_ALG_HANDLE,
    BCRYPT_SHA512_ALGORITHM, BCRYPT_SHA512_ALG_HANDLE,
};
use zeroize::Zeroizing;

/// The CNG-backed provider.
///
/// `generate_keypair` and `pkcs1v15_sign` are absent deliberately and report
/// [`TpmError::NotSupported`]; see the module documentation.
pub static CNG_PROVIDER: CryptoProvider = CryptoProvider {
    hash,
    hmac,
    aes_cfb,
    random,
    rsa: RsaOps {
        oaep_encrypt: rsa_oaep_encrypt,
        pkcs1v15_verify: rsa_pkcs1v15_verify,
        ..RsaOps::new_unimplemented()
    },
    ecc: EccOps {
        ephemeral_agree: ecc_ephemeral_agree,
    },
};

/// The AES block size, which is also the CFB segment width the TPM specification requires.
const AES_BLOCK_LEN: usize = 16;

/// Turns a failed `NTSTATUS` into an error naming both the operation and the raw status.
///
/// The status is reported rather than the `HRESULT` the bindings would convert it to, because the
/// `NTSTATUS` is the value CNG documents and the one worth searching for. `0xC000A000` says
/// "invalid signature"; the translated `HRESULT` says considerably less.
fn check(status: NTSTATUS, operation: &str) -> Result<(), TpmError> {
    if status.is_ok() {
        return Ok(());
    }

    Err(TpmError::GenericError(format!(
        "CNG {operation} failed with NTSTATUS 0x{:08X}",
        status.0 as u32
    )))
}

/// Owns a `BCRYPT_KEY_HANDLE` so that every exit path destroys it.
struct KeyHandle(BCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // Nothing useful can be done if this fails, and it runs on the unwind path too, so the
        // status is deliberately discarded rather than panicking a second time.
        unsafe {
            let _ = BCryptDestroyKey(self.0);
        }
    }
}

/// Owns a `BCRYPT_SECRET_HANDLE` so that every exit path destroys it.
///
/// The handle refers to an agreed value held inside CNG, so releasing it is what discards that
/// value rather than merely tidying up a bookkeeping slot.
struct SecretHandle(BCRYPT_SECRET_HANDLE);

impl Drop for SecretHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroySecret(self.0);
        }
    }
}

/// The already-open provider for a hash algorithm.
///
/// SM3 has no entry because CNG does not implement it. A TPM may nominate it, so this is a real
/// gap rather than an oversight, and it is reported as one instead of being approximated.
fn hash_alg_handle(alg: TPM_ALG_ID) -> Result<BCRYPT_ALG_HANDLE, TpmError> {
    match alg {
        TPM_ALG_ID::SHA1 => Ok(BCRYPT_SHA1_ALG_HANDLE),
        TPM_ALG_ID::SHA256 => Ok(BCRYPT_SHA256_ALG_HANDLE),
        TPM_ALG_ID::SHA384 => Ok(BCRYPT_SHA384_ALG_HANDLE),
        TPM_ALG_ID::SHA512 => Ok(BCRYPT_SHA512_ALG_HANDLE),
        other => Err(TpmError::NotSupported(format!(
            "CNG does not offer hash algorithm {other}"
        ))),
    }
}

/// The already-open provider for an HMAC over a hash algorithm.
///
/// These are separate pseudo-handles rather than the hash ones with a flag set, so the usual
/// `BCRYPT_ALG_HANDLE_HMAC_FLAG` dance at open time does not arise.
fn hmac_alg_handle(alg: TPM_ALG_ID) -> Result<BCRYPT_ALG_HANDLE, TpmError> {
    match alg {
        TPM_ALG_ID::SHA1 => Ok(BCRYPT_HMAC_SHA1_ALG_HANDLE),
        TPM_ALG_ID::SHA256 => Ok(BCRYPT_HMAC_SHA256_ALG_HANDLE),
        TPM_ALG_ID::SHA384 => Ok(BCRYPT_HMAC_SHA384_ALG_HANDLE),
        TPM_ALG_ID::SHA512 => Ok(BCRYPT_HMAC_SHA512_ALG_HANDLE),
        other => Err(TpmError::NotSupported(format!(
            "CNG does not offer HMAC over hash algorithm {other}"
        ))),
    }
}

/// The name CNG knows a hash algorithm by, for the padding structures that take one by string.
fn hash_alg_name(alg: TPM_ALG_ID) -> Result<PCWSTR, TpmError> {
    match alg {
        TPM_ALG_ID::SHA1 => Ok(BCRYPT_SHA1_ALGORITHM),
        TPM_ALG_ID::SHA256 => Ok(BCRYPT_SHA256_ALGORITHM),
        TPM_ALG_ID::SHA384 => Ok(BCRYPT_SHA384_ALGORITHM),
        TPM_ALG_ID::SHA512 => Ok(BCRYPT_SHA512_ALGORITHM),
        other => Err(TpmError::NotSupported(format!(
            "CNG does not offer hash algorithm {other}"
        ))),
    }
}

/// One-shot hashing, which is what `BCryptHash` is for.
///
/// The create, update, finish and destroy sequence would be needed only to hash data arriving in
/// pieces, and the provider contract hands over one slice.
fn hash(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let handle = hash_alg_handle(alg)?;
    let mut digest = vec![0u8; Crypto::digest_size_checked(alg)?];

    check(
        unsafe { BCryptHash(handle, None, data, &mut digest) },
        "hashing",
    )?;

    Ok(digest)
}

/// HMAC, which is the same one-shot call with the key supplied as the secret.
fn hmac(alg: TPM_ALG_ID, key: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let handle = hmac_alg_handle(alg)?;
    let mut mac = vec![0u8; Crypto::digest_size_checked(alg)?];

    check(
        unsafe { BCryptHash(handle, Some(key), data, &mut mac) },
        "HMAC",
    )?;

    Ok(mac)
}

fn random(out: &mut [u8]) -> Result<(), TpmError> {
    check(
        unsafe { BCryptGenRandom(Some(BCRYPT_RNG_ALG_HANDLE), out, BCRYPTGENRANDOM_FLAGS(0)) },
        "random number generation",
    )
}

/// AES in cipher feedback mode over a full block segment, built on the ECB primitive.
///
/// CNG does offer `BCRYPT_CHAIN_MODE_CFB`, and it is the wrong call twice over. Its segment
/// defaults to eight bits rather than a full block, which produces a completely different cipher
/// under a name that looks right; and it rejects input whose length is not a multiple of the block
/// size, which a TPM credential never satisfies, being a digest behind a two byte size. Driving
/// the block cipher directly avoids both. CFB is a stream mode, so consuming only the leading
/// bytes of the key stream for a trailing partial block is exactly what the mode calls for.
///
/// Only the block *encryption* is ever needed, in both directions, because CFB encrypts its
/// feedback value rather than the data.
fn aes_cfb(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError> {
    if iv.len() != AES_BLOCK_LEN {
        return Err(TpmError::InvalidArraySize(format!(
            "An AES-CFB IV must be {AES_BLOCK_LEN} bytes, not {}",
            iv.len()
        )));
    }

    // Rejected here rather than left to CNG, so the error names the length that was wrong.
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(TpmError::InvalidArraySize(format!(
            "An AES key must be 16, 24 or 32 bytes, not {}",
            key.len()
        )));
    }

    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe { BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, &mut handle, None, key, 0) },
        "AES key import",
    )?;
    let key_handle = KeyHandle(handle);

    let mut feedback = [0u8; AES_BLOCK_LEN];
    feedback.copy_from_slice(iv);

    let mut result = Vec::with_capacity(data.len());

    for chunk in data.chunks(AES_BLOCK_LEN) {
        let keystream = encrypt_block(&key_handle, &feedback)?;

        // The next feedback value is the ciphertext in both directions: when encrypting that is
        // the block just produced, when decrypting it is the block just consumed. A trailing
        // partial block is never fed forward, because nothing follows it.
        let mut next_feedback = [0u8; AES_BLOCK_LEN];

        for (index, &byte) in chunk.iter().enumerate() {
            let out = byte ^ keystream[index];
            next_feedback[index] = if encrypt { out } else { byte };
            result.push(out);
        }

        feedback = next_feedback;
    }

    Ok(result)
}

/// One raw AES block encryption.
fn encrypt_block(
    key: &KeyHandle,
    block: &[u8; AES_BLOCK_LEN],
) -> Result<[u8; AES_BLOCK_LEN], TpmError> {
    let mut out = [0u8; AES_BLOCK_LEN];
    let mut written = 0u32;

    // No padding flag, and a whole block in, so ECB returns exactly one block.
    check(
        unsafe {
            BCryptEncrypt(
                key.0,
                Some(block),
                None,
                None,
                Some(&mut out),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        },
        "AES block encryption",
    )?;

    if written as usize != AES_BLOCK_LEN {
        return Err(TpmError::InvalidArraySize(format!(
            "An AES block encryption returned {written} bytes rather than {AES_BLOCK_LEN}"
        )));
    }

    Ok(out)
}

/// What CNG needs to know about a curve, beyond the width the registry already defines.
///
/// The magic is part of the key blob and identifies the curve to the provider the blob is imported
/// into, so it has to match the pseudo-handle beside it.
struct CurveParams {
    provider: BCRYPT_ALG_HANDLE,
    public_magic: u32,
    key_bits: u32,
}

/// Only the NIST prime curves appear, because they are the only ones CNG names a provider for.
///
/// A Barreto-Naehrig or SM2 curve is rejected rather than approximated with a curve of similar
/// width: agreeing over the wrong curve derives a key the peer cannot reproduce, and nothing about
/// the resulting failure would point back here.
fn curve_params(curve: TPM_ECC_CURVE) -> Result<CurveParams, TpmError> {
    match curve {
        TPM_ECC_CURVE::NIST_P256 => Ok(CurveParams {
            provider: BCRYPT_ECDH_P256_ALG_HANDLE,
            public_magic: BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            key_bits: 256,
        }),
        TPM_ECC_CURVE::NIST_P384 => Ok(CurveParams {
            provider: BCRYPT_ECDH_P384_ALG_HANDLE,
            public_magic: BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            key_bits: 384,
        }),
        // 521 rather than 528: the key length is the curve's order in bits, while the coordinate
        // width rounds that up to whole octets.
        TPM_ECC_CURVE::NIST_P521 => Ok(CurveParams {
            provider: BCRYPT_ECDH_P521_ALG_HANDLE,
            public_magic: BCRYPT_ECDH_PUBLIC_P521_MAGIC,
            key_bits: 521,
        }),
        other => Err(TpmError::NotSupported(format!(
            "CNG cannot perform ECDH over curve {other}"
        ))),
    }
}

/// The fixed part of a `BCRYPT_ECCKEY_BLOB`, which the coordinates follow immediately.
const ECC_BLOB_HEADER_LEN: usize = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();

fn ecc_ephemeral_agree(
    curve: TPM_ECC_CURVE,
    peer_x: &[u8],
    peer_y: &[u8],
) -> Result<EccEphemeralAgreement, TpmError> {
    let params = curve_params(curve)?;
    let width = Crypto::ecc_coordinate_size(curve)?;

    // CNG reads a fixed width coordinate pair out of the blob, so a short encoding would be read
    // as a differently valued point rather than rejected.
    let x = Crypto::pad_ecc_coordinate(peer_x, width)?;
    let y = Crypto::pad_ecc_coordinate(peer_y, width)?;

    // An off-curve point is rejected by the import, which is the only validation performed on the
    // peer's point and the reason it happens before anything is agreed.
    let peer = import_public(&params, width, &x, &y)?;
    let ephemeral = generate_ephemeral(&params)?;
    let (ephemeral_x, ephemeral_y) = export_public_coordinates(&ephemeral, width)?;

    let mut secret = BCRYPT_SECRET_HANDLE::default();
    check(
        unsafe { BCryptSecretAgreement(ephemeral.0, peer.0, &mut secret, 0) },
        "ECDH secret agreement",
    )?;
    let secret = SecretHandle(secret);

    let z = raw_secret(&secret, width)?;

    Ok(EccEphemeralAgreement {
        z,
        ephemeral_x,
        ephemeral_y,
    })
}

/// Imports a public point that is already padded to the curve's width.
fn import_public(
    params: &CurveParams,
    width: usize,
    x: &[u8],
    y: &[u8],
) -> Result<KeyHandle, TpmError> {
    let mut blob = Vec::with_capacity(ECC_BLOB_HEADER_LEN + x.len() + y.len());
    blob.extend_from_slice(&params.public_magic.to_le_bytes());
    blob.extend_from_slice(&(width as u32).to_le_bytes());
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);

    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe {
            BCryptImportKeyPair(
                params.provider,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut handle,
                &blob,
                0,
            )
        },
        "ECC public key import",
    )?;

    Ok(KeyHandle(handle))
}

/// Generates a throwaway key on the peer's curve.
fn generate_ephemeral(params: &CurveParams) -> Result<KeyHandle, TpmError> {
    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe { BCryptGenerateKeyPair(params.provider, &mut handle, params.key_bits, 0) },
        "ECC key generation",
    )?;

    // The handle is owned from here on, so a failure to finalize still destroys it.
    let key = KeyHandle(handle);
    check(
        unsafe { BCryptFinalizeKeyPair(key.0, 0) },
        "ECC key finalization",
    )?;

    Ok(key)
}

/// Reads a key's public point back out of CNG.
fn export_public_coordinates(
    key: &KeyHandle,
    width: usize,
) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let mut required = 0u32;
    check(
        unsafe { BCryptExportKey(key.0, None, BCRYPT_ECCPUBLIC_BLOB, None, &mut required, 0) },
        "ECC public key export sizing",
    )?;

    let mut blob = vec![0u8; required as usize];
    check(
        unsafe {
            BCryptExportKey(
                key.0,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                Some(&mut blob),
                &mut required,
                0,
            )
        },
        "ECC public key export",
    )?;

    let coordinates = blob
        .get(ECC_BLOB_HEADER_LEN..ECC_BLOB_HEADER_LEN + 2 * width)
        .ok_or_else(|| {
            TpmError::InvalidArraySize(format!(
                "An exported ECC key blob of {} bytes is too short for two {width} byte coordinates",
                blob.len()
            ))
        })?;

    let (x, y) = coordinates.split_at(width);
    Ok((x.to_vec(), y.to_vec()))
}

/// The agreed value itself, in the big-endian order every caller expects it in.
///
/// Two things about this call are easy to get wrong and silent when wrong, since both produce a
/// well formed value of the right length that simply disagrees with the peer.
///
/// The first is the KDF. CNG offers to run the SP800-56A concatenation itself, and at least one
/// Windows release ignores the hash algorithm it is handed and always uses SHA-256. The
/// derivation the TPM defines belongs to [`Crypto::kdfe`](super::Crypto::kdfe) in any case, so
/// `BCRYPT_KDF_RAW_SECRET` is used to ask for the agreed value untouched.
///
/// The second is the byte order. That one export hands the value back least significant byte
/// first, unlike every other value CNG exports, so it is reversed here. Left padding afterwards
/// matters for the same reason the input coordinates are padded: the value is hashed at the
/// curve's full width, and a short encoding hashes to something else entirely.
fn raw_secret(secret: &SecretHandle, width: usize) -> Result<Zeroizing<Vec<u8>>, TpmError> {
    let mut agreed = Zeroizing::new(vec![0u8; width]);
    let mut written = 0u32;

    check(
        unsafe {
            BCryptDeriveKey(
                secret.0,
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut agreed),
                &mut written,
                0,
            )
        },
        "ECDH raw secret export",
    )?;

    let written = written as usize;
    if written == 0 || written > width {
        return Err(TpmError::InvalidArraySize(format!(
            "An ECDH agreement over a {width} byte curve returned {written} bytes"
        )));
    }

    agreed.truncate(written);
    agreed.reverse();

    if written == width {
        return Ok(agreed);
    }

    // `Zeroizing<Vec<u8>>` wipes the whole allocation rather than the live length, so the shorter
    // buffer is still cleared when it drops at the end of this function.
    let mut padded = Zeroizing::new(vec![0u8; width]);
    padded[width - written..].copy_from_slice(&agreed);
    Ok(padded)
}

/// Imports an RSA public key given its big-endian components.
///
/// The blob is a fixed header followed by the exponent and then the modulus, in that order. Both
/// prime lengths are zero, which is what marks the blob as carrying only the public half.
fn import_rsa_public(modulus: &[u8], exponent: &[u8]) -> Result<KeyHandle, TpmError> {
    if modulus.is_empty() || exponent.is_empty() {
        return Err(TpmError::InvalidArraySize(
            "An RSA public key needs both a modulus and an exponent".to_string(),
        ));
    }

    let header = BCRYPT_RSAKEY_BLOB {
        Magic: BCRYPT_RSAPUBLIC_MAGIC,
        BitLength: (modulus.len() * 8) as u32,
        cbPublicExp: exponent.len() as u32,
        cbModulus: modulus.len() as u32,
        cbPrime1: 0,
        cbPrime2: 0,
    };

    let header_len = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
    let mut blob = Vec::with_capacity(header_len + exponent.len() + modulus.len());

    // The header is plain old data with no padding to reproduce by hand, so it is copied out
    // wholesale rather than field by field.
    let header_bytes =
        unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, header_len) };
    blob.extend_from_slice(header_bytes);
    blob.extend_from_slice(exponent);
    blob.extend_from_slice(modulus);

    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                &mut handle,
                &blob,
                0,
            )
        },
        "RSA public key import",
    )?;

    Ok(KeyHandle(handle))
}

fn rsa_oaep_encrypt(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    label: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TpmError> {
    let key = import_rsa_public(modulus, exponent)?;

    // CNG takes the label through a mutable pointer even though it only reads it, so it needs a
    // buffer of its own that outlives both calls below. The label is passed through byte for byte,
    // including the trailing NUL the TPM specification puts in it.
    let mut label = label.to_vec();
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: hash_alg_name(hash_alg)?,
        pbLabel: label.as_mut_ptr(),
        cbLabel: label.len() as u32,
    };
    let padding_ptr = Some(&padding as *const _ as *const c_void);

    let mut required = 0u32;
    check(
        unsafe {
            BCryptEncrypt(
                key.0,
                Some(data),
                padding_ptr,
                None,
                None,
                &mut required,
                BCRYPT_PAD_OAEP,
            )
        },
        "RSA-OAEP encryption sizing",
    )?;

    let mut ciphertext = vec![0u8; required as usize];
    check(
        unsafe {
            BCryptEncrypt(
                key.0,
                Some(data),
                padding_ptr,
                None,
                Some(&mut ciphertext),
                &mut required,
                BCRYPT_PAD_OAEP,
            )
        },
        "RSA-OAEP encryption",
    )?;

    ciphertext.truncate(required as usize);
    Ok(ciphertext)
}

fn rsa_pkcs1v15_verify(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError> {
    let key = import_rsa_public(modulus, exponent)?;

    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: hash_alg_name(hash_alg)?,
    };

    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            Some(&padding as *const _ as *const c_void),
            digest,
            signature,
            BCRYPT_PAD_PKCS1,
        )
    };

    // A signature that does not verify is an answer rather than a failure, and is the one status
    // separated out here. Anything else means the verification could not be performed at all, for
    // instance because the digest length did not match the algorithm named in the padding.
    if status == STATUS_INVALID_SIGNATURE {
        return Ok(false);
    }

    check(status, "RSA PKCS#1 v1.5 verification")?;
    Ok(true)
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;

    use elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, RsaPrivateKey};
    use sha2::Sha256;

    /// The hash algorithms both providers implement.
    ///
    /// SM3 is absent because CNG has none, which the last case below states outright rather than
    /// leaving to be inferred from its absence here.
    const SHARED_HASHES: [TPM_ALG_ID; 4] = [
        TPM_ALG_ID::SHA1,
        TPM_ALG_ID::SHA256,
        TPM_ALG_ID::SHA384,
        TPM_ALG_ID::SHA512,
    ];

    #[test]
    fn hashes_agree_with_the_software_provider() {
        for alg in SHARED_HASHES {
            for data in [b"".as_slice(), b"abc".as_slice(), &[0x5au8; 1000]] {
                let theirs = (SOFTWARE_PROVIDER.hash)(alg, data).unwrap();
                let ours = (CNG_PROVIDER.hash)(alg, data).unwrap();
                assert_eq!(
                    ours,
                    theirs,
                    "hash mismatch for {alg:?} over {} bytes",
                    data.len()
                );
                assert_eq!(ours.len(), Crypto::digestSize(alg));
            }
        }
    }

    #[test]
    fn hmacs_agree_with_the_software_provider() {
        // The empty key and the over-long key are the two cases HMAC defines specially: one is
        // padded out to the block size, the other is hashed down to it. A backend that delegated
        // either differently would disagree here rather than in some later derivation.
        let keys: [&[u8]; 4] = [b"", b"key", &[0xa5; 64], &[0x3c; 200]];

        for alg in SHARED_HASHES {
            for key in keys {
                let theirs = (SOFTWARE_PROVIDER.hmac)(alg, key, b"message").unwrap();
                let ours = (CNG_PROVIDER.hmac)(alg, key, b"message").unwrap();
                assert_eq!(
                    ours,
                    theirs,
                    "HMAC mismatch for {alg:?} under a {} byte key",
                    key.len()
                );
            }
        }
    }

    #[test]
    fn sm3_is_reported_as_unsupported_rather_than_approximated() {
        assert!(matches!(
            (CNG_PROVIDER.hash)(TPM_ALG_ID::SM3_256, b"abc"),
            Err(TpmError::NotSupported(_))
        ));
    }

    #[test]
    fn aes_cfb_agrees_with_the_software_provider() {
        let iv = [0x42u8; AES_BLOCK_LEN];

        for key_len in [16usize, 24, 32] {
            let key = vec![0x11u8; key_len];

            // 34 bytes is the length that matters: a TPM credential is a digest behind a two byte
            // size, so it is never block aligned, and the trailing partial block is where a
            // backend that reached for CNG's own CFB mode would diverge.
            for len in [0usize, 1, 15, 16, 17, 34, 64] {
                let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();

                let theirs = (SOFTWARE_PROVIDER.aes_cfb)(true, &key, &iv, &plaintext).unwrap();
                let ours = (CNG_PROVIDER.aes_cfb)(true, &key, &iv, &plaintext).unwrap();
                assert_eq!(
                    ours,
                    theirs,
                    "AES-{}-CFB encrypt mismatch at {len} bytes",
                    key_len * 8
                );

                let round_trip = (CNG_PROVIDER.aes_cfb)(false, &key, &iv, &ours).unwrap();
                assert_eq!(
                    round_trip, plaintext,
                    "AES-CFB round trip failed at {len} bytes"
                );
            }
        }
    }

    #[test]
    fn aes_cfb_rejects_a_wrong_sized_key_or_iv() {
        let good_key = [0u8; 16];
        let good_iv = [0u8; AES_BLOCK_LEN];

        assert!((CNG_PROVIDER.aes_cfb)(true, &[0u8; 20], &good_iv, b"data").is_err());
        assert!((CNG_PROVIDER.aes_cfb)(true, &good_key, &[0u8; 8], b"data").is_err());
    }

    #[test]
    fn random_fills_the_whole_buffer() {
        let mut buffer = [0u8; 64];
        (CNG_PROVIDER.random)(&mut buffer).unwrap();
        assert!(
            buffer.iter().any(|&b| b != 0),
            "the random buffer came back untouched"
        );

        // A zero length request is legal and must not be turned into an error.
        (CNG_PROVIDER.random)(&mut []).unwrap();
    }

    /// Agrees with CNG against a peer key this test owns, then reproduces the agreed value
    /// independently.
    ///
    /// This is the test that earns its keep. Two providers cannot simply be compared on ECDH,
    /// because each generates its own ephemeral key, so instead the peer's private half is kept
    /// here and used to recompute the same value from the ephemeral point CNG returned. That
    /// covers the byte reversal in `raw_secret`, which is otherwise invisible: a value that is
    /// reversed, or padded to the wrong width, is still the right length and still looks like a
    /// secret.
    #[test]
    fn ecdh_agrees_with_a_peer_holding_the_private_half() {
        let peer_secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let peer_point = peer_secret.public_key().to_encoded_point(false);

        let agreement = (CNG_PROVIDER.ecc.ephemeral_agree)(
            TPM_ECC_CURVE::NIST_P256,
            peer_point.x().unwrap(),
            peer_point.y().unwrap(),
        )
        .unwrap();

        assert_eq!(agreement.z.len(), 32);
        assert_eq!(agreement.ephemeral_x.len(), 32);
        assert_eq!(agreement.ephemeral_y.len(), 32);

        let ephemeral_point = p256::EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(&agreement.ephemeral_x),
            p256::FieldBytes::from_slice(&agreement.ephemeral_y),
            false,
        );
        let ephemeral_public =
            p256::PublicKey::from_sec1_bytes(ephemeral_point.as_bytes()).unwrap();

        let expected = peer_secret.diffie_hellman(&ephemeral_public);
        assert_eq!(
            agreement.z.as_slice(),
            expected.raw_secret_bytes().as_slice(),
            "the agreed value disagrees with the peer, so the export is being mishandled"
        );
    }

    #[test]
    fn ecdh_rejects_a_curve_cng_cannot_agree_over() {
        assert!(matches!(
            (CNG_PROVIDER.ecc.ephemeral_agree)(TPM_ECC_CURVE::SM2_P256, &[1u8; 32], &[2u8; 32]),
            Err(TpmError::NotSupported(_))
        ));
    }

    #[test]
    fn ecdh_rejects_a_point_that_is_not_on_the_curve() {
        // Coordinates picked arbitrarily are overwhelmingly unlikely to satisfy the curve
        // equation, and CNG checks that on import rather than agreeing with nonsense.
        assert!((CNG_PROVIDER.ecc.ephemeral_agree)(
            TPM_ECC_CURVE::NIST_P256,
            &[0x11u8; 32],
            &[0x22u8; 32]
        )
        .is_err());
    }

    #[test]
    fn oaep_ciphertext_decrypts_under_the_matching_private_key() {
        // OAEP is randomized, so the two providers cannot be compared on their output. Decrypting
        // is the check that matters anyway, since it is what the TPM will do with this blob.
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let modulus = private.n().to_bytes_be();
        let exponent = private.e().to_bytes_be();

        let label = b"IDENTITY\0";
        let secret = b"the seed the credential protects";

        let ciphertext =
            (CNG_PROVIDER.rsa.oaep_encrypt)(&modulus, &exponent, TPM_ALG_ID::SHA256, label, secret)
                .unwrap();
        assert_eq!(ciphertext.len(), modulus.len());

        // The `rsa` crate models the label as a string, and takes it without the trailing NUL
        // that CNG and the TPM specification both include in the hashed label.
        let padding = Oaep::new_with_label::<Sha256, _>("IDENTITY\0");
        let recovered = private.decrypt(padding, &ciphertext).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn pkcs1v15_verification_agrees_with_the_software_provider() {
        let key = (SOFTWARE_PROVIDER.rsa.generate_keypair)(2048, &[0x01, 0x00, 0x01]).unwrap();
        let digest = (SOFTWARE_PROVIDER.hash)(TPM_ALG_ID::SHA256, b"signed data").unwrap();
        let signature =
            (SOFTWARE_PROVIDER.rsa.pkcs1v15_sign)(&key, TPM_ALG_ID::SHA256, &digest).unwrap();

        let verified = (CNG_PROVIDER.rsa.pkcs1v15_verify)(
            &key.modulus,
            &key.exponent,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )
        .unwrap();
        assert!(verified, "a good signature was rejected");

        // A bad signature is an answer, not an error, so it must come back as `Ok(false)`.
        let mut corrupted = signature.clone();
        corrupted[0] ^= 0xff;
        let verified = (CNG_PROVIDER.rsa.pkcs1v15_verify)(
            &key.modulus,
            &key.exponent,
            TPM_ALG_ID::SHA256,
            &digest,
            &corrupted,
        )
        .unwrap();
        assert!(!verified, "a corrupted signature was accepted");
    }

    #[test]
    fn the_two_unimplemented_rsa_primitives_say_so() {
        assert!(matches!(
            (CNG_PROVIDER.rsa.generate_keypair)(2048, &[0x01, 0x00, 0x01]),
            Err(TpmError::NotSupported(_))
        ));

        let key = crate::crypto::RsaKeyParts {
            modulus: vec![0xff; 256],
            prime: vec![0xff; 128],
            exponent: vec![0x01, 0x00, 0x01],
        };
        assert!(matches!(
            (CNG_PROVIDER.rsa.pkcs1v15_sign)(&key, TPM_ALG_ID::SHA256, &[0u8; 32]),
            Err(TpmError::NotSupported(_))
        ));
    }

    /// The KDFs sit above the provider, so running one through both backends checks the whole
    /// stack rather than the primitives in isolation.
    #[test]
    fn the_kdfs_produce_the_same_stream_over_either_provider() {
        for alg in SHARED_HASHES {
            for bits in [128usize, 250, 256, 512] {
                let theirs =
                    Crypto::kdfa(&SOFTWARE_PROVIDER, alg, b"key", "ATH", &[], &[], bits).unwrap();
                let ours = Crypto::kdfa(&CNG_PROVIDER, alg, b"key", "ATH", &[], &[], bits).unwrap();
                assert_eq!(ours, theirs, "KDFa mismatch for {alg:?} at {bits} bits");

                let z = [0x77u8; 32];
                let theirs =
                    Crypto::kdfe(&SOFTWARE_PROVIDER, alg, &z, "IDENTITY", &[], &[], bits).unwrap();
                let ours =
                    Crypto::kdfe(&CNG_PROVIDER, alg, &z, "IDENTITY", &[], &[], bits).unwrap();
                assert_eq!(ours, theirs, "KDFe mismatch for {alg:?} at {bits} bits");
            }
        }
    }
}
