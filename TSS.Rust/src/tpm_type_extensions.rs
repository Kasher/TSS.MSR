use crate::crypto::{provider::CryptoProvider, Crypto, RsaKeyParts, RSA_DEFAULT_EXPONENT};
use crate::error::TpmError;
use crate::tpm2_helpers::int_to_tpm;
use crate::tpm_buffer::*;
use crate::tpm_structure::TpmEnum;
use crate::tpm_types::CertifyResponse;
use crate::tpm_types::*;
use zeroize::Zeroize;

/// Activation data returned from create_activation
#[derive(Debug)]
pub struct ActivationData {
    pub credential_blob: TPMS_ID_OBJECT,
    pub secret: Vec<u8>, // Encrypted seed (ENCRYPTED_SECRET)
}

impl TPMS_RSA_PARMS {
    /// The public exponent as big-endian bytes with no leading zeros.
    ///
    /// The TPM encodes the default exponent of 2^16 + 1 as zero, so a stored zero is resolved
    /// here rather than by rewriting the field. That distinction matters: a key's Name is a
    /// digest over its whole public area, so normalising a stored zero to 65537 would change
    /// the Name of every key that uses the default and silently break every policy digest,
    /// `TPM2_ActivateCredential` and handle-to-Name comparison that depends on it. Resolve at
    /// the point of use, never in the structure.
    pub fn exponent_bytes(&self) -> Vec<u8> {
        if self.exponent == 0 {
            return RSA_DEFAULT_EXPONENT.to_vec();
        }

        // The exponent is non-zero, so at least one byte survives.
        self.exponent
            .to_be_bytes()
            .iter()
            .skip_while(|&&byte| byte == 0)
            .copied()
            .collect()
    }
}

impl TPMT_PUBLIC {
    pub fn get_name(&self, crypto: &CryptoProvider) -> Result<Vec<u8>, TpmError> {
        let mut buffer = TpmBuffer::new(None);
        self.toTpm(&mut buffer)?;

        let mut pub_hash = Crypto::hash(crypto, self.nameAlg, buffer.trim())?;
        let hash_alg = int_to_tpm(self.nameAlg.get_value());

        pub_hash.splice(0..0, hash_alg.iter().cloned());

        Ok(pub_hash)
    }

    pub fn get_signing_hash_alg(&self) -> Result<TPM_ALG_ID, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(rsa_params)) = &self.parameters {
            rsa_params
        } else {
            return Err(TpmError::NotSupported(
                "Get signing hash algorithm is only supported for RSA".to_string(),
            ));
        };

        let scheme = if let Some(TPMU_ASYM_SCHEME::rsassa(scheme)) = &rsa_params.scheme {
            scheme
        } else {
            return Err(TpmError::NotSupported(
                "Get signing hash algorithm is only supported for RSA-SSA".to_string(),
            ));
        };

        Ok(scheme.hashAlg)
    }

    pub fn validate_certify(
        &self,
        crypto: &CryptoProvider,
        certified_key: &TPMT_PUBLIC,
        nonce: &[u8],
        certify_response: &CertifyResponse,
    ) -> Result<bool, TpmError> {
        let key_hash_alg = self.get_signing_hash_alg()?;
        let signature_hash_alg = if let Some(TPMU_SIGNATURE::rsassa(signature)) = &certify_response.signature {
            signature.hash
        } else {
            return Crypto::validate_signature(
                crypto,
                self,
                Vec::new(),
                &certify_response.signature,
            );
        };
        if key_hash_alg != signature_hash_alg {
            return Ok(false);
        }

        let attest = &certify_response.certifyInfo;

        if (attest.extraData != nonce) {
            return Ok(false);
        }

        if (attest.magic != TPM_GENERATED::VALUE) {
            return Ok(false);
        }

        if let Some(TPMU_ATTEST::certify(quote_info)) = &attest.attested {
            if (quote_info.name != certified_key.get_name(crypto)?) {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        // And finally, check the signature
        let signed_blob = {
            let mut buffer = TpmBuffer::new(None);
            certify_response.certifyInfo.toTpm(&mut buffer)?;
            buffer.trim().to_vec()
        };

        let signed_blob_hash = Crypto::hash(crypto, signature_hash_alg, &signed_blob)?;

        Crypto::validate_signature(crypto, self, signed_blob_hash, &certify_response.signature)
    }

    /// Implements the TPM2_MakeCredential command functionality:
    /// 1. Establish a seed and the secret that conveys it to the TPM
    /// 2. Derive symmetric key via KDFa
    /// 3. Encrypt credential + create integrity HMAC
    ///
    /// Both RSA and ECC storage keys are accepted. The two differ only in how the seed reaches the
    /// TPM, which [`Self::produce_seed`] handles; everything after that is defined on the seed
    /// alone and so is shared.
    pub fn create_activation(
        &self,
        crypto: &CryptoProvider,
        credential: &[u8],
        activated_name: &[u8],
    ) -> Result<ActivationData, TpmError> {
        // The wrapping scheme lives in the algorithm-specific parameters, but the constraint on it
        // is the same either way, so it is checked once here.
        let sym_def = match &self.parameters {
            Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) => &params.symmetric,
            Some(TPMU_PUBLIC_PARMS::eccDetail(params)) => &params.symmetric,
            _ => {
                return Err(TpmError::NotSupported(
                    "Activation requires an RSA or ECC storage key".to_string(),
                ))
            }
        };

        if sym_def.algorithm != TPM_ALG_ID::AES
            || sym_def.keyBits != 128
            || sym_def.mode != TPM_ALG_ID::CFB
        {
            return Err(TpmError::NotSupported("Unsupported wrapping scheme".to_string()));
        }

        // The seed is the same size as the nameAlg digest, per TPM 2.0 Part 1 "Credential
        // Protection". TSS.NET does the same in TpmKey.CreateActivationCredentials.
        let name_alg_size = Crypto::digest_size_checked(self.nameAlg)?;
        let (mut seed, secret) = self.produce_seed(crypto, name_alg_size)?;

        // Make the credential blob:

        // 1. Create the symmetric key via KDFa
        let mut sym_key = Crypto::kdfa(
            crypto,
            self.nameAlg,
            &seed,
            "STORAGE",
            activated_name,
            &[],
            128, // 128-bit AES key
        )?;

        // 2. Take credential and prepend size
        let mut credential_with_size = Vec::with_capacity(2 + credential.len());
        credential_with_size.extend_from_slice(&(credential.len() as u16).to_be_bytes());
        credential_with_size.extend_from_slice(credential);

        // 3. Encrypt the credential 
        let enc_credential = Crypto::cfb_xcrypt(
            crypto,
            true,
            &sym_key,
            &[0u8; 16], // Zero IV
            &credential_with_size
        )?;

        // 4. Generate the integrity HMAC key
        let mut hmac_key = Crypto::kdfa(
            crypto,
            self.nameAlg,
            &seed,
            "INTEGRITY",
            &[],
            &[],
            name_alg_size * 8,
        )?;

        // 5. Calculate outer HMAC
        let mut to_hmac = Vec::new();
        to_hmac.extend_from_slice(&enc_credential);
        to_hmac.extend_from_slice(activated_name);
        
        let integrity_hmac = Crypto::hmac(
            crypto,
            self.nameAlg,
            &hmac_key,
            &to_hmac
        )?;

        // Cleanup sensitive data
        seed.zeroize();
        hmac_key.zeroize();
        sym_key.zeroize();

        Ok(ActivationData {
            credential_blob: TPMS_ID_OBJECT::new(&integrity_hmac, &enc_credential),
            secret,
        })
    }

    /// Establishes the activation seed and the `secret` that lets this key's TPM recover it.
    ///
    /// This is the whole of the difference between an RSA and an ECC activation. With RSA the seed
    /// is chosen at random and the secret is that seed encrypted to the public key. With ECC no
    /// value is transported at all: both sides derive the seed from an ECDH agreement, and the
    /// secret is the ephemeral public point the TPM needs to repeat that agreement.
    ///
    /// Returns the seed and the secret, in that order.
    fn produce_seed(
        &self,
        crypto: &CryptoProvider,
        name_alg_size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
        match (&self.parameters, &self.unique) {
            (Some(TPMU_PUBLIC_PARMS::rsaDetail(params)), Some(TPMU_PUBLIC_ID::rsa(unique))) => {
                let seed = Crypto::get_random(crypto, name_alg_size)?;

                // Encrypt seed with label "IDENTITY" using OAEP with the key's nameAlg
                let secret = Crypto::rsa_oaep_encrypt(
                    crypto,
                    &unique.buffer,
                    &params.exponent_bytes(),
                    self.nameAlg,
                    b"IDENTITY\0",
                    &seed,
                )?;

                Ok((seed, secret))
            }

            (Some(TPMU_PUBLIC_PARMS::eccDetail(params)), Some(TPMU_PUBLIC_ID::ecc(point))) => {
                let curve = params.curveID;
                let agreement = Crypto::ecc_ephemeral_agree(crypto, curve, &point.x, &point.y)?;

                // KDFe hashes this coordinate, so one the TPM marshalled without its leading zeroes
                // has to be restored to full width or the two sides hash different inputs and
                // derive different seeds.
                let width = Crypto::ecc_coordinate_size(curve)?;
                let party_v_info = Crypto::pad_ecc_coordinate(&point.x, width)?;

                // partyU is the initiator, which is this side, and partyV the key's owner. The TPM
                // makes the same assignment when it repeats the agreement, even though its own
                // role is the opposite one.
                let seed = Crypto::kdfe(
                    crypto,
                    self.nameAlg,
                    &agreement.z,
                    "IDENTITY",
                    &agreement.ephemeral_x,
                    &party_v_info,
                    name_alg_size * 8,
                )?;

                // The secret is the ephemeral point marshalled as a TPMS_ECC_POINT, so each
                // coordinate carries its own size. It is not a bare concatenation.
                let secret = TPMS_ECC_POINT::new(&agreement.ephemeral_x, &agreement.ephemeral_y)
                    .toBytes()?;

                Ok((seed, secret))
            }

            _ => Err(TpmError::NotSupported(format!(
                "Activation is not supported for a public area whose parameters are {:?} and \
                 whose unique field is {:?}",
                self.parameters.as_ref().map(std::mem::discriminant),
                self.unique.as_ref().map(std::mem::discriminant),
            ))),
        }
    }

    // Performs RSA encryption of the given data using the public key
    pub fn encrypt(
        &self,
        crypto: &CryptoProvider,
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        // Verify we have an RSA key with correct parameters
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) = &self.parameters {
            params
        } else {
            return Err(TpmError::NotSupported("Only RSA encryption supported".to_string()));
        };

        // Check symmetric definition
        let sym_def = &rsa_params.symmetric;
        if sym_def.algorithm != TPM_ALG_ID::AES 
            || sym_def.keyBits != 128 
            || sym_def.mode != TPM_ALG_ID::CFB {
            return Err(TpmError::NotSupported("Unsupported wrapping scheme".to_string()));
        }

        // Get RSA public key components
        let rsa_pub_n = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &self.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported("Invalid RSA public key".to_string()));
        };

        // Encrypt the data using OAEP padding with the key's nameAlg
        Crypto::rsa_oaep_encrypt(
            crypto,
            rsa_pub_n,
            &rsa_params.exponent_bytes(),
            self.nameAlg,
            b"IDENTITY\0",
            data,
        )
    }

    /// Encrypt a session salt for use with salted auth sessions.
    /// Uses RSA-OAEP with the nameAlg hash and label "SECRET\0".
    pub fn encrypt_session_salt(
        &self,
        crypto: &CryptoProvider,
        salt: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) = &self.parameters {
            params
        } else {
            return Err(TpmError::NotSupported("Only RSA keys can encrypt session salt".to_string()));
        };

        let rsa_pub_n = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &self.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported("Only RSA keys can encrypt session salt".to_string()));
        };

        Crypto::rsa_oaep_encrypt(
            crypto,
            rsa_pub_n,
            &rsa_params.exponent_bytes(),
            self.nameAlg,
            b"SECRET\0",
            salt,
        )
    }
}

impl TPMS_PCR_SELECTION {
    /// Get a PCR-selection array naming exactly one PCR in one bank
    pub fn get_selection_array(hash_alg: TPM_ALG_ID, pcr: u32) -> Vec<Self> {
        vec![TPMS_PCR_SELECTION::new_from_pcr_u32(hash_alg, pcr)]
    }

    /// Create a TPMS_PCR_SELECTION naming a single-PCR
    pub fn new_from_pcr_u32(hash_alg: TPM_ALG_ID, pcr: u32) -> Self {
        let mut size = 3;

        let pcr_bytes = pcr / 8;
        if ((pcr_bytes / 8) + 1) > size {
            size = pcr_bytes + 1;
        }

        let mut pcr_select = vec![0; size as usize];
        pcr_select[pcr_bytes as usize] = 1 << (pcr % 8);

        TPMS_PCR_SELECTION::new(hash_alg, &pcr_select)
    }

    /// Create a TPMS_PCR_SELECTION for a set of PCRs in a single bank
    pub fn new_from_pcrs_vec(hash_alg: TPM_ALG_ID, pcrs: &[u32]) -> Self {
        let mut pcr_max = *pcrs.iter().max().unwrap_or(&0);

        if (pcr_max < 23) {
            pcr_max = 23;
        }

        let mut pcr_select = vec![0; (pcr_max / 8 + 1) as usize];
        for pcr in pcrs {
            pcr_select[*pcr as usize / 8] |= 1 << (*pcr % 8);
        }

        TPMS_PCR_SELECTION::new(hash_alg, &pcr_select)
    }
}

impl TPM_HANDLE {
    /// Creates a handle for a persistent object
    pub fn persistent(handle_offset: u32) -> Self {
        Self::new(((TPM_HT::PERSISTENT.get_value() as u32) << 24) + handle_offset)
    }

    /// Creates a handle for a PCR
    pub fn pcr(pcr_index: u32) -> Self {
        Self::new(pcr_index)
    }

    /// Creates a handle for an NV slot
    pub fn nv(nv_index: u32) -> Self {
        Self::new(((TPM_HT::NV_INDEX.get_value() as u32) << 24) + nv_index)
    }

    /// Set the authorization value for this TPM_HANDLE.  The default auth-value is NULL
    pub fn set_auth(&mut self, auth_val: &[u8]) {
        self.auth_value = auth_val.to_vec();
    }

    /// Returns this handle's type
    pub fn get_type(&self) -> TPM_HT {
        // The handle type is the top byte of the handle value
        unsafe { std::mem::transmute((self.handle >> 24) as u8) }
    }

    pub fn set_name(&mut self, name: &[u8]) -> Result<(), TpmError> {
        let handle_type = self.get_type();

        if (handle_type == TPM_HT::NV_INDEX
            || handle_type == TPM_HT::TRANSIENT
            || handle_type == TPM_HT::PERSISTENT)
        {
            self.name = name.to_vec();
            return Ok(());
        }

        if (name != self.get_name()?) {
            return Err(TpmError::GenericError(format!("Setting an invalid name of an entity with the name defined by the handle value, handle type: {}", handle_type)));
        }

        Ok(())
    }

    /// Get the TPM name of this handle
    pub fn get_name(&self) -> Result<Vec<u8>, TpmError> {
        let handle_type = self.get_type();

        // Per spec: handles of these types have their handle value as their name
        if handle_type == TPM_HT::PCR
            || handle_type == TPM_HT::HMAC_SESSION
            || handle_type == TPM_HT::POLICY_SESSION
            || handle_type == TPM_HT::PERMANENT
        {
            let mut name = Vec::with_capacity(4);
            name.extend_from_slice(&self.handle.to_be_bytes());
            return Ok(name);
        }

        if handle_type == TPM_HT::NV_INDEX
            || handle_type == TPM_HT::TRANSIENT
            || handle_type == TPM_HT::PERSISTENT
        {
            if (self.name.is_empty()) {
                return Err(TpmError::GenericError(format!(
                    "Name is not set for handle, handle type: {}",
                    handle_type
                )));
            }
            return Ok(self.name.clone());
        }

        Err(TpmError::GenericError(format!(
            "Unknown handle type, handle type: {}",
            handle_type
        )))
    }
}

impl std::fmt::Display for TPM_HANDLE {
    /// Get a string representation of this handle
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:0x{:x}", self.get_type(), self.handle)
    }
}

impl TSS_KEY {
    /// Generate an RSA key pair in software.
    /// Populates publicPart.unique with the modulus and privatePart with the first prime (p).
    pub fn create_key(&mut self, crypto: &CryptoProvider) -> Result<(), TpmError> {
        let (key_bits, exponent) =
            if let Some(TPMU_PUBLIC_PARMS::rsaDetail(ref params)) = self.publicPart.parameters {
                (params.keyBits as usize, params.exponent_bytes())
            } else {
                return Err(TpmError::GenericError("Only RSA key creation is supported".to_string()));
            };

        let key = Crypto::rsa_generate_keypair(crypto, key_bits, &exponent)?;

        // Store modulus (n) in publicPart.unique
        self.publicPart.unique = Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA { buffer: key.modulus }));

        // Store first prime (p) as privatePart
        self.privatePart = key.prime;

        Ok(())
    }

    /// Sign a digest using the software key (RSASSA-PKCS1-v1_5).
    /// `digest` should be the hash of the data to sign.
    /// Returns a TPMT_SIGNATURE with RSASSA scheme.
    pub fn sign(
        &self,
        crypto: &CryptoProvider,
        digest: &[u8],
        hash_alg: TPM_ALG_ID,
    ) -> Result<TPMT_SIGNATURE, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(ref params)) = self.publicPart.parameters {
            params
        } else {
            return Err(TpmError::GenericError("Only RSA signing is supported".to_string()));
        };

        let n_bytes = if let Some(TPMU_PUBLIC_ID::rsa(ref pub_key)) = self.publicPart.unique {
            pub_key.buffer.clone()
        } else {
            return Err(TpmError::GenericError("No public key available".to_string()));
        };

        // Reconstruct RSA private key from modulus + prime p
        let key = RsaKeyParts {
            modulus: n_bytes,
            prime: self.privatePart.clone(),
            exponent: rsa_params.exponent_bytes(),
        };

        let sig_bytes = Crypto::rsa_pkcs1v15_sign(crypto, &key, hash_alg, digest)?;

        Ok(TPMT_SIGNATURE {
            signature: Some(TPMU_SIGNATURE::rsassa(TPMS_SIGNATURE_RSASSA {
                hash: hash_alg,
                sig: sig_bytes,
            })),
        })
    }
}

// The activation round trip is checked against a software endorsement key built with the `rsa`
// crate, so these tests only apply when the software provider is compiled in.
#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use elliptic_curve::ecdh::diffie_hellman;
    use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
    use elliptic_curve::{
        AffinePoint, CurveArithmetic, FieldBytes, FieldBytesSize, PublicKey, SecretKey,
    };
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, RsaPrivateKey};
    use sha1::Sha1;
    use sha2::Sha256;

    /// Build a software stand-in for an endorsement key, along with its public area.
    fn endorsement_key(name_alg: TPM_ALG_ID) -> Result<(RsaPrivateKey, TPMT_PUBLIC), TpmError> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {e}")))?;

        let parameters = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            65537,
        );

        let public_area = TPMT_PUBLIC {
            nameAlg: name_alg,
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(parameters)),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: private_key.n().to_bytes_be(),
            })),
            ..Default::default()
        };

        Ok((private_key, public_area))
    }

    /// A Name is a two byte algorithm identifier followed by a digest. `create_activation`
    /// treats it as opaque input to KDFa and the integrity HMAC, so the contents do not matter
    /// as long as both sides agree on them.
    fn activated_name(name_alg: TPM_ALG_ID) -> Vec<u8> {
        vec![0xab; 2 + Crypto::digestSize(name_alg)]
    }

    /// Play the part of `TPM2_ActivateCredential` once the seed has been recovered.
    ///
    /// Everything here is defined on the seed alone, so it serves an RSA and an ECC activation
    /// alike. Only the step that produces the seed differs between them.
    fn activate_credential(
        seed: &[u8],
        name_alg: TPM_ALG_ID,
        activated_name: &[u8],
        activation: &ActivationData,
    ) -> Result<Vec<u8>, TpmError> {
        // A TPM rejects a seed whose size is not the nameAlg digest size: TPM 2.0 Part 4,
        // CryptSecretDecrypt, returns TPM_RC_VALUE. Modelling that check here is what makes
        // this test able to catch a wrongly sized seed, because the seed itself travels inside
        // the blob and would otherwise round trip at any length.
        let expected_seed_size = Crypto::digestSize(name_alg);
        if seed.len() != expected_seed_size {
            return Err(TpmError::InvalidArraySize(format!(
                "Seed is {} bytes, but {:?} requires {}",
                seed.len(),
                name_alg,
                expected_seed_size
            )));
        }

        let sym_key = Crypto::kdfa(&SOFTWARE_PROVIDER, name_alg, seed, "STORAGE", activated_name, &[], 128)?;
        let hmac_key = Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            name_alg,
            seed,
            "INTEGRITY",
            &[],
            &[],
            expected_seed_size * 8,
        )?;

        let mut to_hmac = activation.credential_blob.encIdentity.clone();
        to_hmac.extend_from_slice(activated_name);
        if Crypto::hmac(&SOFTWARE_PROVIDER, name_alg, &hmac_key, &to_hmac)?
            != activation.credential_blob.integrityHMAC
        {
            return Err(TpmError::GenericError(
                "Integrity HMAC mismatch".to_string(),
            ));
        }

        let plaintext = Crypto::cfb_xcrypt(
            &SOFTWARE_PROVIDER,
            false,
            &sym_key,
            &[0u8; 16],
            &activation.credential_blob.encIdentity,
        )?;

        let Some(size_bytes) = plaintext.get(..2) else {
            return Err(TpmError::InvalidArraySize(
                "Credential is missing its size prefix".to_string(),
            ));
        };
        let size = u16::from_be_bytes([size_bytes[0], size_bytes[1]]) as usize;

        plaintext
            .get(2..2 + size)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                TpmError::InvalidArraySize("Credential size overruns the blob".to_string())
            })
    }

    /// Recover an RSA activation's seed the way a TPM would, by decrypting it.
    fn rsa_recover_seed(
        endorsement_private: &RsaPrivateKey,
        name_alg: TPM_ALG_ID,
        secret: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let padding = match name_alg {
            TPM_ALG_ID::SHA1 => Oaep::new_with_label::<Sha1, _>("IDENTITY\0"),
            TPM_ALG_ID::SHA256 => Oaep::new_with_label::<Sha256, _>("IDENTITY\0"),
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported nameAlg for OAEP: {:?}",
                    name_alg
                )))
            }
        };

        endorsement_private
            .decrypt(padding, secret)
            .map_err(|e| TpmError::GenericError(format!("Seed decryption failed: {e}")))
    }

    /// A software stand-in for an ECC storage key, along with its public area.
    fn ecc_endorsement_key<C>(
        curve: TPM_ECC_CURVE,
        name_alg: TPM_ALG_ID,
    ) -> Result<(SecretKey<C>, TPMT_PUBLIC), TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let private_key = SecretKey::<C>::random(&mut OsRng);
        let public_area = ecc_public_area(&private_key, curve, name_alg)?;

        Ok((private_key, public_area))
    }

    /// The public area a TPM would report for an ECC key it already holds.
    fn ecc_public_area<C>(
        private_key: &SecretKey<C>,
        curve: TPM_ECC_CURVE,
        name_alg: TPM_ALG_ID,
    ) -> Result<TPMT_PUBLIC, TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let point = private_key.public_key().to_encoded_point(false);
        let missing =
            || TpmError::GenericError("The generated point has no coordinates".to_string());

        let parameters = TPMS_ECC_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            curve,
            &Some(TPMU_KDF_SCHEME::null(TPMS_NULL_KDF_SCHEME::default())),
        );

        Ok(TPMT_PUBLIC {
            nameAlg: name_alg,
            parameters: Some(TPMU_PUBLIC_PARMS::eccDetail(parameters)),
            unique: Some(TPMU_PUBLIC_ID::ecc(TPMS_ECC_POINT::new(
                &point.x().ok_or_else(missing)?.to_vec(),
                &point.y().ok_or_else(missing)?.to_vec(),
            ))),
            ..Default::default()
        })
    }

    /// A P-256 endorsement key whose public X coordinate is encoded short.
    ///
    /// A TPM is free to drop the leading zero octets of a coordinate it marshals into a `TPM2B`,
    /// and restoring them is what [`Crypto::pad_ecc_coordinate`] exists for. A point built from a
    /// SEC1 encoding always carries its coordinates at full width, so no generated fixture
    /// exercises the restoration.
    ///
    /// The scalar is fixed rather than searched for. Only one key in 256 has a leading zero octet,
    /// and generating that many keys costs more in an unoptimised test build than the rest of this
    /// suite put together.
    fn ecc_endorsement_key_with_a_short_x(
        name_alg: TPM_ALG_ID,
    ) -> Result<(SecretKey<p256::NistP256>, TPMT_PUBLIC), TpmError> {
        // Public X is 001de71052742cda097122e99b7d6e10e60ed5452c8a6de03f0ca1455b7ba892.
        const SCALAR: [u8; 32] = [
            0xad, 0x56, 0xea, 0xd1, 0xd6, 0x29, 0x0c, 0xf6, 0x9f, 0x18, 0x71, 0x82, 0xd2, 0x70,
            0xd6, 0x2f, 0xd4, 0x09, 0x2b, 0xa1, 0xda, 0x80, 0x5a, 0x64, 0x13, 0xcf, 0xfe, 0x42,
            0x8f, 0xa7, 0x34, 0xbf,
        ];

        let private_key = SecretKey::<p256::NistP256>::from_slice(&SCALAR)
            .map_err(|e| TpmError::GenericError(format!("The fixture scalar is invalid: {e}")))?;
        let mut public_area = ecc_public_area(&private_key, TPM_ECC_CURVE::NIST_P256, name_alg)?;

        let Some(TPMU_PUBLIC_ID::ecc(point)) = &mut public_area.unique else {
            return Err(TpmError::GenericError(
                "The fixture is not an ECC key".to_string(),
            ));
        };

        // Drop the leading zeroes, the way a TPM marshalling a TPM2B is entitled to.
        let leading_zeroes = point
            .x
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(point.x.len());
        point.x.drain(..leading_zeroes);

        Ok((private_key, public_area))
    }

    /// Recover an ECC activation's seed the way a TPM would, by repeating the agreement.
    ///
    /// Nothing is decrypted here, because nothing was transported. The TPM agrees its own private
    /// key with the ephemeral point it was handed and derives the same seed the caller did.
    fn ecc_recover_seed<C>(
        private_key: &SecretKey<C>,
        name_alg: TPM_ALG_ID,
        secret: &[u8],
    ) -> Result<Vec<u8>, TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        // The secret is a marshalled TPMS_ECC_POINT, so each coordinate arrives sized.
        let mut ephemeral_point = TPMS_ECC_POINT::default();
        ephemeral_point.initFromTpm(&mut TpmBuffer::from(secret))?;

        let width = FieldBytes::<C>::default().len();
        let ephemeral_x = Crypto::pad_ecc_coordinate(&ephemeral_point.x, width)?;
        let ephemeral_y = Crypto::pad_ecc_coordinate(&ephemeral_point.y, width)?;

        let encoded = EncodedPoint::<C>::from_affine_coordinates(
            FieldBytes::<C>::from_slice(&ephemeral_x),
            FieldBytes::<C>::from_slice(&ephemeral_y),
            false,
        );
        let ephemeral_public: PublicKey<C> =
            Option::from(PublicKey::<C>::from_encoded_point(&encoded)).ok_or_else(|| {
                TpmError::GenericError("The ephemeral point is not on the curve".to_string())
            })?;

        let z = diffie_hellman(private_key.to_nonzero_scalar(), ephemeral_public.as_affine());

        // The TPM is the responder, yet it still names the originator's point as partyU. Deriving
        // with the roles reversed would produce a different seed in silence, which is why this
        // assignment is written the same way on both sides.
        let own_point = private_key.public_key().to_encoded_point(false);
        let own_x = own_point
            .x()
            .ok_or_else(|| TpmError::GenericError("The key has no X coordinate".to_string()))?
            .to_vec();

        Crypto::kdfe(
            &SOFTWARE_PROVIDER,
            name_alg,
            z.raw_secret_bytes(),
            "IDENTITY",
            &ephemeral_x,
            &own_x,
            Crypto::digestSize(name_alg) * 8,
        )
    }

    #[test]
    fn create_activation_round_trips_through_a_software_activate() -> Result<(), TpmError> {
        for name_alg in [TPM_ALG_ID::SHA1, TPM_ALG_ID::SHA256] {
            let (endorsement_private, endorsement_public) = endorsement_key(name_alg)?;
            let activated_name = activated_name(name_alg);
            let credential = b"credential to activate".to_vec();

            let activation = endorsement_public.create_activation(
                &SOFTWARE_PROVIDER,
                &credential,
                &activated_name,
            )?;
            let seed = rsa_recover_seed(&endorsement_private, name_alg, &activation.secret)?;
            let recovered = activate_credential(&seed, name_alg, &activated_name, &activation)?;

            assert_eq!(recovered, credential, "nameAlg {:?}", name_alg);
        }

        Ok(())
    }

    /// The whole ECC activation, exercised against a stand-in that repeats the agreement.
    ///
    /// A curve is passed both as a `TPM_ECC_CURVE` and as its Rust type, so a mismatch between the
    /// two would show up as a failed round trip rather than passing unnoticed.
    fn ecc_round_trip<C>(curve: TPM_ECC_CURVE, name_alg: TPM_ALG_ID) -> Result<(), TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let (private_key, public_area) = ecc_endorsement_key::<C>(curve, name_alg)?;
        let activated_name = activated_name(name_alg);
        let credential = b"credential to activate".to_vec();

        let activation =
            public_area.create_activation(&SOFTWARE_PROVIDER, &credential, &activated_name)?;
        let seed = ecc_recover_seed::<C>(&private_key, name_alg, &activation.secret)?;
        let recovered = activate_credential(&seed, name_alg, &activated_name, &activation)?;

        assert_eq!(recovered, credential, "curve {:?}, nameAlg {:?}", curve, name_alg);
        Ok(())
    }

    #[test]
    fn ecc_activation_round_trips_on_every_supported_curve() -> Result<(), TpmError> {
        for name_alg in [TPM_ALG_ID::SHA1, TPM_ALG_ID::SHA256, TPM_ALG_ID::SHA384] {
            ecc_round_trip::<p256::NistP256>(TPM_ECC_CURVE::NIST_P256, name_alg)?;
            ecc_round_trip::<p384::NistP384>(TPM_ECC_CURVE::NIST_P384, name_alg)?;
            ecc_round_trip::<p521::NistP521>(TPM_ECC_CURVE::NIST_P521, name_alg)?;
        }

        Ok(())
    }

    #[test]
    fn ecc_activation_restores_a_coordinate_the_tpm_marshalled_short() -> Result<(), TpmError> {
        let name_alg = TPM_ALG_ID::SHA256;
        let (private_key, public_area) = ecc_endorsement_key_with_a_short_x(name_alg)?;

        let Some(TPMU_PUBLIC_ID::ecc(point)) = &public_area.unique else {
            return Err(TpmError::GenericError(
                "The fixture is not an ECC key".to_string(),
            ));
        };
        assert!(
            point.x.len() < 32,
            "the fixture is only meaningful if its X coordinate is short, got {} octets",
            point.x.len()
        );

        let activated_name = activated_name(name_alg);
        let credential = b"credential to activate".to_vec();

        let activation =
            public_area.create_activation(&SOFTWARE_PROVIDER, &credential, &activated_name)?;
        let seed = ecc_recover_seed::<p256::NistP256>(&private_key, name_alg, &activation.secret)?;
        let recovered = activate_credential(&seed, name_alg, &activated_name, &activation)?;

        // KDFe hashes this coordinate, and the key's owner hashes it at its curve's full width.
        // Hashing it as it arrived would derive a different seed on each side, and the credential
        // would not come back.
        assert_eq!(recovered, credential);
        Ok(())
    }

    #[test]
    fn ecc_activation_rejects_a_coordinate_wider_than_its_curve() -> Result<(), TpmError> {
        let (_, mut public_area) =
            ecc_endorsement_key::<p256::NistP256>(TPM_ECC_CURVE::NIST_P256, TPM_ALG_ID::SHA256)?;

        if let Some(TPMU_PUBLIC_ID::ecc(point)) = &mut public_area.unique {
            point.x.insert(0, 0);
        }

        // A 33 octet X does not belong to P-256. Quietly trimming it to fit would agree with a
        // point the key's owner never held, and the failure would only appear at the TPM.
        assert!(
            public_area
                .create_activation(
                    &SOFTWARE_PROVIDER,
                    b"credential",
                    &activated_name(TPM_ALG_ID::SHA256)
                )
                .is_err(),
            "an oversized coordinate should be rejected"
        );
        Ok(())
    }

    #[test]
    fn ecc_activation_secret_is_a_marshalled_point() -> Result<(), TpmError> {
        // Two sized coordinates, not a bare concatenation. A TPM parses this field as a
        // TPMS_ECC_POINT, so a concatenation would be read as a single overlong X.
        let (_, public_area) =
            ecc_endorsement_key::<p256::NistP256>(TPM_ECC_CURVE::NIST_P256, TPM_ALG_ID::SHA256)?;
        let activation = public_area.create_activation(
            &SOFTWARE_PROVIDER,
            b"credential",
            &activated_name(TPM_ALG_ID::SHA256),
        )?;

        assert_eq!(
            activation.secret.len(),
            2 + 32 + 2 + 32,
            "P-256 point should be two sized 32 byte coordinates"
        );

        let mut point = TPMS_ECC_POINT::default();
        point.initFromTpm(&mut TpmBuffer::from(&activation.secret))?;
        assert_eq!(point.x.len(), 32);
        assert_eq!(point.y.len(), 32);
        Ok(())
    }

    #[test]
    fn ecc_activation_rejects_a_curve_without_an_implementation() -> Result<(), TpmError> {
        // The registry defines these, so their coordinate width is known, but no agreement is
        // available for them. Silently substituting a NIST curve would derive an unusable seed.
        for curve in [TPM_ECC_CURVE::BN_P256, TPM_ECC_CURVE::SM2_P256] {
            let (_, mut public_area) = ecc_endorsement_key::<p256::NistP256>(
                TPM_ECC_CURVE::NIST_P256,
                TPM_ALG_ID::SHA256,
            )?;

            if let Some(TPMU_PUBLIC_PARMS::eccDetail(params)) = &mut public_area.parameters {
                params.curveID = curve;
            }

            assert!(
                public_area
                    .create_activation(
                        &SOFTWARE_PROVIDER,
                        b"credential",
                        &activated_name(TPM_ALG_ID::SHA256)
                    )
                    .is_err(),
                "curve {:?} should be rejected",
                curve
            );
        }

        Ok(())
    }

    #[test]
    fn ecc_coordinate_size_agrees_with_the_curve_implementations() -> Result<(), TpmError> {
        // The provider pads with the width its curve crate reports, while create_activation pads
        // the peer's coordinate with the width from the registry table. The two feed the same
        // KDFe, so a disagreement between them would derive mismatched seeds.
        assert_eq!(
            Crypto::ecc_coordinate_size(TPM_ECC_CURVE::NIST_P256)?,
            FieldBytes::<p256::NistP256>::default().len()
        );
        assert_eq!(
            Crypto::ecc_coordinate_size(TPM_ECC_CURVE::NIST_P384)?,
            FieldBytes::<p384::NistP384>::default().len()
        );
        assert_eq!(
            Crypto::ecc_coordinate_size(TPM_ECC_CURVE::NIST_P521)?,
            FieldBytes::<p521::NistP521>::default().len()
        );
        Ok(())
    }

    #[test]
    fn exponent_bytes_resolves_the_specification_default() {
        // The TPM encodes 2^16 + 1 as zero on the wire.
        let mut parms = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            0,
        );
        assert_eq!(parms.exponent_bytes(), vec![0x01, 0x00, 0x01]);

        // An explicit 65537 encodes to the same bytes as the default.
        parms.exponent = 65537;
        assert_eq!(parms.exponent_bytes(), vec![0x01, 0x00, 0x01]);

        // A non default exponent is returned big-endian with leading zeros stripped.
        parms.exponent = 3;
        assert_eq!(parms.exponent_bytes(), vec![0x03]);

        parms.exponent = u32::MAX;
        assert_eq!(parms.exponent_bytes(), vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn create_activation_rejects_a_non_storage_wrapping_scheme() -> Result<(), TpmError> {
        let (_, mut endorsement_public) = endorsement_key(TPM_ALG_ID::SHA256)?;

        let parameters = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 256, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            65537,
        );
        endorsement_public.parameters = Some(TPMU_PUBLIC_PARMS::rsaDetail(parameters));

        assert!(endorsement_public
            .create_activation(
                &SOFTWARE_PROVIDER,
                b"credential",
                &activated_name(TPM_ALG_ID::SHA256)
            )
            .is_err());

        Ok(())
    }

    #[test]
    fn create_activation_rejects_a_name_alg_that_is_not_a_hash() -> Result<(), TpmError> {
        // A behaviour lock, not a regression test: OAEP already rejects a non-hash nameAlg a few
        // lines further on, so this held before the seed sizing was made checked. It pins the
        // property itself so that reordering or relaxing either check cannot let a zero length
        // seed through unnoticed.
        let (_, mut endorsement_public) = endorsement_key(TPM_ALG_ID::SHA256)?;
        endorsement_public.nameAlg = TPM_ALG_ID::NULL;

        assert!(endorsement_public
            .create_activation(
                &SOFTWARE_PROVIDER,
                b"credential",
                &activated_name(TPM_ALG_ID::SHA256)
            )
            .is_err());

        Ok(())
    }
}
