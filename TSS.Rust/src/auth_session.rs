use crate::crypto::Crypto;
use crate::error::TpmError;
use crate::{tpm_structure::TpmEnum, tpm_types::*};

/// Authentication session for TPM commands
#[derive(Debug, Default, Clone)]
pub struct Session {
    pub sess_in: TPMS_AUTH_COMMAND,
    pub sess_out: TPMS_AUTH_RESPONSE,

    // Additional session properties
    pub hash_alg: TPM_ALG_ID,
    pub session_type: TPM_SE,
    pub needs_hmac: bool,
    pub needs_password: bool,

    /// Derived session key (from KDFa with "ATH" label)
    pub session_key: Vec<u8>,

    /// Symmetric algorithm for parameter encryption
    pub symmetric: TPMT_SYM_DEF,

    /// Handle of the entity this session is bound to (NULL if unbound)
    pub bind_handle: u32,
}

impl Session {
    pub fn new(
        session_handle: TPM_HANDLE,
        nonce_tpm: &[u8],
        session_attributes: TPMA_SESSION,
        nonce_caller: &[u8],
    ) -> Self {
        Session {
            sess_in: TPMS_AUTH_COMMAND::new(
                &session_handle,
                &nonce_caller.to_vec(),
                session_attributes,
                &Vec::new(),
            ),
            sess_out: TPMS_AUTH_RESPONSE::new(
                &nonce_tpm.to_vec(), 
                session_attributes,
                &Vec::new(),
            ),
            hash_alg: TPM_ALG_ID::SHA256,
            session_type: TPM_SE::HMAC,
            needs_hmac: true,
            needs_password: false,
            session_key: Vec::new(),
            symmetric: TPMT_SYM_DEF::default(),
            bind_handle: TPM_RH::NULL.get_value(),
        }
    }

    /// Create a password authorization session (PWAP)
    pub fn pw(auth_value: Option<Vec<u8>>) -> Self {
        let mut s = Session::default();
        s.sess_in.sessionHandle = TPM_HANDLE::new(TPM_RH::PW.get_value());
        s.sess_in.nonce = Vec::new();
        s.sess_in.sessionAttributes = TPMA_SESSION::continueSession;
        let auth_value = auth_value.unwrap_or_default();
        s.sess_in.hmac = auth_value;
        s.sess_out.sessionAttributes = TPMA_SESSION::continueSession;
        s.session_type = TPM_SE::HMAC;
        s.needs_hmac = false;
        s.needs_password = true;
        s.bind_handle = TPM_RH::NULL.get_value();

        s
    }

    /// Create a fully initialized HMAC or policy session from a TPM StartAuthSession response.
    pub fn from_tpm_response(
        session_handle: TPM_HANDLE,
        session_type: TPM_SE,
        hash_alg: TPM_ALG_ID,
        nonce_caller: Vec<u8>,
        nonce_tpm: Vec<u8>,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
        salt: &[u8],
        bind_object: &TPM_HANDLE,
    ) -> Result<Self, TpmError> {
        let mut sess = Session {
            sess_in: TPMS_AUTH_COMMAND::new(
                &session_handle,
                &nonce_caller,
                attributes,
                &Vec::new(),
            ),
            sess_out: TPMS_AUTH_RESPONSE::new(
                &nonce_tpm,
                attributes,
                &Vec::new(),
            ),
            hash_alg,
            session_type,
            needs_hmac: session_type == TPM_SE::HMAC,
            needs_password: false,
            session_key: Vec::new(),
            symmetric,
            bind_handle: bind_object.handle,
        };

        sess.calc_session_key(salt, bind_object)?;
        Ok(sess)
    }

    /// Derive the session key using KDFa with label "ATH".
    /// SessionKey = KDFa(hashAlg, bindAuth || salt, "ATH", nonceTPM, nonceCaller, hashBits)
    fn calc_session_key(&mut self, salt: &[u8], bind_object: &TPM_HANDLE) -> Result<(), TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());
        let has_salt = !salt.is_empty();
        let is_bound = bind_object.handle != null_handle.handle;

        if !has_salt && !is_bound {
            // No key derivation needed for unbound, unsalted sessions
            return Ok(());
        }

        // hmacKey = bindAuth || salt
        let mut hmac_key = Vec::new();
        if is_bound {
            let bind_auth = trim_trailing_zeros(&bind_object.auth_value);
            hmac_key.extend_from_slice(&bind_auth);
        }
        hmac_key.extend_from_slice(salt);

        let hash_bits = Crypto::digestSize(self.hash_alg) * 8;
        self.session_key = Crypto::kdfa(
            self.hash_alg,
            &hmac_key,
            "ATH",
            &self.sess_out.nonce,  // nonceTPM
            &self.sess_in.nonce,   // nonceCaller
            hash_bits,
        )?;

        Ok(())
    }

    /// Check if this is a password authorization session
    pub fn is_pwap(&self) -> bool {
        self.sess_in.sessionHandle.handle == TPM_RH::PW.get_value()
    }

    /// Set authorization value for HMAC calculation
    pub fn set_auth_value(&mut self, auth_value: Vec<u8>) {
        if self.is_pwap() {
            self.sess_in.hmac = auth_value;
        }
    }

    /// Get the hash algorithm used by this session
    pub fn get_hash_alg(&self) -> TPM_ALG_ID {
        self.hash_alg
    }

    /// Generate an HMAC for authorization.
    /// hmacKey = sessionKey || authValue
    /// hmac = HMAC(hashAlg, hmacKey, parmHash || nonceNewer || nonceOlder || nonceDec || nonceEnc || sessionAttrs)
    pub fn get_auth_hmac(
        &self,
        cp_hash: Vec<u8>,
        is_command: bool,
        nonce_tpm_dec: &[u8],
        nonce_tpm_enc: &[u8],
        associated_handle: Option<&TPM_HANDLE>,
    ) -> Result<Vec<u8>, TpmError> {
        // PWAP: return the auth value directly
        if self.is_pwap() {
            return Ok(self.sess_in.hmac.clone());
        }

        // PolicyPassword: return auth value directly
        if self.needs_password {
            return Ok(self.sess_in.hmac.clone());
        }

        // Determine nonce order based on direction
        let (nonce_newer, nonce_older) = if is_command {
            (&self.sess_in.nonce, &self.sess_out.nonce)
        } else {
            (&self.sess_out.nonce, &self.sess_in.nonce)
        };

        // Session attributes: use command attrs for commands, response attrs for responses
        let session_attrs = if is_command {
            vec![self.sess_in.sessionAttributes.get_value()]
        } else {
            vec![self.sess_out.sessionAttributes.get_value()]
        };

        // Get auth value from the associated handle
        let mut auth = Vec::new();
        if let Some(handle) = associated_handle {
            // For bound sessions: if the handle IS the bound entity, skip auth
            // (it's already incorporated in the session key via KDFa).
            let is_bound = self.bind_handle != TPM_RH::NULL.get_value()
                && self.bind_handle != 0
                && handle.handle == self.bind_handle;

            if is_bound {
                // Bound to same entity: auth already in session key, don't add again
            } else if self.session_type != TPM_SE::POLICY || self.needs_hmac {
                auth = trim_trailing_zeros(&handle.auth_value);
            }
        }

        // hmacKey = sessionKey || auth
        let mut hmac_key = Vec::new();
        hmac_key.extend_from_slice(&self.session_key);
        hmac_key.extend_from_slice(&auth);

        // Buffer to HMAC: parmHash || nonceNewer || nonceOlder || nonceDec || nonceEnc || sessionAttrs
        let mut buf_to_hmac = Vec::new();
        buf_to_hmac.extend_from_slice(&cp_hash);
        buf_to_hmac.extend_from_slice(nonce_newer);
        buf_to_hmac.extend_from_slice(nonce_older);
        buf_to_hmac.extend_from_slice(nonce_tpm_dec);
        buf_to_hmac.extend_from_slice(nonce_tpm_enc);
        buf_to_hmac.extend_from_slice(&session_attrs);

        Crypto::hmac(self.hash_alg, &hmac_key, &buf_to_hmac)
    }

    /// Process parameter encryption/decryption using AES-CFB.
    /// Key derivation: KDFa(hashAlg, sessionKey, "CFB", nonceNewer, nonceOlder, 256)
    /// First keyBits/8 bytes = AES key, next 16 bytes = IV
    pub fn param_xcrypt(&self, data: &[u8], is_command: bool) -> Result<Vec<u8>, TpmError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Only AES-128/256 CFB is supported
        if self.symmetric.algorithm != TPM_ALG_ID::AES || self.symmetric.mode != TPM_ALG_ID::CFB {
            return Err(TpmError::GenericError(
                "Only AES in CFB mode is supported for parameter encryption".to_string(),
            ));
        }

        let key_bits = self.symmetric.keyBits as usize;
        if key_bits != 128 && key_bits != 256 {
            return Err(TpmError::GenericError(
                format!("Unsupported AES key size: {} bits", key_bits),
            ));
        }

        let key_size = key_bits / 8;

        // Determine nonce order: for requests, nonceNewer=nonceCaller, nonceOlder=nonceTPM
        // For responses, nonceNewer=nonceTPM, nonceOlder=nonceCaller
        let (nonce_newer, nonce_older) = if is_command {
            (&self.sess_in.nonce, &self.sess_out.nonce)
        } else {
            (&self.sess_out.nonce, &self.sess_in.nonce)
        };

        // Derive key material: KDFa(hashAlg, sessionKey, "CFB", nonceNewer, nonceOlder, 256)
        // Produces key_size + 16 bytes (key + IV)
        let num_bits = (key_size + 16) * 8;
        let key_info = Crypto::kdfa(
            self.hash_alg,
            &self.session_key,
            "CFB",
            nonce_newer,
            nonce_older,
            num_bits,
        )?;

        let aes_key = &key_info[..key_size];
        let iv = &key_info[key_size..key_size + 16];

        // For requests: encrypt (TPM will decrypt)
        // For responses: decrypt (TPM encrypted it)
        Crypto::cfb_xcrypt(is_command, aes_key, iv, data)
    }
}

/// Trim trailing zero bytes from a byte vector
fn trim_trailing_zeros(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    while result.last() == Some(&0) {
        result.pop();
    }
    result
}
