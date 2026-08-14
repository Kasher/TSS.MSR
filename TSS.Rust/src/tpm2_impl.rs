/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

use crate::auth_session::Session;
use crate::crypto::{provider::CryptoProvider, Crypto};
use crate::device::TpmDevice;
use crate::error::TpmError;
use crate::tpm_buffer::{TpmBuffer, TpmMarshaller};
use crate::tpm_structure::{CmdStructure, ReqStructure, RespStructure, TpmEnum};
use crate::tpm_type_extensions::TrustedPublic;
use crate::tpm_types::{
    TPMA_SESSION, TPMS_AUTH_COMMAND, TPMS_AUTH_RESPONSE, TPMT_HA, TPMT_SYM_DEF, TPM_ALG_ID, TPM_CC,
    TPM_HANDLE, TPM_HT, TPM_RC, TPM_RH, TPM_SE, TPM_ST,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// A TPM error with associated command and context information
#[derive(Debug, Clone)]
pub struct TpmCommandError {
    /// Response code returned by the TPM
    pub response_code: TPM_RC,
    /// Command code that triggered the error
    pub command_code: TPM_CC,
    /// Description of the error
    pub message: String,
}

impl std::fmt::Display for TpmCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TPM command {:?} failed with response code {:?}: {}",
            self.command_code, self.response_code, self.message
        )
    }
}

impl std::error::Error for TpmCommandError {}

impl From<TpmCommandError> for TpmError {
    fn from(err: TpmCommandError) -> Self {
        TpmError::GenericError(err.to_string())
    }
}

/// Base implementation for TPM operations
pub struct Tpm2 {
    /// The TPM device used for communication
    device: Box<dyn TpmDevice>,

    /// The crypto backend used for the host-side work a TPM session requires: deriving session
    /// keys, computing command parameter hashes, and encrypting command parameters.
    ///
    /// This is held rather than passed per call because the generated command methods dispatch
    /// through `&mut self` and have no parameter to carry it.
    crypto: CryptoProvider,

    /// Response code returned by the last executed command
    last_response_code: TPM_RC,

    /// Error object (may be None) generated during the last TPM command execution
    last_error: Option<TpmCommandError>,

    /// TPM sessions associated with the next command
    sessions: Option<Vec<Session>>,

    /// Controls whether exceptions are enabled
    exceptions_enabled: bool,

    /// Suppresses exceptions in response to the next command failure, when exceptions are enabled
    errors_allowed: bool,

    /// Command code for the current operation (for error reporting)
    current_cmd_code: Option<TPM_CC>,

    /// Session tag for the current operation
    current_session_tag: Option<TPM_ST>,

    /// Handle for pending TPM commands
    pending_command: Option<TPM_CC>,

    /// Input handles for current command
    in_handles: Vec<TPM_HANDLE>,

    /// Auth value for objects
    object_in_auth: Vec<u8>,

    /// Name for objects
    object_in_name: Vec<u8>,

    /// Admin authorization handles with auth values
    admin_platform: TPM_HANDLE,
    admin_owner: TPM_HANDLE,
    admin_endorsement: TPM_HANDLE,
    admin_lockout: TPM_HANDLE,

    /// CpHash for parameter encryption
    cp_hash: Option<TPMT_HA>,

    /// Command audit hash
    command_audit_hash: TPMT_HA,

    /// Audit command flag
    audit_command: bool,

    /// Audit CpHash
    audit_cp_hash: TPMT_HA,

    /// Encryption session
    enc_session: Option<Session>,

    /// Decryption session
    dec_session: Option<Session>,

    /// Nonces for TPM parameter encryption/decryption
    nonce_tpm_dec: Vec<u8>,
    nonce_tpm_enc: Vec<u8>,

    /// Command buffer for last command
    last_command_buf: Vec<u8>,

    /// Last command's serialized parameters (before handles)
    last_cmd_params: Vec<u8>,

    /// Sessions updated after the last command (preserved for continueSession)
    completed_sessions: Option<Vec<Session>>,
}

impl Tpm2 {
    /// Creates a new Tpm2 that performs its host-side crypto with `crypto`.
    pub fn new(device: Box<dyn TpmDevice>, crypto: CryptoProvider) -> Self {
        Tpm2 {
            device,
            crypto,
            last_response_code: TPM_RC::SUCCESS,
            last_error: None,
            sessions: None,
            exceptions_enabled: false,
            errors_allowed: true,
            current_cmd_code: None,
            current_session_tag: None,
            pending_command: None,
            in_handles: Vec::new(),
            object_in_auth: Vec::new(),
            object_in_name: Vec::new(),
            admin_platform: TPM_HANDLE::new(0),
            admin_owner: TPM_HANDLE::new(0),
            admin_endorsement: TPM_HANDLE::new(0),
            admin_lockout: TPM_HANDLE::new(0),
            cp_hash: None,
            command_audit_hash: TPMT_HA::default(),
            audit_command: false,
            audit_cp_hash: TPMT_HA::default(),
            enc_session: None,
            dec_session: None,
            nonce_tpm_dec: Vec::new(),
            nonce_tpm_enc: Vec::new(),
            last_command_buf: Vec::new(),
            last_cmd_params: Vec::new(),
            completed_sessions: None,
        }
    }

    /// Creates a new Tpm2 that performs its host-side crypto with the built-in software backend.
    #[cfg(feature = "software-crypto")]
    pub fn with_software_crypto(device: Box<dyn TpmDevice>) -> Self {
        Self::new(device, crate::crypto::software_provider::SOFTWARE_PROVIDER)
    }

    /// The crypto backend this instance was built with.
    ///
    /// Callers that need to compute a policy digest or a key name alongside a live TPM can pass
    /// this to the corresponding `Crypto` entry point, so both agree on one backend.
    pub fn crypto(&self) -> &CryptoProvider {
        &self.crypto
    }

    /// Checks whether the response code is generated by the TSS.Rust implementation
    fn is_comm_medium_error(code: TPM_RC) -> bool {
        // Check if error is in the TSS communication layer rather than TPM itself
        (code.get_value()) & 0xFFFF0000 == 0x80280000
    }

    /// Cleans the raw response code from the TPM
    fn response_code_from_tpm_error(raw_response: TPM_RC) -> TPM_RC {
        if Self::is_comm_medium_error(raw_response) {
            return raw_response;
        }

        let raw_response_u32 = raw_response.get_value();
        let is_fmt = (raw_response_u32 & TPM_RC::RC_FMT1.get_value()) != 0;

        let mask: u32 = if is_fmt { 0xBF } else { 0x97F };

        TPM_RC(raw_response_u32 & mask)
    }

    /// Send a TPM command to the underlying TPM device.
    pub fn dispatch<R: ReqStructure, S: RespStructure>(
        &mut self,
        cmd_code: TPM_CC,
        req: R,
        resp: &mut S,
    ) -> Result<(), TpmError> {
        loop {
            let process_phase_two = match self.dispatch_command(cmd_code, &req) {
                Ok(v) => v,
                Err(e) => {
                    self.current_cmd_code = None;
                    return Err(e);
                }
            };
            match self.process_response(cmd_code, resp) {
                Ok(done) => {
                    if !process_phase_two || done {
                        break;
                    }
                }
                Err(e) => {
                    self.current_cmd_code = None;
                    return Err(e);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }

        Ok(())
    }

    /// Internal method to dispatch a command to the TPM
    pub fn dispatch_command<R: ReqStructure>(
        &mut self,
        cmd_code: TPM_CC,
        req: &R,
    ) -> Result<(bool), TpmError> {
        if self.current_cmd_code.is_some() {
            return Err(TpmError::GenericError(
                "Pending async command must be completed before issuing the next command."
                    .to_string(),
            ));
        }

        if self.audit_command && self.command_audit_hash.hashAlg == TPM_ALG_ID::NULL {
            return Err(TpmError::GenericError(
                "Command audit is not enabled".to_string(),
            ));
        }

        self.current_cmd_code = Some(cmd_code);

        // Determine session tag based on whether we need authorization
        let num_auth_handles = req.num_auth_handles();
        let has_sessions = num_auth_handles > 0 || self.sessions.is_some();
        self.current_session_tag = if has_sessions {
            Some(TPM_ST::SESSIONS)
        } else {
            Some(TPM_ST::NO_SESSIONS)
        };

        let mut cmd_buf = TpmBuffer::new(None);

        // Create command buffer header
        cmd_buf.writeShort(self.current_session_tag.unwrap().get_value());
        cmd_buf.writeInt(0); // to be filled in later
        cmd_buf.writeInt(cmd_code.get_value());

        // Marshal handles
        self.in_handles = req.get_handles();
        // Set auth values for well-known admin handles (OWNER, LOCKOUT, ENDORSEMENT, PLATFORM)
        for h in self.in_handles.iter_mut() {
            Self::set_rh_auth_value_static(
                h,
                &self.admin_owner,
                &self.admin_endorsement,
                &self.admin_platform,
                &self.admin_lockout,
            );
        }
        for handle in self.in_handles.iter() {
            handle.toTpm(&mut cmd_buf)?;
        }

        // Marshal command parameters to a separate buffer
        let mut param_buf = TpmBuffer::new(None);
        req.toTpm(&mut param_buf)?;
        param_buf.trim();
        self.last_cmd_params = param_buf.buffer().clone();

        // Process authorization sessions if present
        let mut cp_hash_data = Vec::new();

        if has_sessions {
            // We do not know the size of the authorization area yet.
            // Remember the place to marshal it, ...
            let auth_size_pos = cmd_buf.current_pos();
            // ... and marshal a placeholder 0 value for now.
            cmd_buf.writeInt(0);

            // If not all required sessions were provided explicitly, create the necessary
            // number of password sessions with auth values from the corresponding TPM_HANDLE objects.
            if let Some(ref mut sessions) = self.sessions {
                // Ensure we have enough sessions
                if sessions.len() < num_auth_handles as usize {
                    for _ in sessions.len()..(num_auth_handles as usize) {
                        sessions.push(Session::pw(None));
                    }
                }

                // Roll nonces
                self.roll_nonces()?;

                // Prepare parameter encryption sessions
                self.prepare_param_encryption_sessions();

                // Do parameter encryption if needed
                self.do_param_encryption(req, &mut param_buf, 0, true)?;

                // Process authorization sessions and get cpHash data
                cp_hash_data = self.process_auth_sessions(
                    &mut cmd_buf,
                    cmd_code,
                    num_auth_handles,
                    param_buf.buffer(),
                )?;
            } else {
                // Create all password sessions with auth from the corresponding handles
                let mut new_sessions = Vec::with_capacity(num_auth_handles as usize);
                for i in 0..num_auth_handles as usize {
                    let auth = if i < self.in_handles.len() {
                        Some(self.in_handles[i].auth_value.clone())
                    } else {
                        None
                    };
                    new_sessions.push(Session::pw(auth));
                }

                // Marshal sessions to command buffer
                for sess in new_sessions.iter() {
                    sess.sess_in.toTpm(&mut cmd_buf)?;
                }

                self.sessions = Some(new_sessions);
            }

            // Update the auth area size
            cmd_buf.write_num_at_pos(
                (cmd_buf.current_pos() - auth_size_pos - 4) as u64,
                auth_size_pos,
                4,
            );
        }

        // Write marshaled command params to the command buffer
        cmd_buf.writeByteBuf(param_buf.buffer());

        // Fill in command buffer size in the command header
        cmd_buf.write_num_at_pos(cmd_buf.current_pos() as u64, 2, 4);
        cmd_buf.trim();

        // Handle CpHash and Audit processing
        if self.cp_hash.is_some() || self.audit_command {
            if cp_hash_data.is_empty() {
                cp_hash_data = self.get_cp_hash_data(cmd_code, param_buf.buffer())?;
            }

            if let Some(ref mut cp_hash) = self.cp_hash {
                cp_hash.digest = Crypto::hash(&self.crypto, cp_hash.hashAlg, &cp_hash_data)?;
                self.clear_invocation_state();
                self.sessions = None;
                self.cp_hash = None;
                return Ok(false);
            }

            if self.audit_command {
                self.audit_cp_hash.digest =
                    Crypto::hash(&self.crypto, self.command_audit_hash.hashAlg, &cp_hash_data)?;
            }
        }

        // Dispatch command to the device
        self.last_command_buf = cmd_buf.trim().to_vec();
        self.device.dispatch_command(&self.last_command_buf)?;

        // Update request handles based on command
        self.update_request_handles(cmd_code)?;

        // Set pending command
        self.pending_command = Some(cmd_code);

        Ok(true)
    }

    /// Process the TPM response and update the response structure
    pub fn process_response<T: RespStructure>(
        &mut self,
        cmd_code: TPM_CC,
        resp_struct: &mut T,
    ) -> Result<(bool), TpmError> {
        if self.pending_command.is_none() {
            return Err(TpmError::GenericError(
                "Async command completion with no outstanding command".to_string(),
            ));
        }

        if self.pending_command.unwrap() != cmd_code {
            return Err(TpmError::GenericError(
                "Async command completion does not match command being processed".to_string(),
            ));
        }

        if self.audit_command && self.command_audit_hash.hashAlg == TPM_ALG_ID::NULL {
            return Err(TpmError::GenericError(
                "Command audit is not enabled".to_string(),
            ));
        }

        self.pending_command = None;

        // Get response from the TPM device
        let raw_resp_buf = self.device.get_response()?;

        if raw_resp_buf.len() < 10 {
            return Err(TpmError::GenericError(format!(
                "Too short TPM response of {} B received",
                raw_resp_buf.len()
            )));
        }

        let mut resp_buf = TpmBuffer::from(&raw_resp_buf);

        // Read the response header
        let resp_tag = TPM_ST::try_from(resp_buf.readShort())?;
        let resp_size = resp_buf.readInt();
        let resp_code = TPM_RC::try_from(resp_buf.readInt())?;

        let act_resp_size = resp_buf.size();
        if resp_size as usize != act_resp_size {
            return Err(TpmError::GenericError(format!(
                "Inconsistent TPM response buffer: {} B reported, {} B received",
                resp_size, act_resp_size
            )));
        }

        if resp_code == TPM_RC::RETRY {
            return Ok(false);
        }

        // Clean and store the response code
        self.last_response_code = Self::response_code_from_tpm_error(resp_code);

        // Figure out our reaction to the received response. This logic depends on:
        //   errors_allowed - no exception, regardless of success or failure

        // Store a copy of audit command flag before clearing invocation state
        let audit_command = self.audit_command;

        // Handle errors and clean up invocation state
        if resp_code != TPM_RC::SUCCESS {
            self.clear_invocation_state();
            self.sessions = None;

            // Return error
            return Err(TpmError::GenericError(format!(
                "TPM Error - TPM_RC::{:?}",
                self.last_response_code
            )));
        }

        // A check for the session tag consistency across the command invocation
        let sess_tag = self.current_session_tag.unwrap_or(TPM_ST::NULL);
        if resp_tag != sess_tag {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(TpmError::GenericError(
                "Wrong response session tag".to_string(),
            ));
        }

        //
        // The command succeeded, so we can process the response buffer
        //

        // Get the handles if any
        if resp_struct.num_handles() > 0 {
            let handle_val = resp_buf.readInt();
            resp_struct.set_handle(&TPM_HANDLE::new(handle_val));
        }

        let resp_params_pos: usize;
        let resp_params_size: usize;
        let mut rp_ready = false;

        // If there are no sessions then response parameters take up the remaining part
        // of the response buffer. Otherwise the response parameters area is preceded with
        // its size, and followed by the session area.
        if sess_tag == TPM_ST::SESSIONS {
            resp_params_size = resp_buf.readInt() as usize;
            resp_params_pos = resp_buf.current_pos();

            // Process response sessions, including verification of response HMACs
            rp_ready = match self.process_resp_sessions(
                &mut resp_buf,
                cmd_code,
                resp_params_pos,
                resp_params_size,
            ) {
                Ok(ready) => ready,
                Err(e) => {
                    self.clear_invocation_state();
                    self.sessions = None;
                    return Err(e);
                }
            };
        } else {
            resp_params_pos = resp_buf.current_pos();
            resp_params_size = resp_buf.size() - resp_params_pos;
        }

        // Update enc_session/dec_session nonces from the processed sessions
        if let Some(ref sessions) = self.sessions {
            if let Some(ref mut enc) = self.enc_session {
                for s in sessions.iter() {
                    if s.sess_in.sessionHandle.handle == enc.sess_in.sessionHandle.handle {
                        enc.sess_out.nonce = s.sess_out.nonce.clone();
                        enc.sess_in.nonce = s.sess_in.nonce.clone();
                        break;
                    }
                }
            }
            if let Some(ref mut dec) = self.dec_session {
                for s in sessions.iter() {
                    if s.sess_in.sessionHandle.handle == dec.sess_in.sessionHandle.handle {
                        dec.sess_out.nonce = s.sess_out.nonce.clone();
                        dec.sess_in.nonce = s.sess_in.nonce.clone();
                        break;
                    }
                }
            }
        }

        // Handle audit processing
        if audit_command {
            let rp_hash = self.get_rp_hash(
                self.command_audit_hash.hashAlg,
                &mut resp_buf,
                cmd_code,
                resp_params_pos,
                resp_params_size,
                rp_ready,
            )?;

            // Extend audit digest: CommandAuditHash = H(CommandAuditHash || cpHash || rpHash)
            let hash_alg = self.command_audit_hash.hashAlg;
            let mut extend_data = Vec::new();
            extend_data.extend_from_slice(&self.command_audit_hash.digest);
            extend_data.extend_from_slice(&self.audit_cp_hash.digest);
            extend_data.extend_from_slice(&rp_hash);
            if let Ok(new_digest) = Crypto::hash(&self.crypto, hash_alg, &extend_data) {
                self.command_audit_hash.digest = new_digest;
            }
        }

        // Parameter decryption (if necessary)
        if let Err(e) = self.do_param_encryption(resp_struct, &mut resp_buf, resp_params_pos, false)
        {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }
        // Clear encryption session state after use
        self.enc_session = None;
        self.dec_session = None;

        // Reset position to start of parameters area and unmarshall
        resp_buf.set_current_pos(resp_params_pos);
        resp_struct.initFromTpm(&mut resp_buf)?;
        resp_buf.check_status()?;

        // Validate that we read the exact number of bytes expected
        if resp_buf.current_pos() != resp_params_pos + resp_params_size {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(TpmError::GenericError(
                "Bad response parameters area".to_string(),
            ));
        }

        // Update response handle with name and auth value
        if let Err(e) = self.update_resp_handle(cmd_code, resp_struct) {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }

        // Complete post-command handle updates (e.g., HierarchyChangeAuth auth tracking)
        if let Err(e) = self.complete_update_request_handles(cmd_code) {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }

        // Preserve sessions with continueSession for reuse, otherwise clear
        self.completed_sessions = self.sessions.take();
        self.clear_invocation_state();

        Ok(true)
    }
}

impl Tpm2 {
    pub fn last_response_code(&self) -> TPM_RC {
        self.last_response_code
    }

    pub fn last_error(&self) -> Option<TpmCommandError> {
        self.last_error.clone()
    }

    pub fn allow_errors(&mut self) -> &mut Self {
        self.errors_allowed = true;
        self
    }

    pub fn enable_exceptions(&mut self, enable: bool) {
        self.exceptions_enabled = enable;
        self.errors_allowed = !enable;
    }

    pub fn with_session(&mut self, session: Session) -> &mut Self {
        self.sessions = Some(vec![session]);
        self
    }

    pub fn with_sessions(&mut self, sessions: Vec<Session>) -> &mut Self {
        self.sessions = Some(sessions);
        self
    }

    /// Get the updated session after the last command completed.
    /// This is needed when reusing HMAC/policy sessions across commands,
    /// since the TPM updates nonces after each command.
    pub fn last_sessions(&self) -> Option<&Vec<Session>> {
        self.completed_sessions.as_ref()
    }

    /// Get the first updated session from the last completed command.
    /// Convenience method for the common single-session case.
    pub fn last_session(&self) -> Option<Session> {
        self.completed_sessions
            .as_ref()
            .and_then(|s| s.first().cloned())
    }

    pub fn connect(&mut self) -> Result<(), TpmError> {
        self.device.connect()?;
        self.last_response_code = TPM_RC::SUCCESS;
        Ok(())
    }

    pub fn close(&mut self) {
        self.device.close();
    }
}

/// High-level convenience methods for session management and common patterns.
impl Tpm2 {
    /// Start a simple HMAC or policy auth session (no salt, no binding).
    pub fn start_auth_session(
        &mut self,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
    ) -> Result<Session, TpmError> {
        self.start_auth_session_full(
            session_type,
            auth_hash,
            TPMA_SESSION::continueSession,
            TPMT_SYM_DEF::default(),
        )
    }

    /// Start an auth session with explicit attributes and symmetric definition.
    ///
    /// The session is neither salted nor bound, so it has no secret key material. It cannot be
    /// used for parameter encryption — see [`Tpm2::start_salted_auth_session`] for that.
    pub fn start_auth_session_full(
        &mut self,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
    ) -> Result<Session, TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());

        self.start_auth_session_ex(
            None, // no salt key
            &null_handle,
            session_type,
            auth_hash,
            attributes,
            symmetric,
        )
    }

    /// Start a session salted to `salt_key`, the straightforward way to get a session that can
    /// carry parameter encryption.
    ///
    /// `salt_key_public` must be the public area of `salt_key` as a [`TrustedPublic`] — see
    /// [`Tpm2::start_auth_session_ex`] for why this client will not fetch it for you.
    pub fn start_salted_auth_session(
        &mut self,
        salt_key: &TPM_HANDLE,
        salt_key_public: &TrustedPublic,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
    ) -> Result<Session, TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());

        self.start_auth_session_ex(
            Some((salt_key, salt_key_public)),
            &null_handle,
            session_type,
            auth_hash,
            attributes,
            symmetric,
        )
    }

    /// Start an auth session with full control over salting and binding.
    ///
    /// # Salting
    ///
    /// Pass `Some((handle, public))` to salt the session. The salt is generated here, at the
    /// session hash's digest size, and encrypted to `public` — which the caller supplies as a
    /// [`TrustedPublic`], having already decided that this public area is the one it means.
    ///
    /// This function deliberately does **not** call `TPM2_ReadPublic` on the salt key. Doing so
    /// would encrypt the salt to whatever public area came back over the very channel the salt
    /// exists to protect: an adversary in the middle answers the `ReadPublic` with a key it
    /// holds the private half of, learns the salt, derives the session key, and from then on
    /// produces and verifies both command and response HMACs. Nothing downstream would notice,
    /// because every check would use the adversary's key. The trust decision has to be made from
    /// something other than the channel, so it is the caller's to make.
    ///
    /// Note also what salting does *not* buy you. It gives the session key an input an
    /// eavesdropper does not have, which is what parameter encryption and HMAC integrity need.
    /// It does not authenticate the peer. If the pinned Name came from the same untrusted
    /// channel — or if [`TrustedPublic::assume_trusted`] was used on a public area read over
    /// it — the session is salted and still unauthenticated.
    // The parameter list mirrors the TPM2_StartAuthSession command parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn start_auth_session_ex(
        &mut self,
        salt_key: Option<(&TPM_HANDLE, &TrustedPublic)>,
        bind: &TPM_HANDLE,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
    ) -> Result<Session, TpmError> {
        let nonce_size = Crypto::digest_size_checked(auth_hash)?;
        let nonce_caller = Crypto::get_random(&self.crypto, nonce_size)?;

        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());
        let (tpm_key, salt, encrypted_salt) = match salt_key {
            Some((handle, trusted)) => {
                // The salt is what makes the session key unpredictable, so it is sized to the
                // session hash rather than left to the caller to get right.
                let salt = Zeroizing::new(Crypto::get_random(
                    &self.crypto,
                    Crypto::digest_size_checked(auth_hash)?,
                )?);
                let encrypted = trusted.public().encrypt_session_salt(&self.crypto, &salt)?;
                (handle.clone(), salt, encrypted)
            }
            None => (null_handle, Zeroizing::new(Vec::new()), Vec::new()),
        };

        let resp = self.StartAuthSession(
            &tpm_key,
            bind,
            &nonce_caller,
            &encrypted_salt,
            session_type,
            &symmetric,
            auth_hash,
        )?;

        Session::from_tpm_response(
            &self.crypto,
            resp.handle,
            session_type,
            auth_hash,
            nonce_caller,
            resp.nonceTPM,
            attributes,
            symmetric,
            &salt,
            bind,
        )
    }

    /// Set a session on this Tpm2 for the next command.
    pub fn set_sessions(&mut self, sessions: Vec<Session>) {
        self.sessions = Some(sessions);
    }
}

impl Tpm2 {
    // Additional helper methods to support the dispatch_command and process_response implementations

    /// Roll nonces for all non-PWAP sessions
    fn roll_nonces(&mut self) -> Result<(), TpmError> {
        if let Some(ref mut sessions) = self.sessions {
            for session in sessions.iter_mut() {
                if !session.is_pwap() {
                    let nonce_size = session.sess_out.nonce.len();
                    session.sess_in.nonce = Crypto::get_random(&self.crypto, nonce_size.max(16))?;
                }
            }
        }
        Ok(())
    }

    /// Clear the current invocation state
    fn clear_invocation_state(&mut self) {
        self.current_cmd_code = None;
        self.current_session_tag = None;
        // Clear other command-specific state
    }

    /// Set the auth value for an admin hierarchy handle.
    /// Use this when the TPM's hierarchy auth was set externally (e.g., recovering from a
    /// previous run that changed auth but failed to reset it).
    pub fn set_admin_auth(&mut self, hierarchy: TPM_RH, auth: &[u8]) {
        let val = hierarchy.get_value();
        if val == TPM_RH::OWNER.get_value() {
            self.admin_owner.set_auth(auth);
        } else if val == TPM_RH::ENDORSEMENT.get_value() {
            self.admin_endorsement.set_auth(auth);
        } else if val == TPM_RH::PLATFORM.get_value() {
            self.admin_platform.set_auth(auth);
        } else if val == TPM_RH::LOCKOUT.get_value() {
            self.admin_lockout.set_auth(auth);
        }
    }

    /// Set auth values for well-known admin handles (avoids borrow issues)
    fn set_rh_auth_value_static(
        h: &mut TPM_HANDLE,
        admin_owner: &TPM_HANDLE,
        admin_endorsement: &TPM_HANDLE,
        admin_platform: &TPM_HANDLE,
        admin_lockout: &TPM_HANDLE,
    ) {
        match h.handle {
            val if val == TPM_RH::OWNER.get_value() => h.set_auth(&admin_owner.auth_value),
            val if val == TPM_RH::ENDORSEMENT.get_value() => {
                h.set_auth(&admin_endorsement.auth_value)
            }
            val if val == TPM_RH::PLATFORM.get_value() => h.set_auth(&admin_platform.auth_value),
            val if val == TPM_RH::LOCKOUT.get_value() => h.set_auth(&admin_lockout.auth_value),
            _ => {} // No auth value change needed
        }
    }

    /// Get CpHash data for parameter encryption
    fn get_cp_hash_data(&self, cmd_code: TPM_CC, cmd_params: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut buf = TpmBuffer::new(None);
        buf.writeInt(cmd_code.get_value());

        for h in self.in_handles.iter() {
            let name = h.get_name()?;
            buf.writeByteBuf(&name);
        }

        buf.writeByteBuf(cmd_params);
        Ok(buf.buffer().clone())
    }

    /// Process authorization sessions for a command
    fn process_auth_sessions(
        &mut self,
        cmd_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        num_auth_handles: u16,
        cmd_params: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let mut needs_hmac = false;

        if let Some(ref sessions) = self.sessions {
            for session in sessions.iter() {
                if !session.is_pwap() {
                    needs_hmac = true;
                    break;
                }
            }
        }

        // Compute CpHash if needed for HMAC sessions
        let cp_hash_data = if needs_hmac {
            self.get_cp_hash_data(cmd_code, cmd_params)?
        } else {
            Vec::new()
        };

        if let Some(ref mut sessions) = self.sessions {
            for (i, session) in sessions.iter().enumerate() {
                let mut auth_cmd = TPMS_AUTH_COMMAND::default();

                // If it's a PWAP session, handling is simple
                if session.is_pwap() {
                    auth_cmd.sessionHandle = TPM_HANDLE::new(TPM_RH::PW.get_value());
                    auth_cmd.nonce = Vec::new();

                    if i < self.in_handles.len() {
                        auth_cmd.hmac = self.in_handles[i].auth_value.clone();
                    }

                    auth_cmd.sessionAttributes = TPMA_SESSION::continueSession;
                    auth_cmd.toTpm(cmd_buf)?;
                    continue;
                }

                // For non-PWAP sessions, we need more complex processing
                let mut h_copy = None;

                if i < num_auth_handles as usize && i < self.in_handles.len() {
                    // Set appropriate auth value on handle
                    h_copy = Some(self.in_handles[i].clone());
                }

                auth_cmd.nonce = session.sess_in.nonce.clone();
                auth_cmd.sessionHandle = session.sess_in.sessionHandle.clone();
                auth_cmd.sessionAttributes = session.sess_in.sessionAttributes;

                // Mirrors the TPM's own dispatch rule (`SessionProcess.c`: `if (PWAP ||
                // isPasswordNeeded) CheckPWAuthSession else CheckSessionHMAC`). Note the order:
                // a policy session on which TPM2_PolicyPassword ran sends the authValue in the
                // clear, every other non-PWAP session sends a computed HMAC — including a policy
                // session that has run no PolicyAuthValue, which used to send an empty field and
                // so could not be salted or bound at all.
                if session.needs_password {
                    if i < self.in_handles.len() {
                        auth_cmd.hmac = self.in_handles[i].auth_value.clone();
                    }
                } else {
                    // Calculate HMAC based on CpHash
                    let cp_hash =
                        Crypto::hash(&self.crypto, session.get_hash_alg(), &cp_hash_data)?;
                    auth_cmd.hmac = session.get_auth_hmac(
                        &self.crypto,
                        cp_hash,
                        true,
                        &self.nonce_tpm_dec,
                        &self.nonce_tpm_enc,
                        h_copy.as_ref(),
                    )?;
                }

                auth_cmd.toTpm(cmd_buf)?;
            }
        }

        Ok(cp_hash_data)
    }

    /// Prepare parameter encryption sessions
    fn prepare_param_encryption_sessions(&mut self) {
        self.enc_session = None;
        self.dec_session = None;
        self.nonce_tpm_dec.clear();
        self.nonce_tpm_enc.clear();

        if let Some(ref sessions) = self.sessions {
            for session in sessions.iter() {
                if session.is_pwap() {
                    continue;
                }

                // Check for decrypt attribute
                if (session.sess_in.sessionAttributes.get_value()
                    & TPMA_SESSION::decrypt.get_value())
                    != 0
                {
                    self.dec_session = Some(session.clone());
                }

                // Check for encrypt attribute
                if (session.sess_in.sessionAttributes.get_value()
                    & TPMA_SESSION::encrypt.get_value())
                    != 0
                {
                    self.enc_session = Some(session.clone());
                }
            }

            // Store nonces for the first session to prevent tampering
            if let Some(ref sessions_vec) = self.sessions {
                if !sessions_vec.is_empty() {
                    let first_session = &sessions_vec[0];

                    // If first session is followed by decrypt session
                    if let Some(ref dec) = self.dec_session {
                        if dec.sess_in.sessionHandle.handle
                            != first_session.sess_in.sessionHandle.handle
                        {
                            self.nonce_tpm_dec = dec.sess_out.nonce.clone();
                        }
                    }

                    // If first session is followed by encrypt session (and it's not the decrypt session)
                    if let Some(ref enc) = self.enc_session {
                        if enc.sess_in.sessionHandle.handle
                            != first_session.sess_in.sessionHandle.handle
                            && (self.dec_session.is_none()
                                || enc.sess_in.sessionHandle.handle
                                    != self
                                        .dec_session
                                        .as_ref()
                                        .unwrap()
                                        .sess_in
                                        .sessionHandle
                                        .handle)
                        {
                            self.nonce_tpm_enc = enc.sess_out.nonce.clone();
                        }
                    }
                }
            }
        }
    }

    /// Process parameter encryption/decryption
    fn do_param_encryption<T: CmdStructure>(
        &self,
        cmd: &T,
        param_buf: &mut TpmBuffer,
        start_pos: usize,
        is_request: bool,
    ) -> Result<(), TpmError> {
        let xcrypt_sess = if is_request {
            if self.dec_session.is_none() {
                return Ok(());
            }
            self.dec_session.as_ref()
        } else {
            if self.enc_session.is_none() {
                return Ok(());
            }
            self.enc_session.as_ref()
        };

        let sess = xcrypt_sess.unwrap();
        let sei = cmd.sess_enc_info();
        if sei.size_len == 0 || sei.val_len == 0 {
            return Ok(());
        }

        let orig_cur_pos = param_buf.current_pos();
        param_buf.set_current_pos(start_pos);

        // Read the size of the first parameter (TPM2B prefix)
        let arr_size = param_buf.read_num(sei.size_len as usize) as usize;
        param_buf.check_status()?;
        let arr_pos = param_buf.current_pos();

        if arr_size == 0 {
            param_buf.set_current_pos(orig_cur_pos);
            return Ok(());
        }

        // Read the data to encrypt/decrypt
        let xcrypt_size = arr_size
            .checked_mul(sei.val_len as usize)
            .ok_or(TpmError::BufferUnderflow)?;
        let to_xcrypt = param_buf.readByteBuf(xcrypt_size);
        param_buf.check_status()?;

        // Perform encryption/decryption
        let result = sess.param_xcrypt(&self.crypto, &to_xcrypt, is_request)?;

        // Write the result back into the buffer
        param_buf.set_current_pos(arr_pos);
        param_buf.writeByteBuf(&result);

        param_buf.set_current_pos(orig_cur_pos);

        Ok(())
    }

    /// Get RP hash (response parameter hash)
    fn get_rp_hash(
        &self,
        hash_alg: TPM_ALG_ID,
        resp_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        resp_params_pos: usize,
        resp_params_size: usize,
        rp_ready: bool,
    ) -> Result<Vec<u8>, TpmError> {
        let rp_header_size = 8;
        let rp_hash_data_pos = resp_params_pos - rp_header_size;

        if !rp_ready {
            // Create a continuous data area required by rpHash
            let orig_cur_pos = resp_buf.current_pos();
            resp_buf.set_current_pos(rp_hash_data_pos);
            resp_buf.writeInt(TPM_RC::SUCCESS.get_value());
            resp_buf.writeInt(cmd_code.get_value());
            resp_buf.set_current_pos(orig_cur_pos);
        }

        let data_to_hash = &resp_buf.buffer()
            [rp_hash_data_pos..(rp_hash_data_pos + rp_header_size + resp_params_size)];
        Crypto::hash(&self.crypto, hash_alg, data_to_hash)
    }

    /// Process response sessions
    fn process_resp_sessions(
        &mut self,
        resp_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        resp_params_pos: usize,
        resp_params_size: usize,
    ) -> Result<bool, TpmError> {
        let mut rp_ready = false;
        resp_buf.set_current_pos(resp_params_pos + resp_params_size);
        resp_buf.check_status()?;

        // Pre-compute values needed for HMAC verification to avoid borrow conflicts
        let nonce_tpm_dec = self.nonce_tpm_dec.clone();
        let nonce_tpm_enc = self.nonce_tpm_enc.clone();
        let in_handles = self.in_handles.clone();

        if let Some(ref mut sessions) = self.sessions {
            for (j, session) in sessions.iter_mut().enumerate() {
                let mut auth_response = TPMS_AUTH_RESPONSE::default();
                auth_response.initFromTpm(resp_buf)?;
                resp_buf.check_status()?;

                if session.is_pwap() {
                    // PWAP sessions should have empty nonce and hmac
                    if !auth_response.nonce.is_empty() || !auth_response.hmac.is_empty() {
                        return Err(TpmError::GenericError(
                            "Bad value in PWAP session response".to_string(),
                        ));
                    }
                    continue;
                }

                // Non-PWAP session handling
                let associated_handle = if j < in_handles.len() {
                    Some(&in_handles[j])
                } else {
                    None
                };

                // Update session data based on what the TPM just told us.
                //
                // The response nonce and the response attributes are both inputs to the response
                // HMAC, so they have to be in place before it is checked; if either was tampered
                // with, the HMAC verification below is what catches it.
                session.sess_out.nonce = auth_response.nonce.clone();
                session.sess_out.sessionAttributes = auth_response.sessionAttributes;

                // What is NOT done here is copying the response attributes into `sess_in` for
                // the next command. The response is attacker-reachable; the caller's requested
                // attributes are not. Sourcing the next command's attributes from the response
                // lets an adversary clear `encrypt`/`decrypt` and have this client send the next
                // command's first parameter in the clear, while the calling code goes on
                // believing the session encrypts. The caller's request stays authoritative.
                //
                // The TPM echoes `encrypt`/`decrypt` verbatim, so a differing echo means either
                // tampering or a TPM that is not doing what was asked. Either way, stop.
                let xcrypt_mask =
                    TPMA_SESSION::encrypt.get_value() | TPMA_SESSION::decrypt.get_value();
                let requested_xcrypt = session.sess_in.sessionAttributes.get_value() & xcrypt_mask;
                let echoed_xcrypt = auth_response.sessionAttributes.get_value() & xcrypt_mask;
                if requested_xcrypt != echoed_xcrypt {
                    return Err(TpmError::GenericError(format!(
                        "Session {} response echoed encrypt/decrypt attributes 0x{:02x} but \
                         0x{:02x} was requested",
                        j, echoed_xcrypt, requested_xcrypt
                    )));
                }

                // The TPM returns an authorization HMAC for every session except a password
                // session and a policy session on which TPM2_PolicyPassword has run; for those
                // two it returns an empty field (`BuildSingleResponseAuth`). Everything else —
                // an HMAC session, and equally a policy session driven by PolicyAuthValue,
                // PolicyPCR, PolicySecret or nothing at all — is authenticated and must be
                // verified. Skipping the policy cases left every response parameter they carried
                // unauthenticated. This mirrors the command-side rule above.
                if !session.expects_response_auth() {
                    if !auth_response.hmac.is_empty() {
                        return Err(TpmError::GenericError(format!(
                            "Session {} returned an authorization HMAC where none was expected",
                            j
                        )));
                    }
                    continue;
                }

                // Compute rpHash inline to avoid borrow conflict with self
                let rp_hash = {
                    let rp_header_size = 8;
                    let rp_hash_data_pos = resp_params_pos - rp_header_size;

                    if !rp_ready {
                        let orig_cur_pos = resp_buf.current_pos();
                        resp_buf.set_current_pos(rp_hash_data_pos);
                        resp_buf.writeInt(TPM_RC::SUCCESS.get_value());
                        resp_buf.writeInt(cmd_code.get_value());
                        resp_buf.set_current_pos(orig_cur_pos);
                    }

                    let data_to_hash = &resp_buf.buffer()
                        [rp_hash_data_pos..(rp_hash_data_pos + rp_header_size + resp_params_size)];
                    Crypto::hash(&self.crypto, session.get_hash_alg(), data_to_hash)?
                };
                rp_ready = true;

                let expected_hmac = session.get_auth_hmac(
                    &self.crypto,
                    rp_hash,
                    false,
                    &nonce_tpm_dec,
                    &nonce_tpm_enc,
                    associated_handle,
                )?;

                if auth_response.hmac.is_empty() {
                    return Err(TpmError::GenericError(format!(
                        "Session {} returned no authorization HMAC where one was expected",
                        j
                    )));
                }

                // Length first, because `ct_eq` is only defined for equal-length slices, and
                // then a constant-time compare so that a wrong tag leaks nothing about how much
                // of it was right.
                let tag_ok = expected_hmac.len() == auth_response.hmac.len()
                    && bool::from(expected_hmac.ct_eq(&auth_response.hmac));
                if !tag_ok {
                    return Err(TpmError::GenericError(format!(
                        "Invalid TPM response HMAC (session {})",
                        j
                    )));
                }
            }
        }

        if resp_buf.size() - resp_buf.current_pos() != 0 {
            return Err(TpmError::GenericError(
                "Invalid response buffer: Data beyond the authorization area".to_string(),
            ));
        }

        Ok(rp_ready)
    }

    /// Update request handles based on command
    fn update_request_handles(&mut self, cmd_code: TPM_CC) -> Result<(), TpmError> {
        // Reset state
        self.object_in_name.clear();

        // This function handles updates to handles based on specific commands
        match cmd_code {
            TPM_CC::HierarchyChangeAuth => {
                // Extract newAuth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            TPM_CC::LoadExternal => {
                // Store the name for later use
                // In a real implementation, calculate the name from the public area
                self.object_in_name = vec![]; // Calculate from req
                Ok(())
            }
            TPM_CC::Load => {
                // Store the name for later use
                // In a real implementation, calculate the name from the public area
                self.object_in_name = vec![]; // Calculate from req
                Ok(())
            }
            TPM_CC::NV_ChangeAuth => {
                // Extract newAuth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            TPM_CC::ObjectChangeAuth => {
                // Extract newAuth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            TPM_CC::PCR_SetAuthValue => {
                // Store auth value for later use
                // In a real implementation, extract the new auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            TPM_CC::EvictControl => {
                // Store name and auth value for later use
                if (!self.in_handles.is_empty()
                    && self.in_handles[1].get_type() != TPM_HT::PERSISTENT)
                {
                    let handle = &self.in_handles[1];
                    self.object_in_auth = handle.auth_value.clone();
                    self.object_in_name = handle.get_name()?;
                }
                Ok(())
            }
            TPM_CC::Clear => {
                // Reset admin auth values
                if !self.in_handles.is_empty() {
                    let mut handle = self.in_handles[0].clone();
                    handle.set_auth(&[]);
                }
                Ok(())
            }
            TPM_CC::HashSequenceStart => {
                // Extract auth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Complete update of request handles after command success
    fn complete_update_request_handles(&mut self, cmd_code: TPM_CC) -> Result<(), TpmError> {
        match cmd_code {
            TPM_CC::HierarchyChangeAuth => {
                // Update the appropriate hierarchy auth value
                if !self.in_handles.is_empty() {
                    match self.in_handles[0].handle {
                        val if val == TPM_RH::OWNER.get_value() => {
                            self.admin_owner.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::ENDORSEMENT.get_value() => {
                            self.admin_endorsement.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::PLATFORM.get_value() => {
                            self.admin_platform.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::LOCKOUT.get_value() => {
                            self.admin_lockout.set_auth(&self.object_in_auth)
                        }
                        _ => {}
                    }

                    // Update handle auth
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::NV_ChangeAuth => {
                if !self.in_handles.is_empty() {
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::PCR_SetAuthValue => {
                if !self.in_handles.is_empty() {
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::EvictControl => {
                // Update handle auth and name
                if self.in_handles.len() >= 2 && self.in_handles[1].get_type() != TPM_HT::PERSISTENT
                {
                    self.in_handles[1].set_auth(&self.object_in_auth);
                    let _ = self.in_handles[1].set_name(&self.object_in_name.clone());
                }
                Ok(())
            }
            TPM_CC::Clear => {
                // Reset all hierarchy auth values
                self.admin_lockout.set_auth(&[]);
                self.admin_owner.set_auth(&[]);
                self.admin_endorsement.set_auth(&[]);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Update response handle with name and auth value
    fn update_resp_handle<T: RespStructure>(
        &mut self,
        cmd_code: TPM_CC,
        resp: &mut T,
    ) -> Result<(), TpmError> {
        match cmd_code {
            TPM_CC::Load | TPM_CC::CreatePrimary | TPM_CC::LoadExternal | TPM_CC::CreateLoaded => {
                let name = resp.get_resp_name();
                if !name.is_empty() {
                    let mut handle = resp.get_handle();
                    handle.set_name(&name)?;
                    resp.set_handle(&handle);
                }
                Ok(())
            }
            TPM_CC::HashSequenceStart | TPM_CC::HMAC_Start => Ok(()),
            _ => Ok(()),
        }
    }
}

/// Factory function to create a new TPM implementation based on the available platform,
/// performing its host-side crypto with `crypto`.
pub fn create_tpm_with_crypto(crypto: CryptoProvider) -> Tpm2 {
    #[cfg(target_os = "windows")]
    {
        use crate::device::TpmTbsDevice;
        Tpm2::new(Box::new(TpmTbsDevice::new()), crypto)
    }
    #[cfg(not(target_os = "windows"))]
    {
        use crate::device::TpmTbsDevice;
        Tpm2::new(Box::new(TpmTbsDevice::new()), crypto)
    }
}

/// Factory function to create a new TPM implementation based on the available platform, using
/// the built-in software crypto backend.
#[cfg(feature = "software-crypto")]
pub fn create_tpm() -> Tpm2 {
    create_tpm_with_crypto(crate::crypto::software_provider::SOFTWARE_PROVIDER)
}

/// Factory function to create a TPM implementation with a custom device, using the built-in
/// software crypto backend.
///
/// To supply a different backend, call [`Tpm2::new`] directly.
#[cfg(feature = "software-crypto")]
pub fn create_tpm_with_device(device: Box<dyn TpmDevice>) -> Tpm2 {
    Tpm2::with_software_crypto(device)
}

/// An in-memory [`TpmDevice`] that replays canned response bytes.
///
/// Without it nothing in this module is reachable from a test: the only real `TpmDevice` talks to
/// Windows TBS, so every session and authorization path here has historically been exercised only
/// by hand against hardware.
///
/// Note what a mock device can and cannot establish. It can show that this client *reacts*
/// correctly to a given response — verifies what it should verify, refuses what it should refuse.
/// It cannot establish that a digest this client computes is the digest the TPM computes, because
/// the canned bytes are ours too. Tests of the second kind have to pin their expectations to
/// something outside this crate; see the `spec_*` helpers below, which are transcribed from the
/// TPM 2.0 specification rather than obtained from the code under test.
#[cfg(test)]
pub(crate) mod mock_device {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// The bytes a [`MockTpmDevice`] returns for one response, derived from the command that was
    /// just dispatched.
    pub type Responder = Box<dyn Fn(&[u8]) -> Vec<u8> + Send>;

    /// Where a [`MockTpmDevice`] gets the bytes for one response.
    pub enum MockResponse {
        /// Fixed bytes, returned verbatim.
        Canned(Vec<u8>),
        /// Bytes derived from the command just dispatched. Needed whenever the response has to
        /// be well formed with respect to values the client picked at random — the nonceCaller,
        /// and the authorization HMAC computed over it.
        Computed(Responder),
    }

    pub struct MockTpmDevice {
        responses: VecDeque<MockResponse>,
        commands: Arc<Mutex<Vec<Vec<u8>>>>,
        pending: Option<Vec<u8>>,
    }

    impl MockTpmDevice {
        pub fn new(responses: Vec<MockResponse>) -> Self {
            MockTpmDevice {
                responses: responses.into_iter().collect(),
                commands: Arc::new(Mutex::new(Vec::new())),
                pending: None,
            }
        }

        /// A handle on the commands this device is sent, live for as long as the device is.
        pub fn command_log(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
            Arc::clone(&self.commands)
        }
    }

    impl TpmDevice for MockTpmDevice {
        fn connect(&mut self) -> Result<bool, TpmError> {
            Ok(true)
        }

        fn close(&mut self) {}

        fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
            self.commands.lock().unwrap().push(cmd_buf.to_vec());
            let response = self.responses.pop_front().ok_or_else(|| {
                TpmError::GenericError("MockTpmDevice: no queued response".to_string())
            })?;
            self.pending = Some(match response {
                MockResponse::Canned(bytes) => bytes,
                MockResponse::Computed(f) => f(cmd_buf),
            });
            Ok(())
        }

        fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
            self.pending.take().ok_or_else(|| {
                TpmError::GenericError("MockTpmDevice: no response pending".to_string())
            })
        }

        fn response_is_ready(&self) -> Result<bool, TpmError> {
            Ok(self.pending.is_some())
        }

        fn has_flag(&self, _flag: u32) -> bool {
            false
        }

        fn get_tpm_info(&self) -> u32 {
            0
        }
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::mock_device::{MockResponse, MockTpmDevice};
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use std::sync::{Arc, Mutex};

    const LOCKOUT_AUTH: &[u8] = b"lockout-auth";
    const SALT: &[u8] = b"a thirty-two byte session salt..";

    fn be16(buf: &[u8], pos: usize) -> u16 {
        u16::from_be_bytes([buf[pos], buf[pos + 1]])
    }

    fn be32(buf: &[u8], pos: usize) -> u32 {
        u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
    }

    /// The one authorization area of a `TPM2_Clear` command, which has a single handle and no
    /// parameters. Layout from TPM 2.0 Part 1, §18.2:
    /// `tag ‖ commandSize ‖ commandCode ‖ handles ‖ authorizationSize ‖ authorizationArea`.
    struct CommandAuth {
        nonce_caller: Vec<u8>,
        attributes: u8,
        hmac: Vec<u8>,
    }

    fn parse_clear_command_auth(cmd: &[u8]) -> CommandAuth {
        let mut p = 2 + 4 + 4 + 4; // tag, commandSize, commandCode, one handle
        let auth_size = be32(cmd, p) as usize;
        p += 4;
        let auth_end = p + auth_size;

        p += 4; // sessionHandle
        let nonce_len = be16(cmd, p) as usize;
        p += 2;
        let nonce_caller = cmd[p..p + nonce_len].to_vec();
        p += nonce_len;
        let attributes = cmd[p];
        p += 1;
        let hmac_len = be16(cmd, p) as usize;
        p += 2;
        let hmac = cmd[p..p + hmac_len].to_vec();
        p += hmac_len;

        assert_eq!(
            p, auth_end,
            "authorization area size does not match its contents"
        );
        assert_eq!(auth_end, cmd.len(), "TPM2_Clear should have no parameters");

        CommandAuth {
            nonce_caller,
            attributes,
            hmac,
        }
    }

    /// A `TPM_ST_SESSIONS` response for a command with no response handles and no response
    /// parameters, carrying exactly one authorization area.
    fn build_response(nonce_tpm: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
        let mut auth = Vec::new();
        auth.extend_from_slice(&(nonce_tpm.len() as u16).to_be_bytes());
        auth.extend_from_slice(nonce_tpm);
        auth.push(attributes);
        auth.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
        auth.extend_from_slice(hmac);

        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST::SESSIONS.get_value().to_be_bytes());
        resp.extend_from_slice(&((2 + 4 + 4 + 4 + auth.len()) as u32).to_be_bytes());
        resp.extend_from_slice(&TPM_RC::SUCCESS.get_value().to_be_bytes()); // responseCode
        resp.extend_from_slice(&0u32.to_be_bytes()); // parameterSize
        resp.extend_from_slice(&auth);
        resp
    }

    /// The TPM 2.0 response authorization HMAC, transcribed from the specification rather than
    /// obtained from the code under test.
    ///
    /// TPM 2.0 Part 1, §19.6.5 and §19.6.6, for a response with no parameters:
    /// ```text
    ///   rpHash   := H_sessionAlg(responseCode ‖ commandCode ‖ parameters)
    ///   authHMAC := HMAC_sessionAlg(sessionKey ‖ authValue,
    ///                               rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes)
    /// ```
    /// (`nonceTPM` is the newer nonce on the response side, `nonceCaller` the older.)
    fn spec_response_hmac(
        key: &[u8],
        cmd_code: TPM_CC,
        nonce_tpm: &[u8],
        nonce_caller: &[u8],
        attributes: u8,
    ) -> Vec<u8> {
        let mut rp = Vec::new();
        rp.extend_from_slice(&TPM_RC::SUCCESS.get_value().to_be_bytes());
        rp.extend_from_slice(&cmd_code.get_value().to_be_bytes());
        let rp_hash = Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &rp).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&rp_hash);
        buf.extend_from_slice(nonce_tpm);
        buf.extend_from_slice(nonce_caller);
        buf.push(attributes);
        Crypto::hmac(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, key, &buf).unwrap()
    }

    /// The TPM 2.0 command authorization HMAC, likewise transcribed from the specification.
    ///
    /// TPM 2.0 Part 1, §19.6.5, for a command with no parameters and no separate
    /// encrypt/decrypt sessions:
    /// ```text
    ///   cpHash   := H_sessionAlg(commandCode ‖ name(s) ‖ parameters)
    ///   authHMAC := HMAC_sessionAlg(sessionKey ‖ authValue,
    ///                               cpHash ‖ nonceCaller ‖ nonceTPM ‖ sessionAttributes)
    /// ```
    fn spec_command_hmac(
        key: &[u8],
        cmd_code: TPM_CC,
        handle_names: &[Vec<u8>],
        nonce_caller: &[u8],
        nonce_tpm: &[u8],
        attributes: u8,
    ) -> Vec<u8> {
        let mut cp = Vec::new();
        cp.extend_from_slice(&cmd_code.get_value().to_be_bytes());
        for name in handle_names {
            cp.extend_from_slice(name);
        }
        let cp_hash = Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &cp).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&cp_hash);
        buf.extend_from_slice(nonce_caller);
        buf.extend_from_slice(nonce_tpm);
        buf.push(attributes);
        Crypto::hmac(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, key, &buf).unwrap()
    }

    /// A session as `TPM2_StartAuthSession` would have left it, built directly so that the test
    /// knows the salt and therefore the session key.
    fn make_session(session_type: TPM_SE, salt: &[u8]) -> Session {
        Session::from_tpm_response(
            &SOFTWARE_PROVIDER,
            TPM_HANDLE::new(0x03000000),
            session_type,
            TPM_ALG_ID::SHA256,
            vec![0xAA; 32],
            vec![0xBB; 32],
            TPMA_SESSION::continueSession,
            TPMT_SYM_DEF::default(),
            salt,
            &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        )
        .unwrap()
    }

    /// A `Tpm2` over a mock device, with the lockout authValue set so that `TPM2_Clear` has a
    /// non-empty authValue to fold into its HMAC key.
    fn tpm_with(responses: Vec<MockResponse>) -> (Tpm2, Arc<Mutex<Vec<Vec<u8>>>>) {
        let device = MockTpmDevice::new(responses);
        let log = device.command_log();
        let mut tpm = Tpm2::with_software_crypto(Box::new(device));
        tpm.set_admin_auth(TPM_RH::LOCKOUT, LOCKOUT_AUTH);
        (tpm, log)
    }

    /// A responder that answers a `TPM2_Clear` with a correctly authenticated response.
    ///
    /// `key_for` turns the parsed command into the HMAC key the TPM would have used, so each
    /// test states for itself what it believes the key is.
    fn correct_responder(
        nonce_tpm: Vec<u8>,
        resp_attributes_of: fn(u8) -> u8,
        key: Vec<u8>,
    ) -> MockResponse {
        MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            let resp_attrs = resp_attributes_of(auth.attributes);
            let hmac = spec_response_hmac(
                &key,
                TPM_CC::Clear,
                &nonce_tpm,
                &auth.nonce_caller,
                resp_attrs,
            );
            build_response(&nonce_tpm, resp_attrs, &hmac)
        }))
    }

    fn echo(attrs: u8) -> u8 {
        attrs
    }

    // ---------------------------------------------------------------------------------------
    // Item 7(a): which sessions carry a response authorization, and whether it is verified.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn response_auth_is_verified_for_a_policy_session_without_policy_password() {
        // A policy session that has run no PolicyAuthValue and no PolicyPassword. The TPM still
        // authenticates the response with the session key, and this client used to skip the
        // check entirely for exactly this case.
        let session = make_session(TPM_SE::POLICY, SALT);
        let key = session.session_key.clone();
        assert!(!key.is_empty(), "the salted session should have a key");

        let (mut tpm, _log) = tpm_with(vec![correct_responder(vec![0xC1; 32], echo, key)]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("a correctly authenticated response should be accepted");
    }

    #[test]
    fn tampered_response_hmac_is_rejected() {
        // The same exchange as above with one bit flipped in the tag. If verification were
        // skipped — as it was — this would pass silently.
        let session = make_session(TPM_SE::POLICY, SALT);
        let key = session.session_key.clone();
        let nonce_tpm = vec![0xC1; 32];

        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            let mut hmac = spec_response_hmac(
                &key,
                TPM_CC::Clear,
                &nonce_tpm,
                &auth.nonce_caller,
                auth.attributes,
            );
            hmac[31] ^= 0x01;
            build_response(&nonce_tpm, auth.attributes, &hmac)
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("a tampered response HMAC must be rejected");
        assert!(
            format!("{:?}", err).contains("Invalid TPM response HMAC"),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    fn response_auth_is_not_expected_after_policy_password() {
        // TPM2_PolicyPassword makes the TPM authenticate the command with the authValue in the
        // clear and return an empty response authorization (`BuildSingleResponseAuth`). Demanding
        // one here would break every legitimate PolicyPassword session.
        let mut session = make_session(TPM_SE::POLICY, SALT);
        session.needs_password = true;
        session.needs_hmac = false;

        let nonce_tpm = vec![0xC2; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[])
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("an empty response auth is correct after TPM2_PolicyPassword");
    }

    #[test]
    fn unexpected_response_auth_after_policy_password_is_rejected() {
        let mut session = make_session(TPM_SE::POLICY, SALT);
        session.needs_password = true;
        session.needs_hmac = false;

        let nonce_tpm = vec![0xC3; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[0x00; 32])
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("an authorization the TPM cannot have produced must be rejected");
        assert!(
            format!("{:?}", err).contains("where none was expected"),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    fn missing_response_auth_is_rejected_for_an_hmac_session() {
        let session = make_session(TPM_SE::HMAC, SALT);
        let nonce_tpm = vec![0xC4; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[])
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("stripping the response authorization must not go unnoticed");
        assert!(
            format!("{:?}", err).contains("no authorization HMAC where one was expected"),
            "unexpected error: {:?}",
            err
        );
    }

    // ---------------------------------------------------------------------------------------
    // Item 7(b): the response must not dictate the next command's session attributes.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn session_attributes_are_not_taken_from_the_response() {
        // The response clears continueSession. The client must keep the attributes the caller
        // asked for, because the response is attacker-reachable and the request is not.
        let session = make_session(TPM_SE::HMAC, SALT);
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };
        let requested = session.sess_in.sessionAttributes.get_value();
        assert_eq!(requested, TPMA_SESSION::continueSession.get_value());

        let (mut tpm, _log) = tpm_with(vec![correct_responder(vec![0xC5; 32], |_| 0x00, key)]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("clearing continueSession in the response is legal, just not authoritative");

        let after = tpm.last_session().expect("session should be retained");
        assert_eq!(
            after.sess_in.sessionAttributes.get_value(),
            requested,
            "the next command's attributes must come from the caller, not the response"
        );
        assert_eq!(
            after.sess_out.sessionAttributes.get_value(),
            0x00,
            "what the TPM actually returned should still be observable"
        );
    }

    #[test]
    fn a_response_that_drops_the_encrypt_attribute_is_rejected() {
        // Stripping `encrypt` from the echo is how an adversary would try to talk this client
        // out of encrypting the next command's first parameter.
        let mut session = make_session(TPM_SE::HMAC, SALT);
        session.sess_in.sessionAttributes = TPMA_SESSION::continueSession | TPMA_SESSION::encrypt;
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };

        let (mut tpm, _log) = tpm_with(vec![correct_responder(
            vec![0xC6; 32],
            |attrs| attrs & !TPMA_SESSION::encrypt.get_value(),
            key,
        )]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("a downgraded encrypt/decrypt echo must be rejected");
        assert!(
            format!("{:?}", err).contains("echoed encrypt/decrypt attributes"),
            "unexpected error: {:?}",
            err
        );
    }

    // ---------------------------------------------------------------------------------------
    // Command side: the rule the response side mirrors.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_policy_session_without_policy_password_sends_a_command_hmac() {
        // Previously this sent an empty authorization field, which is why a salted or bound
        // policy session could not be used at all: the TPM computed an HMAC over its session key
        // and got nothing to compare it with.
        let session = make_session(TPM_SE::POLICY, SALT);
        let key = session.session_key.clone();
        let expected_key = key.clone();

        let (mut tpm, log) = tpm_with(vec![correct_responder(vec![0xC7; 32], echo, key)]);
        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let auth = parse_clear_command_auth(&cmd);
        // TPM2_Clear's one handle is TPM_RH_LOCKOUT, whose Name is the four-byte handle value
        // (TPM 2.0 Part 1, §16: for a permanent handle the Name is the handle).
        let name = TPM_RH::LOCKOUT.get_value().to_be_bytes().to_vec();
        assert_eq!(
            auth.hmac,
            spec_command_hmac(
                &expected_key,
                TPM_CC::Clear,
                &[name],
                &auth.nonce_caller,
                &[0xBB; 32],
                auth.attributes,
            ),
            "a policy session with no PolicyAuthValue keys its command HMAC on the session key \
             alone, with no authValue folded in"
        );
    }

    #[test]
    fn a_policy_password_session_sends_the_auth_value_in_the_command() {
        let mut session = make_session(TPM_SE::POLICY, SALT);
        session.needs_password = true;
        session.needs_hmac = false;

        let nonce_tpm = vec![0xC8; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[])
        }));

        let (mut tpm, log) = tpm_with(vec![responder]);
        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let auth = parse_clear_command_auth(&cmd);
        assert_eq!(
            auth.hmac, LOCKOUT_AUTH,
            "after TPM2_PolicyPassword the authValue is sent in the clear, not HMAC'd"
        );
    }

    #[test]
    fn an_hmac_session_folds_the_auth_value_into_its_command_key() {
        let session = make_session(TPM_SE::HMAC, SALT);
        let mut key = session.session_key.clone();
        key.extend_from_slice(LOCKOUT_AUTH);
        let responder_key = key.clone();

        let (mut tpm, log) = tpm_with(vec![correct_responder(vec![0xC9; 32], echo, responder_key)]);
        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let auth = parse_clear_command_auth(&cmd);
        let name = TPM_RH::LOCKOUT.get_value().to_be_bytes().to_vec();
        assert_eq!(
            auth.hmac,
            spec_command_hmac(
                &key,
                TPM_CC::Clear,
                &[name],
                &auth.nonce_caller,
                &[0xBB; 32],
                auth.attributes,
            )
        );
    }
}

/// Round trips against the machine's own TPM, one per session category.
///
/// **These require hardware and are not CI coverage.** They are `#[ignore]`d and only run when
/// asked for by name, for example
/// `cargo test --locked hardware -- --ignored --test-threads=1`.
/// They use the local TBS device, create and flush transient objects under the owner hierarchy,
/// and will fail on a TPM whose owner hierarchy has a non-empty authValue.
///
/// Their purpose is the one thing a mock cannot serve: confirming that the command and response
/// authorization rules in this module agree with a real TPM's, for every session category those
/// rules distinguish between.
#[cfg(all(test, target_os = "windows", feature = "software-crypto"))]
mod hardware_tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use crate::device::TpmTbsDevice;
    use crate::policy::{PolicyAuthValue, PolicyPassword, PolicyPcr, PolicyTree};
    use crate::tpm_type_extensions::TrustedPublic;
    use crate::tpm_types::*;

    const OBJ_AUTH: &[u8] = b"object-auth";

    fn open_tpm() -> Tpm2 {
        let mut tpm = Tpm2::with_software_crypto(Box::new(TpmTbsDevice::new()));
        tpm.connect().expect("no local TPM available");
        tpm
    }

    /// A keyed-hash primary under the owner hierarchy carrying `policy`, with `userWithAuth` so
    /// that the authValue paths are exercised too.
    fn make_primary(tpm: &mut Tpm2, policy: &[u8]) -> Result<TPM_HANDLE, TpmError> {
        let attrs = TPMA_OBJECT::sign
            | TPMA_OBJECT::fixedParent
            | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::userWithAuth;
        let parameters = TPMU_PUBLIC_PARMS::keyedHashDetail(TPMS_KEYEDHASH_PARMS::new(&Some(
            TPMU_SCHEME_KEYEDHASH::hmac(TPMS_SCHEME_HMAC {
                hashAlg: TPM_ALG_ID::SHA256,
            }),
        )));
        let unique = TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH::default());
        let templ = TPMT_PUBLIC::new(
            TPM_ALG_ID::SHA256,
            attrs,
            &policy.to_vec(),
            &Some(parameters),
            &Some(unique),
        );
        let sens = TPMS_SENSITIVE_CREATE::new(&OBJ_AUTH.to_vec(), &vec![5, 4, 3, 2, 1, 0]);
        let resp = tpm.CreatePrimary(
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            &sens,
            &templ,
            &Default::default(),
            &Default::default(),
        )?;
        let mut handle = resp.handle;
        handle.set_auth(OBJ_AUTH);
        Ok(handle)
    }

    /// An RSA storage primary, used where a salt key is needed.
    fn make_storage_primary(tpm: &mut Tpm2) -> Result<TPM_HANDLE, TpmError> {
        let attrs = TPMA_OBJECT::decrypt
            | TPMA_OBJECT::restricted
            | TPMA_OBJECT::fixedParent
            | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::sensitiveDataOrigin
            | TPMA_OBJECT::userWithAuth;
        let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA {
                hashAlg: TPM_ALG_ID::NULL,
            })),
            2048,
            65537,
        ));
        let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());
        let templ = TPMT_PUBLIC::new(
            TPM_ALG_ID::SHA256,
            attrs,
            &Vec::new(),
            &Some(parameters),
            &Some(unique),
        );
        let resp = tpm.CreatePrimary(
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            &TPMS_SENSITIVE_CREATE::new(&Vec::new(), &Vec::new()),
            &templ,
            &Default::default(),
            &Default::default(),
        )?;
        Ok(resp.handle)
    }

    /// The exchange every case below runs: one authorized command, so that both the command and
    /// the response authorization for this session category are exercised end to end.
    fn authorized_round_trip(tpm: &mut Tpm2, handle: &TPM_HANDLE, session: Session) {
        let out = tpm
            .with_session(session)
            .HMAC(handle, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256)
            .expect("authorized command should succeed and its response should verify");
        assert_eq!(out.len(), 32);
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_pwap_session_round_trip() {
        let mut tpm = open_tpm();
        let handle = make_primary(&mut tpm, &[]).unwrap();
        authorized_round_trip(&mut tpm, &handle, Session::pw(Some(OBJ_AUTH.to_vec())));
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_salted_hmac_session_round_trip() {
        let mut tpm = open_tpm();
        let handle = make_primary(&mut tpm, &[]).unwrap();
        let salt_key = make_storage_primary(&mut tpm).unwrap();

        // The salt key is one this process just created, so `assume_trusted` is the honest
        // constructor: there is no channel between us and it for anyone to be in the middle of.
        let public = tpm.ReadPublic(&salt_key).unwrap().outPublic;
        let trusted = TrustedPublic::assume_trusted(public, &SOFTWARE_PROVIDER).unwrap();

        let session = tpm
            .start_salted_auth_session(
                &salt_key,
                &trusted,
                TPM_SE::HMAC,
                TPM_ALG_ID::SHA256,
                TPMA_SESSION::continueSession,
                TPMT_SYM_DEF::default(),
            )
            .unwrap();
        assert!(session.has_secret_key_material());
        let sess_handle = session.sess_in.sessionHandle.clone();
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&salt_key).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_bound_hmac_session_round_trip() {
        let mut tpm = open_tpm();
        let handle = make_primary(&mut tpm, &[]).unwrap();

        let session = tpm
            .start_auth_session_ex(
                None,
                &handle,
                TPM_SE::HMAC,
                TPM_ALG_ID::SHA256,
                TPMA_SESSION::continueSession,
                TPMT_SYM_DEF::default(),
            )
            .unwrap();
        assert!(
            session.has_secret_key_material(),
            "binding to an entity with a non-empty authValue does give the session a secret"
        );
        let sess_handle = session.sess_in.sessionHandle.clone();
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_policy_auth_value_session_round_trip() {
        let mut tpm = open_tpm();
        let tree = PolicyTree::new().add(PolicyAuthValue::new());
        let digest = tree
            .get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
            .unwrap();

        let handle = make_primary(&mut tpm, &digest).unwrap();
        let session = tpm
            .start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)
            .unwrap();
        let sess_handle = session.sess_in.sessionHandle.clone();
        let session = tree.execute(&mut tpm, session).unwrap();
        assert!(session.expects_response_auth());
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_policy_password_session_round_trip() {
        let mut tpm = open_tpm();
        let tree = PolicyTree::new().add(PolicyPassword::new());
        let digest = tree
            .get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
            .unwrap();

        let handle = make_primary(&mut tpm, &digest).unwrap();
        let session = tpm
            .start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)
            .unwrap();
        let sess_handle = session.sess_in.sessionHandle.clone();
        let session = tree.execute(&mut tpm, session).unwrap();
        // The one category that must NOT expect a response authorization.
        assert!(!session.expects_response_auth());
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_policy_pcr_session_round_trip() {
        let mut tpm = open_tpm();
        let selection = TPMS_PCR_SELECTION::new(TPM_ALG_ID::SHA256, &vec![0u8]);
        let read = tpm.PCR_Read(&vec![selection.clone()]).unwrap();

        let tree = PolicyTree::new().add(PolicyPcr::new(read.pcrValues.clone(), vec![selection]));
        let digest = tree
            .get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
            .unwrap();

        let handle = make_primary(&mut tpm, &digest).unwrap();
        let session = tpm
            .start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)
            .unwrap();
        let sess_handle = session.sess_in.sessionHandle.clone();
        let session = tree.execute(&mut tpm, session).unwrap();
        // A policy session with neither PolicyAuthValue nor PolicyPassword: the TPM still
        // authenticates the response, and this client must check it. This is the category the
        // old rule skipped.
        assert!(session.expects_response_auth());
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }
}
