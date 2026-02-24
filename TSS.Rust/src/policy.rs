/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

//! Policy tree infrastructure for declarative TPM 2.0 policy composition.
//!
//! This module provides a `PolicyTree` that lets you compose policy assertions
//! (e.g., PolicyLocality, PolicyCommandCode, PolicyPCR, PolicyOR, etc.) into
//! a tree. The tree can then compute a policy digest (trial) or be executed
//! against a real policy session on the TPM.

use crate::auth_session::Session;
use crate::crypto::Crypto;
use crate::error::TpmError;
use crate::tpm2_impl::Tpm2;
use crate::tpm_buffer::{TpmBuffer, TpmMarshaller};
use crate::tpm_structure::TpmEnum;
use crate::tpm_types::*;

// ---------------------------------------------------------------------------
// PolicyAssertion trait - base for all policy nodes
// ---------------------------------------------------------------------------

/// Trait implemented by all policy assertion types.
pub trait PolicyAssertion {
    /// Update a policy digest accumulator (used for trial/software digest computation).
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, accumulator: &mut Vec<u8>) -> Result<(), TpmError>;

    /// Execute this policy assertion against a live TPM policy session.
    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError>;
}

// ---------------------------------------------------------------------------
// Helper: PolicyUpdate - shared digest update logic per TPM spec
// ---------------------------------------------------------------------------

/// `policyDigest = H(policyDigest || commandCode || arg2)`
/// Then: `policyDigest = H(policyDigest || arg3)`
fn policy_update(
    hash_alg: TPM_ALG_ID,
    accumulator: &mut Vec<u8>,
    command_code: TPM_CC,
    arg2: &[u8],
    arg3: &[u8],
) -> Result<(), TpmError> {
    // First extend: H(accumulator || CC || arg2)
    let mut buf = Vec::new();
    buf.extend_from_slice(accumulator);
    buf.extend_from_slice(&command_code.get_value().to_be_bytes());
    buf.extend_from_slice(arg2);
    *accumulator = Crypto::hash(hash_alg, &buf)?;

    // Second extend (if arg3 is non-empty): H(accumulator || arg3)
    if !arg3.is_empty() {
        let mut buf2 = Vec::new();
        buf2.extend_from_slice(accumulator);
        buf2.extend_from_slice(arg3);
        *accumulator = Crypto::hash(hash_alg, &buf2)?;
    }
    Ok(())
}

/// Helper to get session handle from a Session
fn sess_handle(s: &Session) -> TPM_HANDLE {
    s.sess_in.sessionHandle.clone()
}

// ---------------------------------------------------------------------------
// PolicyTree
// ---------------------------------------------------------------------------

/// A composable policy tree that can compute digests and execute against the TPM.
pub struct PolicyTree {
    assertions: Vec<Box<dyn PolicyAssertion>>,
}

impl PolicyTree {
    /// Create an empty policy tree.
    pub fn new() -> Self {
        Self { assertions: Vec::new() }
    }

    /// Add a policy assertion to the tree. Assertions execute in order (first added = first executed).
    pub fn add(mut self, assertion: impl PolicyAssertion + 'static) -> Self {
        self.assertions.push(Box::new(assertion));
        self
    }

    /// Compute the policy digest in software (equivalent to a trial session).
    pub fn get_policy_digest(&self, hash_alg: TPM_ALG_ID) -> Result<Vec<u8>, TpmError> {
        compute_digest(&self.assertions, hash_alg)
    }

    /// Execute all assertions in order against a live policy session.
    /// Returns the updated session (with rolled nonces).
    pub fn execute(&self, tpm: &mut Tpm2, session: Session) -> Result<Session, TpmError> {
        let mut sess = session;
        for assertion in &self.assertions {
            sess = assertion.execute(tpm, &sess)?;
        }
        Ok(sess)
    }
}

/// Compute the digest for a slice of assertions (used by PolicyTree and PolicyOr).
pub(crate) fn compute_digest(
    assertions: &[Box<dyn PolicyAssertion>],
    hash_alg: TPM_ALG_ID,
) -> Result<Vec<u8>, TpmError> {
    let hash_len = Crypto::hash(hash_alg, &[])?.len();
    let mut accumulator = vec![0u8; hash_len];
    for assertion in assertions {
        assertion.update_policy_digest(hash_alg, &mut accumulator)?;
    }
    Ok(accumulator)
}

// ---------------------------------------------------------------------------
// Concrete policy assertion types
// ---------------------------------------------------------------------------

/// PolicyCommandCode - limits the authorized action to a specific command.
pub struct PolicyCommandCode {
    pub command_code: TPM_CC,
}

impl PolicyCommandCode {
    pub fn new(command_code: TPM_CC) -> Self {
        Self { command_code }
    }
}

impl PolicyAssertion for PolicyCommandCode {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.command_code.get_value().to_be_bytes());
        policy_update(hash_alg, acc, TPM_CC::PolicyCommandCode, &buf, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyCommandCode(&sess_handle(session), self.command_code)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyLocality - limits authorization to a specific locality.
pub struct PolicyLocality {
    pub locality: TPMA_LOCALITY,
}

impl PolicyLocality {
    pub fn new(locality: TPMA_LOCALITY) -> Self {
        Self { locality }
    }
}

impl PolicyAssertion for PolicyLocality {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        // PolicyLocality: H(acc || TPM_CC_PolicyLocality || locality_byte)
        let mut buf = Vec::new();
        buf.extend_from_slice(acc);
        buf.extend_from_slice(&TPM_CC::PolicyLocality.get_value().to_be_bytes());
        buf.push(self.locality.get_value() as u8);
        *acc = Crypto::hash(hash_alg, &buf)?;
        Ok(())
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyLocality(&sess_handle(session), self.locality)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyPCR - gates policy on PCR values.
pub struct PolicyPcr {
    pub pcr_values: Vec<TPM2B_DIGEST>,
    pub pcr_selections: Vec<TPMS_PCR_SELECTION>,
}

impl PolicyPcr {
    pub fn new(pcr_values: Vec<TPM2B_DIGEST>, pcr_selections: Vec<TPMS_PCR_SELECTION>) -> Self {
        Self { pcr_values, pcr_selections }
    }
}

impl PolicyAssertion for PolicyPcr {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        // Concatenate all PCR values and hash them
        let mut pcr_data = Vec::new();
        for v in &self.pcr_values {
            pcr_data.extend_from_slice(&v.buffer);
        }
        let pcr_digest = Crypto::hash(hash_alg, &pcr_data)?;

        // Marshal PCR selections
        let mut sel_buf = TpmBuffer::new(None);
        sel_buf.writeInt(self.pcr_selections.len() as u32);
        for sel in &self.pcr_selections {
            sel.toTpm(&mut sel_buf)?;
        }

        let mut arg2 = Vec::new();
        arg2.extend_from_slice(sel_buf.trim());
        arg2.extend_from_slice(&pcr_digest);
        policy_update(hash_alg, acc, TPM_CC::PolicyPCR, &arg2, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyPCR(&sess_handle(session), &self.pcr_values[0].buffer, &self.pcr_selections)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyPassword - requires the object's authorization value be provided as a password.
pub struct PolicyPassword;

impl PolicyPassword {
    pub fn new() -> Self { Self }
}

impl PolicyAssertion for PolicyPassword {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        // PolicyPassword uses the same digest as PolicyAuthValue per spec
        policy_update(hash_alg, acc, TPM_CC::PolicyAuthValue, &[], &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyPassword(&sess_handle(session))?;
        let mut sess = tpm.last_session().unwrap_or_else(|| session.clone());
        sess.needs_password = true;
        Ok(sess)
    }
}

/// PolicyAuthValue - requires auth-value HMAC during policy use.
pub struct PolicyAuthValue;

impl PolicyAuthValue {
    pub fn new() -> Self { Self }
}

impl PolicyAssertion for PolicyAuthValue {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        policy_update(hash_alg, acc, TPM_CC::PolicyAuthValue, &[], &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyAuthValue(&sess_handle(session))?;
        let mut sess = tpm.last_session().unwrap_or_else(|| session.clone());
        sess.needs_hmac = true;
        Ok(sess)
    }
}

/// PolicyCpHash - binds policy to specific command parameters.
pub struct PolicyCpHash {
    pub cp_hash: Vec<u8>,
}

impl PolicyCpHash {
    pub fn new(cp_hash: Vec<u8>) -> Self {
        Self { cp_hash }
    }
}

impl PolicyAssertion for PolicyCpHash {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        policy_update(hash_alg, acc, TPM_CC::PolicyCpHash, &self.cp_hash, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyCpHash(&sess_handle(session), &self.cp_hash)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyNameHash - binds policy to specific object handles.
pub struct PolicyNameHash {
    pub name_hash: Vec<u8>,
}

impl PolicyNameHash {
    pub fn new(name_hash: Vec<u8>) -> Self {
        Self { name_hash }
    }
}

impl PolicyAssertion for PolicyNameHash {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        policy_update(hash_alg, acc, TPM_CC::PolicyNameHash, &self.name_hash, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyNameHash(&sess_handle(session), &self.name_hash)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyCounterTimer - gates policy on TPMS_TIME_INFO contents.
pub struct PolicyCounterTimer {
    pub operand_b: Vec<u8>,
    pub offset: u16,
    pub operation: TPM_EO,
}

impl PolicyCounterTimer {
    pub fn new(operand_b: Vec<u8>, offset: u16, operation: TPM_EO) -> Self {
        Self { operand_b, offset, operation }
    }

    /// Convenience: create from a u64 value (marshalled as 8 big-endian bytes).
    pub fn from_u64(value: u64, offset: u16, operation: TPM_EO) -> Self {
        Self { operand_b: value.to_be_bytes().to_vec(), offset, operation }
    }
}

impl PolicyAssertion for PolicyCounterTimer {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        // arg2 = H(operandB || offset || operation)
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.operand_b);
        inner.extend_from_slice(&self.offset.to_be_bytes());
        inner.extend_from_slice(&(self.operation.get_value() as u16).to_be_bytes());
        let arg_hash = Crypto::hash(hash_alg, &inner)?;
        policy_update(hash_alg, acc, TPM_CC::PolicyCounterTimer, &arg_hash, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyCounterTimer(
            &sess_handle(session), &self.operand_b, self.offset, self.operation,
        )?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicySecret - secret-based authorization (proves knowledge of an auth value).
pub struct PolicySecret {
    pub auth_object_name: Vec<u8>,
    pub policy_ref: Vec<u8>,
    pub cp_hash_a: Vec<u8>,
    pub expiration: i32,
    pub include_tpm_nonce: bool,
    /// The handle used during execution (set before calling execute).
    pub auth_handle: TPM_HANDLE,
}

impl PolicySecret {
    pub fn new(auth_object_name: Vec<u8>, auth_handle: TPM_HANDLE) -> Self {
        Self {
            auth_object_name,
            policy_ref: vec![],
            cp_hash_a: vec![],
            expiration: 0,
            include_tpm_nonce: false,
            auth_handle,
        }
    }
}

impl PolicyAssertion for PolicySecret {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        policy_update(hash_alg, acc, TPM_CC::PolicySecret, &self.auth_object_name, &self.policy_ref)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        let nonce_tpm = if self.include_tpm_nonce {
            session.sess_out.nonce.clone()
        } else {
            vec![]
        };
        tpm.PolicySecret(
            &self.auth_handle, &sess_handle(session),
            &nonce_tpm, &self.cp_hash_a, &self.policy_ref, self.expiration,
        )?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicySigned - asymmetrically signed authorization.
pub struct PolicySigned {
    pub include_tpm_nonce: bool,
    pub cp_hash_a: Vec<u8>,
    pub policy_ref: Vec<u8>,
    pub expiration: i32,
    pub public_key: TPMT_PUBLIC,
    /// If set, the library will sign automatically. Otherwise a callback is needed.
    pub sw_key: Option<TSS_KEY>,
}

impl PolicySigned {
    pub fn new(public_key: TPMT_PUBLIC) -> Self {
        Self {
            include_tpm_nonce: false,
            cp_hash_a: vec![],
            policy_ref: vec![],
            expiration: 0,
            public_key,
            sw_key: None,
        }
    }

    /// Provide a software key so the library can sign automatically.
    pub fn with_key(mut self, key: TSS_KEY) -> Self {
        self.sw_key = Some(key);
        self
    }

    pub fn with_nonce(mut self) -> Self {
        self.include_tpm_nonce = true;
        self
    }
}

impl PolicyAssertion for PolicySigned {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        let key_name = self.public_key.get_name()?;
        policy_update(hash_alg, acc, TPM_CC::PolicySigned, &key_name, &self.policy_ref)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        let nonce_tpm = if self.include_tpm_nonce {
            session.sess_out.nonce.clone()
        } else {
            vec![]
        };

        // Determine hash alg from the key's scheme
        let hash_alg = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(ref params)) = self.public_key.parameters {
            if let Some(TPMU_ASYM_SCHEME::rsassa(ref scheme)) = params.scheme {
                scheme.hashAlg
            } else {
                self.public_key.nameAlg
            }
        } else {
            self.public_key.nameAlg
        };

        // Compute aHash = Hash(nonceTPM || expiration || cpHashA || policyRef)
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&nonce_tpm);
        to_hash.extend_from_slice(&self.expiration.to_be_bytes());
        to_hash.extend_from_slice(&self.cp_hash_a);
        to_hash.extend_from_slice(&self.policy_ref);
        let a_hash = Crypto::hash(hash_alg, &to_hash)?;

        let sw_key = self.sw_key.as_ref().ok_or_else(|| {
            TpmError::GenericError("PolicySigned: no SW key set (callbacks not yet supported)".into())
        })?;
        let signature = sw_key.sign(&a_hash, hash_alg)?;

        // Load the public key into the TPM
        let pub_key_handle = tpm.LoadExternal(
            &TPMT_SENSITIVE::default(),
            &self.public_key,
            &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        )?;

        let result = tpm.PolicySigned(
            &pub_key_handle, &sess_handle(session),
            &nonce_tpm, &self.cp_hash_a, &self.policy_ref, self.expiration,
            &signature.signature,
        );

        tpm.FlushContext(&pub_key_handle)?;
        result?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyNV - conditional gating based on NV Index contents.
pub struct PolicyNv {
    pub operand_b: Vec<u8>,
    pub offset: u16,
    pub operation: TPM_EO,
    pub nv_index_name: Vec<u8>,
    pub auth_handle: TPM_HANDLE,
    pub nv_index: TPM_HANDLE,
}

impl PolicyNv {
    pub fn new(
        auth_handle: TPM_HANDLE,
        nv_index: TPM_HANDLE,
        nv_index_name: Vec<u8>,
        operand_b: Vec<u8>,
        offset: u16,
        operation: TPM_EO,
    ) -> Self {
        Self { operand_b, offset, operation, nv_index_name, auth_handle, nv_index }
    }
}

impl PolicyAssertion for PolicyNv {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        // arg2 = H(operandB || offset || operation)
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.operand_b);
        inner.extend_from_slice(&self.offset.to_be_bytes());
        inner.extend_from_slice(&(self.operation.get_value() as u16).to_be_bytes());
        let args_hash = Crypto::hash(hash_alg, &inner)?;
        policy_update(hash_alg, acc, TPM_CC::PolicyNV, &args_hash, &self.nv_index_name)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyNV(
            &self.auth_handle, &self.nv_index, &sess_handle(session),
            &self.operand_b, self.offset, self.operation,
        )?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyOR - allows one of several policy branches to satisfy the policy.
pub struct PolicyOr {
    pub branches: Vec<Vec<Box<dyn PolicyAssertion>>>,
}

impl PolicyOr {
    /// Create from pre-built branches (each branch is a Vec of boxed assertions).
    pub fn new(branches: Vec<Vec<Box<dyn PolicyAssertion>>>) -> Self {
        Self { branches }
    }

    /// Convenience: create a two-branch PolicyOR from PolicyTrees.
    pub fn from_trees(trees: Vec<PolicyTree>) -> Self {
        let branches = trees.into_iter()
            .map(|t| t.assertions)
            .collect();
        Self { branches }
    }
}

impl PolicyAssertion for PolicyOr {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        // PolicyOR: accumulator = H(0...0 || TPM_CC_PolicyOR || digest1 || digest2 || ...)
        let hash_len = Crypto::hash(hash_alg, &[])?.len();
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0u8; hash_len]); // reset to zero
        buf.extend_from_slice(&TPM_CC::PolicyOR.get_value().to_be_bytes());
        for branch in &self.branches {
            let branch_digest = compute_digest(branch, hash_alg)?;
            buf.extend_from_slice(&branch_digest);
        }
        *acc = Crypto::hash(hash_alg, &buf)?;
        Ok(())
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        let hash_alg = session.get_hash_alg();
        let mut hash_list: Vec<TPM2B_DIGEST> = Vec::new();
        for branch in &self.branches {
            let digest = compute_digest(branch, hash_alg)?;
            hash_list.push(TPM2B_DIGEST { buffer: digest });
        }
        tpm.PolicyOR(&sess_handle(session), &hash_list)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyAuthorize - transforms a policy digest using a signing key's authorization.
pub struct PolicyAuthorize {
    pub approved_policy: Vec<u8>,
    pub policy_ref: Vec<u8>,
    pub authorizing_key: TPMT_PUBLIC,
    pub signature: TPMT_SIGNATURE,
}

impl PolicyAuthorize {
    pub fn new(
        approved_policy: Vec<u8>,
        policy_ref: Vec<u8>,
        authorizing_key: TPMT_PUBLIC,
        signature: TPMT_SIGNATURE,
    ) -> Self {
        Self { approved_policy, policy_ref, authorizing_key, signature }
    }
}

impl PolicyAssertion for PolicyAuthorize {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        let key_name = self.authorizing_key.get_name()?;
        // PolicyAuthorize resets the digest, then does PolicyUpdate
        let hash_len = Crypto::hash(hash_alg, &[])?.len();
        *acc = vec![0u8; hash_len];
        policy_update(hash_alg, acc, TPM_CC::PolicyAuthorize, &key_name, &self.policy_ref)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        let key_name = self.authorizing_key.get_name()?;

        // Load the authorizing key
        let key_handle = tpm.LoadExternal(
            &TPMT_SENSITIVE::default(),
            &self.authorizing_key,
            &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        )?;

        // Compute aHash and get a verification ticket
        let mut a_hash_data = Vec::new();
        a_hash_data.extend_from_slice(&self.approved_policy);
        a_hash_data.extend_from_slice(&self.policy_ref);
        let a_hash = Crypto::hash(self.authorizing_key.nameAlg, &a_hash_data)?;

        let check_ticket = tpm.VerifySignature(
            &key_handle, &a_hash, &self.signature.signature,
        )?;

        let result = tpm.PolicyAuthorize(
            &sess_handle(session),
            &self.approved_policy,
            &self.policy_ref,
            &key_name,
            &check_ticket,
        );

        tpm.FlushContext(&key_handle)?;
        result?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyDuplicationSelect - qualifies duplication to a selected new parent.
pub struct PolicyDuplicationSelect {
    pub object_name: Vec<u8>,
    pub new_parent_name: Vec<u8>,
    pub include_object: bool,
}

impl PolicyDuplicationSelect {
    pub fn new(object_name: Vec<u8>, new_parent_name: Vec<u8>, include_object: bool) -> Self {
        Self { object_name, new_parent_name, include_object }
    }
}

impl PolicyAssertion for PolicyDuplicationSelect {
    fn update_policy_digest(&self, hash_alg: TPM_ALG_ID, acc: &mut Vec<u8>) -> Result<(), TpmError> {
        let mut arg2 = Vec::new();
        if self.include_object {
            arg2.extend_from_slice(&self.object_name);
        }
        arg2.extend_from_slice(&self.new_parent_name);
        arg2.push(if self.include_object { 1 } else { 0 });
        policy_update(hash_alg, acc, TPM_CC::PolicyDuplicationSelect, &arg2, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyDuplicationSelect(
            &sess_handle(session),
            &self.object_name,
            &self.new_parent_name,
            if self.include_object { 1 } else { 0 },
        )?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}
