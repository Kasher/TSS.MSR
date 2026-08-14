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
use crate::crypto::{provider::CryptoProvider, Crypto};
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        accumulator: &mut Vec<u8>,
    ) -> Result<(), TpmError>;

    /// Execute this policy assertion against a live TPM policy session.
    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError>;
}

// ---------------------------------------------------------------------------
// Helper: PolicyUpdate - shared digest update logic per TPM spec
// ---------------------------------------------------------------------------

/// One `TPM_HASH::Extend`: `policyDigest = H(policyDigest || data)`.
fn policy_extend(
    crypto: &CryptoProvider,
    hash_alg: TPM_ALG_ID,
    accumulator: &mut Vec<u8>,
    data: &[u8],
) -> Result<(), TpmError> {
    let mut buf = Vec::with_capacity(accumulator.len() + data.len());
    buf.extend_from_slice(accumulator);
    buf.extend_from_slice(data);
    *accumulator = Crypto::hash(crypto, hash_alg, &buf)?;
    Ok(())
}

/// A **single-extend** policy digest update: `policyDigest = H(policyDigest || commandCode || arg2)`.
///
/// This — not [`policy_update`] — is the shape of *most* policy assertions. In
/// `TSS.CPP/Src/TpmPolicy.cpp` these are the `UpdatePolicyDigest` bodies that build a
/// `TpmBuffer` and end in exactly one `accumulator.Extend(buf.trim())`; in
/// `TSS.NET/TSS.Net/PolicyAces.cs` they are the ones ending in a single `.Extend(...)`, of
/// which this function is the direct analogue of `PolicyAce.PolicyUpdate1`.
///
/// Assertions that use this shape: `TPM2_PolicyCommandCode`, `TPM2_PolicyPCR`,
/// `TPM2_PolicyAuthValue`, `TPM2_PolicyPassword`, `TPM2_PolicyCpHash`,
/// `TPM2_PolicyNameHash`, `TPM2_PolicyCounterTimer`, `TPM2_PolicyLocality`,
/// `TPM2_PolicyDuplicationSelect`, `TPM2_PolicyNV` and `TPM2_PolicyOR` (the last two after a
/// reset of the accumulator).
///
/// Routing one of these through [`policy_update`] instead adds a second extend over an empty
/// `arg3` and produces a digest no policy session can ever satisfy.
fn policy_update1(
    crypto: &CryptoProvider,
    hash_alg: TPM_ALG_ID,
    accumulator: &mut Vec<u8>,
    command_code: TPM_CC,
    arg2: &[u8],
) -> Result<(), TpmError> {
    let mut buf = Vec::with_capacity(4 + arg2.len());
    buf.extend_from_slice(&command_code.get_value().to_be_bytes());
    buf.extend_from_slice(arg2);
    policy_extend(crypto, hash_alg, accumulator, &buf)
}

/// The TPM 2.0 `PolicyUpdate()` function (Part 1, "Policy Digest Update Function").
///
/// `policyDigest = H(policyDigest || commandCode || arg2)`
/// Then: `policyDigest = H(policyDigest || arg3)`
///
/// Both extends are unconditional. The second one is *not* skipped when `arg3` is empty: an
/// empty `policyRef` is the common case for `TPM2_PolicySigned`, `TPM2_PolicySecret` and
/// `TPM2_PolicyAuthorize`, and the TPM still performs the extend for it, producing
/// `H(policyDigest)` rather than leaving the digest alone. Skipping it yields a digest no
/// policy session can ever satisfy. `TSS.CPP/Src/TpmPolicy.cpp` (`PABase::PolicyUpdate`) and
/// `TSS.NET/TSS.Net/PolicyAces.cs` (`PolicyAce.PolicyUpdate`) both extend unconditionally.
///
/// **Only four assertions are built on this function**, and they are exactly the four whose
/// `UpdatePolicyDigest` in `TSS.CPP/Src/TpmPolicy.cpp` calls `PABase::PolicyUpdate`:
/// `TPM2_PolicySigned`, `TPM2_PolicySecret`, `TPM2_PolicyAuthorize` (after a reset) and
/// `TPM2_PolicyTicket` (not implemented here). Every other assertion is a single extend —
/// use [`policy_update1`].
fn policy_update(
    crypto: &CryptoProvider,
    hash_alg: TPM_ALG_ID,
    accumulator: &mut Vec<u8>,
    command_code: TPM_CC,
    arg2: &[u8],
    arg3: &[u8],
) -> Result<(), TpmError> {
    policy_update1(crypto, hash_alg, accumulator, command_code, arg2)?;
    policy_extend(crypto, hash_alg, accumulator, arg3)
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

impl Default for PolicyTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyTree {
    /// Create an empty policy tree.
    pub fn new() -> Self {
        Self {
            assertions: Vec::new(),
        }
    }

    /// Add a policy assertion to the tree. Assertions execute in order (first added = first executed).
    // This is a consuming builder method, not arithmetic - `std::ops::Add` is the wrong shape for it.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, assertion: impl PolicyAssertion + 'static) -> Self {
        self.assertions.push(Box::new(assertion));
        self
    }

    /// Compute the policy digest in software (equivalent to a trial session).
    pub fn get_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
    ) -> Result<Vec<u8>, TpmError> {
        compute_digest(crypto, &self.assertions, hash_alg)
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
    crypto: &CryptoProvider,
    assertions: &[Box<dyn PolicyAssertion>],
    hash_alg: TPM_ALG_ID,
) -> Result<Vec<u8>, TpmError> {
    let hash_len = Crypto::digest_size_checked(hash_alg)?;
    let mut accumulator = vec![0u8; hash_len];
    for assertion in assertions {
        assertion.update_policy_digest(crypto, hash_alg, &mut accumulator)?;
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyCommandCode::UpdatePolicyDigest` (TpmPolicy.cpp:333) is a *single* extend:
        //     H(policyDigest || TPM_CC_PolicyCommandCode || commandCode)
        // It does not go through `PABase::PolicyUpdate`.
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.command_code.get_value().to_be_bytes());
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyCommandCode, &buf)
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyLocality::UpdatePolicyDigest` (TpmPolicy.cpp:239) is a single extend:
        //     H(policyDigest || TPM_CC_PolicyLocality || locality)
        // `TPMA_LOCALITY` is one byte on the wire.
        policy_update1(
            crypto,
            hash_alg,
            acc,
            TPM_CC::PolicyLocality,
            &[self.locality.get_value()],
        )
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
        Self {
            pcr_values,
            pcr_selections,
        }
    }

    /// The `pcrDigest` this assertion asserts: `H(pcrValue[0] || pcrValue[1] || ...)`.
    ///
    /// This is the value that goes into the policy digest *and* the value sent as the
    /// `pcrDigest` argument of `TPM2_PolicyPCR`; the two must be the same digest or the session
    /// cannot satisfy the policy. It mirrors `Helpers::HashPcrs` in
    /// `TSS.CPP/Src/TpmHelpers.cpp` and `PcrValueCollection.GetSelectionHash` in TSS.NET.
    ///
    /// An empty `pcr_values` is rejected rather than hashed. The TPM treats an *empty*
    /// `pcrDigest` as "do not compare the PCRs at all", so a caller that supplied no expected
    /// values has almost certainly made a mistake, and quietly turning that into a digest over
    /// no data would hide it.
    pub fn pcr_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
    ) -> Result<Vec<u8>, TpmError> {
        if self.pcr_values.is_empty() {
            return Err(TpmError::InvalidParameter);
        }

        let mut pcr_data = Vec::new();
        for v in &self.pcr_values {
            pcr_data.extend_from_slice(&v.buffer);
        }
        Crypto::hash(crypto, hash_alg, &pcr_data)
    }
}

impl PolicyAssertion for PolicyPcr {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        let pcr_digest = self.pcr_digest(crypto, hash_alg)?;

        // Marshal PCR selections
        let mut sel_buf = TpmBuffer::new(None);
        sel_buf.writeInt(self.pcr_selections.len() as u32);
        for sel in &self.pcr_selections {
            sel.toTpm(&mut sel_buf)?;
        }

        let mut arg2 = Vec::new();
        arg2.extend_from_slice(sel_buf.trim());
        arg2.extend_from_slice(&pcr_digest);
        // `PolicyPcr::UpdatePolicyDigest` (TpmPolicy.cpp:312) is a *single* extend:
        //     H(policyDigest || TPM_CC_PolicyPCR || count || selections || pcrDigest)
        // It does not go through `PABase::PolicyUpdate`.
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyPCR, &arg2)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        // The same digest that went into the policy digest, not the first raw PCR value.
        // `pcr_digest` also rejects an empty `pcr_values`, which both keeps this off the
        // panicking `self.pcr_values[0]` path and makes it impossible to send the empty
        // `pcrDigest` that tells the TPM to skip the PCR comparison entirely.
        let pcr_digest = self.pcr_digest(tpm.crypto(), session.get_hash_alg())?;
        tpm.PolicyPCR(&sess_handle(session), &pcr_digest, &self.pcr_selections)?;
        Ok(tpm.last_session().unwrap_or_else(|| session.clone()))
    }
}

/// PolicyPassword - requires the object's authorization value be provided as a password.
pub struct PolicyPassword;

impl Default for PolicyPassword {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyPassword {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyAssertion for PolicyPassword {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyPassword::UpdatePolicyDigest` (TpmPolicy.cpp:425) is a single extend of the
        // *PolicyAuthValue* command code and nothing else — identical to PolicyAuthValue, so
        // that a policy can be satisfied either way. No `PABase::PolicyUpdate`.
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyAuthValue, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyPassword(&sess_handle(session))?;
        let mut sess = tpm.last_session().unwrap_or_else(|| session.clone());
        // TPM2_PolicyPassword SETs isPasswordNeeded and CLEARs isAuthValueNeeded; mirror both,
        // because the two flags select different authorization encodings and the TPM will only
        // honour the one it last recorded.
        sess.needs_password = true;
        sess.needs_hmac = false;
        Ok(sess)
    }
}

/// PolicyAuthValue - requires auth-value HMAC during policy use.
pub struct PolicyAuthValue;

impl Default for PolicyAuthValue {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyAuthValue {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyAssertion for PolicyAuthValue {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyAuthValue::UpdatePolicyDigest` (TpmPolicy.cpp:411) is the whole function:
        //     accumulator.Extend(Int32ToTpm(TPM_CC::PolicyAuthValue));
        // A single extend of the command code, with no second extend.
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyAuthValue, &[])
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyAuthValue(&sess_handle(session))?;
        let mut sess = tpm.last_session().unwrap_or_else(|| session.clone());
        // TPM2_PolicyAuthValue SETs isAuthValueNeeded and CLEARs isPasswordNeeded.
        sess.needs_hmac = true;
        sess.needs_password = false;
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyCpHash::UpdatePolicyDigest` (TpmPolicy.cpp:349) is a single extend:
        //     H(policyDigest || TPM_CC_PolicyCpHash || cpHashA)
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyCpHash, &self.cp_hash)
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyNameHash::UpdatePolicyDigest` (TpmPolicy.cpp:395) is a single extend:
        //     H(policyDigest || TPM_CC_PolicyNameHash || nameHash)
        policy_update1(
            crypto,
            hash_alg,
            acc,
            TPM_CC::PolicyNameHash,
            &self.name_hash,
        )
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
        Self {
            operand_b,
            offset,
            operation,
        }
    }

    /// Convenience: create from a u64 value (marshalled as 8 big-endian bytes).
    pub fn from_u64(value: u64, offset: u16, operation: TPM_EO) -> Self {
        Self {
            operand_b: value.to_be_bytes().to_vec(),
            offset,
            operation,
        }
    }
}

impl PolicyAssertion for PolicyCounterTimer {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // arg2 = H(operandB || offset || operation)
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.operand_b);
        inner.extend_from_slice(&self.offset.to_be_bytes());
        inner.extend_from_slice(&self.operation.get_value().to_be_bytes());
        let arg_hash = Crypto::hash(crypto, hash_alg, &inner)?;
        // `PolicyCounterTimer::UpdatePolicyDigest` (TpmPolicy.cpp:379) is a single extend:
        //     H(policyDigest || TPM_CC_PolicyCounterTimer || H(operandB || offset || operation))
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyCounterTimer, &arg_hash)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyCounterTimer(
            &sess_handle(session),
            &self.operand_b,
            self.offset,
            self.operation,
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicySecret` is one of the assertions genuinely built on `PABase::PolicyUpdate`
        // (TpmPolicy.cpp:226) — two extends, the second over `policyRef`.
        policy_update(
            crypto,
            hash_alg,
            acc,
            TPM_CC::PolicySecret,
            &self.auth_object_name,
            &self.policy_ref,
        )
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        let nonce_tpm = if self.include_tpm_nonce {
            session.sess_out.nonce.clone()
        } else {
            vec![]
        };
        tpm.PolicySecret(
            &self.auth_handle,
            &sess_handle(session),
            &nonce_tpm,
            &self.cp_hash_a,
            &self.policy_ref,
            self.expiration,
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
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        let key_name = self.public_key.get_name(crypto)?;
        // `PolicySigned::UpdatePolicyDigest` (TpmPolicy.cpp:462) calls `PABase::PolicyUpdate`,
        // so this is genuinely a two-extend assertion.
        policy_update(
            crypto,
            hash_alg,
            acc,
            TPM_CC::PolicySigned,
            &key_name,
            &self.policy_ref,
        )
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        // Copied out because `tpm` is borrowed mutably by the command calls below.
        let crypto = *tpm.crypto();
        let nonce_tpm = if self.include_tpm_nonce {
            session.sess_out.nonce.clone()
        } else {
            vec![]
        };

        // Determine hash alg from the key's scheme
        let hash_alg =
            if let Some(TPMU_PUBLIC_PARMS::rsaDetail(ref params)) = self.public_key.parameters {
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
        let a_hash = Crypto::hash(&crypto, hash_alg, &to_hash)?;

        let sw_key = self.sw_key.as_ref().ok_or_else(|| {
            TpmError::GenericError(
                "PolicySigned: no SW key set (callbacks not yet supported)".into(),
            )
        })?;
        let signature = sw_key.sign(&crypto, &a_hash, hash_alg)?;

        // Load the public key into the TPM (OWNER hierarchy for valid tickets)
        let pub_key_handle = tpm.LoadExternal(
            &TPMT_SENSITIVE::default(),
            &self.public_key,
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        )?;

        let result = tpm.PolicySigned(
            &pub_key_handle,
            &sess_handle(session),
            &nonce_tpm,
            &self.cp_hash_a,
            &self.policy_ref,
            self.expiration,
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
        Self {
            operand_b,
            offset,
            operation,
            nv_index_name,
            auth_handle,
            nv_index,
        }
    }
}

impl PolicyAssertion for PolicyNv {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyNV::UpdatePolicyDigest` (TpmPolicy.cpp:439) is a single extend, with the
        // Name folded into the same extend rather than into a second one:
        //
        //   policyDigest := H(policyDigest || TPM_CC_PolicyNV || args || nvIndex.Name)
        //   where args    = H(operandB || offset || operation)
        //
        // Delegating to `policy_update` with the Name as `arg3` would produce two extends and
        // a digest no session can satisfy. `TpmPolicyNV.GetPolicyDigest` in
        // `TSS.NET/TSS.Net/PolicyAces.cs` extends once as well.
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.operand_b);
        inner.extend_from_slice(&self.offset.to_be_bytes());
        inner.extend_from_slice(&self.operation.get_value().to_be_bytes());
        let args_hash = Crypto::hash(crypto, hash_alg, &inner)?;

        let mut arg2 = Vec::new();
        arg2.extend_from_slice(&args_hash);
        arg2.extend_from_slice(&self.nv_index_name);
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyNV, &arg2)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        tpm.PolicyNV(
            &self.auth_handle,
            &self.nv_index,
            &sess_handle(session),
            &self.operand_b,
            self.offset,
            self.operation,
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
        let branches = trees.into_iter().map(|t| t.assertions).collect();
        Self { branches }
    }
}

impl PolicyAssertion for PolicyOr {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        // `PolicyOr::UpdatePolicyDigest` (TpmPolicy.cpp:268) resets the accumulator and then
        // performs a single extend:
        //     policyDigest := 0...0
        //     policyDigest := H(policyDigest || TPM_CC_PolicyOR || digest1 || digest2 || ...)
        let hash_len = Crypto::digest_size_checked(hash_alg)?;
        let mut arg2 = Vec::new();
        for branch in &self.branches {
            let branch_digest = compute_digest(crypto, branch, hash_alg)?;
            arg2.extend_from_slice(&branch_digest);
        }
        *acc = vec![0u8; hash_len];
        policy_update1(crypto, hash_alg, acc, TPM_CC::PolicyOR, &arg2)
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        // Copied out because `tpm` is borrowed mutably by the command calls below.
        let crypto = *tpm.crypto();
        let hash_alg = session.get_hash_alg();
        let mut hash_list: Vec<TPM2B_DIGEST> = Vec::new();
        for branch in &self.branches {
            let digest = compute_digest(&crypto, branch, hash_alg)?;
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
        Self {
            approved_policy,
            policy_ref,
            authorizing_key,
            signature,
        }
    }
}

impl PolicyAssertion for PolicyAuthorize {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        let key_name = self.authorizing_key.get_name(crypto)?;
        // `PolicyAuthorize::UpdatePolicyDigest` (TpmPolicy.cpp:509) resets the accumulator and
        // then calls `PABase::PolicyUpdate`, so this is a reset plus two extends.
        let hash_len = Crypto::digest_size_checked(hash_alg)?;
        *acc = vec![0u8; hash_len];
        policy_update(
            crypto,
            hash_alg,
            acc,
            TPM_CC::PolicyAuthorize,
            &key_name,
            &self.policy_ref,
        )
    }

    fn execute(&self, tpm: &mut Tpm2, session: &Session) -> Result<Session, TpmError> {
        // Copied out because `tpm` is borrowed mutably by the command calls below.
        let crypto = *tpm.crypto();
        let key_name = self.authorizing_key.get_name(&crypto)?;

        // Load the authorizing key (OWNER hierarchy for valid tickets)
        let key_handle = tpm.LoadExternal(
            &TPMT_SENSITIVE::default(),
            &self.authorizing_key,
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
        )?;

        // Compute aHash and get a verification ticket
        let mut a_hash_data = Vec::new();
        a_hash_data.extend_from_slice(&self.approved_policy);
        a_hash_data.extend_from_slice(&self.policy_ref);
        let a_hash = Crypto::hash(&crypto, self.authorizing_key.nameAlg, &a_hash_data)?;

        let check_ticket = tpm.VerifySignature(&key_handle, &a_hash, &self.signature.signature)?;

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
        Self {
            object_name,
            new_parent_name,
            include_object,
        }
    }
}

impl PolicyAssertion for PolicyDuplicationSelect {
    fn update_policy_digest(
        &self,
        crypto: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        acc: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        let mut arg2 = Vec::new();
        if self.include_object {
            arg2.extend_from_slice(&self.object_name);
        }
        arg2.extend_from_slice(&self.new_parent_name);
        arg2.push(if self.include_object { 1 } else { 0 });
        // `PolicyDuplicationSelect::UpdatePolicyDigest` (TpmPolicy.cpp:565) is a single extend:
        //     H(policyDigest || TPM_CC_PolicyDuplicationSelect
        //                    || [objectName] || newParentName || includeObject)
        policy_update1(
            crypto,
            hash_alg,
            acc,
            TPM_CC::PolicyDuplicationSelect,
            &arg2,
        )
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

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use crate::tpm2_impl::mock_device::{MockResponse, MockTpmDevice};

    /// Every expected digest below is a literal produced outside this crate, by transcribing the
    /// algorithm from `TSS.CPP/Src/TpmPolicy.cpp` (cross-checked against
    /// `TSS.NET/TSS.Net/PolicyAces.cs`) into a short independent script. Asserting against a
    /// value this implementation computed would only show that it agrees with itself, which is
    /// precisely the failure mode these tests exist to catch.
    ///
    /// Each vector must be transcribed from the `UpdatePolicyDigest` of the *matching*
    /// assertion, not from `PABase::PolicyUpdate`. Most assertions are a single extend and only
    /// `PolicySigned`, `PolicySecret`, `PolicyAuthorize` and `PolicyTicket` use `PolicyUpdate`;
    /// deriving a single-extend assertion's vector from `PolicyUpdate` produces a test that
    /// passes against a double-extending implementation a real TPM rejects.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn zero_digest() -> Vec<u8> {
        vec![0u8; 32]
    }

    // -----------------------------------------------------------------------------------
    // Item 1: PolicyUpdate's second extend is unconditional.
    // -----------------------------------------------------------------------------------

    #[test]
    fn policy_update_extends_unconditionally_with_empty_policy_ref() {
        // `PABase::PolicyUpdate` (TpmPolicy.cpp:226) is
        //     policyDigest.Extend(commandCode ‖ arg2);
        //     policyDigest.Extend(arg3);
        // with no test on arg3. For TPM_CC_PolicySecret against TPM_RH_OWNER with an empty
        // policyRef — the common case — that is
        //     H( H(0^32 ‖ 0x00000151 ‖ 0x40000001) ‖ <nothing> )
        let expected = hex("0d84f55daf6e43ac97966e62c9bb989d3397777d25c5f749868055d65394f952");
        // What the guarded version produced: the first extend only, and therefore a digest no
        // policy session could ever reach.
        let single_extend_only =
            hex("478cf794da0e0531f4117344277d77d086259043f037b6d67f63b132a08bfc27");

        let mut acc = zero_digest();
        policy_update(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &mut acc,
            TPM_CC::PolicySecret,
            &TPM_RH::OWNER.get_value().to_be_bytes(),
            &[],
        )
        .unwrap();

        assert_eq!(acc, expected);
        assert_ne!(acc, single_extend_only);
    }

    #[test]
    fn policy_update_with_a_non_empty_policy_ref_is_unchanged() {
        // The non-empty branch was always right; pin it so the fix cannot silently alter it.
        let policy_ref = b"reference".to_vec();
        let mut acc = zero_digest();
        policy_update(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &mut acc,
            TPM_CC::PolicySecret,
            &TPM_RH::OWNER.get_value().to_be_bytes(),
            &policy_ref,
        )
        .unwrap();

        let first = Crypto::hash(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &[
                zero_digest().as_slice(),
                &TPM_CC::PolicySecret.get_value().to_be_bytes(),
                &TPM_RH::OWNER.get_value().to_be_bytes(),
            ]
            .concat(),
        )
        .unwrap();
        let expected = Crypto::hash(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &[first.as_slice(), policy_ref.as_slice()].concat(),
        )
        .unwrap();
        assert_eq!(acc, expected);
    }

    // -----------------------------------------------------------------------------------
    // Item 2: TPM2_PolicyNV takes exactly one extend.
    // -----------------------------------------------------------------------------------

    #[test]
    fn policy_nv_uses_a_single_extend() {
        // `PolicyNV::UpdatePolicyDigest` (TpmPolicy.cpp:439) extends once, with the Name inside
        // the same extend:
        //     H(0^32 ‖ 0x00000149 ‖ H(operandB ‖ offset ‖ operation) ‖ nvIndex.Name)
        let expected = hex("8be05d12a9bbbcb4858fafe713814c5d5fb1611ed8c22769ced2ee987b3ca078");
        // What delegating to PolicyUpdate produced: two extends, and an unsatisfiable digest.
        let two_extends = hex("6dd4cb20c2431ca98c146169d750d4862cd8d4b8b4b4b2949bb992b016efabc5");

        let nv_name: Vec<u8> = [0x00u8, 0x0B].iter().copied().chain(0u8..32).collect();
        let policy = PolicyNv::new(
            TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            TPM_HANDLE::new(0x01800001),
            nv_name,
            vec![1, 2, 3, 4],
            0,
            TPM_EO::EQ,
        );

        let mut acc = zero_digest();
        policy
            .update_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &mut acc)
            .unwrap();

        assert_eq!(acc, expected);
        assert_ne!(acc, two_extends);
    }

    // -----------------------------------------------------------------------------------
    // Item 3: TPM2_PolicyPCR is sent the computed digest, not the first raw PCR value.
    // -----------------------------------------------------------------------------------

    fn two_pcr_values() -> Vec<TPM2B_DIGEST> {
        vec![
            TPM2B_DIGEST::new(&vec![0xAAu8; 32]),
            TPM2B_DIGEST::new(&vec![0xBBu8; 32]),
        ]
    }

    fn one_selection() -> Vec<TPMS_PCR_SELECTION> {
        vec![TPMS_PCR_SELECTION::new(TPM_ALG_ID::SHA256, &vec![0x03u8])]
    }

    #[test]
    fn policy_pcr_digest_matches_hash_pcrs() {
        // `Helpers::HashPcrs` — H over the concatenated PCR values, here H(0xAA*32 ‖ 0xBB*32).
        let expected = hex("e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6");
        let policy = PolicyPcr::new(two_pcr_values(), one_selection());
        assert_eq!(
            policy
                .pcr_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn policy_pcr_policy_digest_matches_the_cpp_reference() {
        // `PolicyPcr::UpdatePolicyDigest` (TpmPolicy.cpp:312) is a SINGLE extend:
        //     H(0^32 ‖ 0x0000017F ‖ count ‖ selections ‖ HashPcrs(values))
        // The previous literal here was transcribed from `PABase::PolicyUpdate`'s two-extend
        // shape instead, so it agreed with a PolicyPCR that double-extended. A real TPM does
        // not.
        let expected = hex("5ac44e92d0326eb3afec6049aa2391f17693707874c2cc260541238ae3906e13");
        // The two-extend value, i.e. the old (wrong) literal.
        let two_extends = hex("797f02987199a628dc6f8d86a79999a356bec0ecfb211ec17fdadc4b91582bd0");
        let policy = PolicyPcr::new(two_pcr_values(), one_selection());

        let mut acc = zero_digest();
        policy
            .update_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &mut acc)
            .unwrap();
        assert_eq!(acc, expected);
        assert_ne!(acc, two_extends);
    }

    #[test]
    fn policy_pcr_sends_the_computed_digest_not_the_first_value() {
        // Drive `execute` against a mock device and read the pcrDigest argument straight out of
        // the command bytes. `TPM2_PolicyPCR` has no auth handle and no sessions, so the command
        // is  tag ‖ size ‖ commandCode ‖ policySession ‖ pcrDigest(TPM2B) ‖ pcrs.
        let expected_digest =
            hex("e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6");

        // TPM_ST_NO_SESSIONS, 10 bytes, TPM_RC_SUCCESS, no parameters.
        let ok = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let device = MockTpmDevice::new(vec![MockResponse::Canned(ok)]);
        let log = device.command_log();
        let mut tpm = Tpm2::with_software_crypto(Box::new(device));

        let session = Session::new(
            TPM_HANDLE::new(0x03000000),
            &[0u8; 32],
            TPMA_SESSION::continueSession,
            &[0u8; 32],
        );
        let policy = PolicyPcr::new(two_pcr_values(), one_selection());
        policy.execute(&mut tpm, &session).unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let digest_len = u16::from_be_bytes([cmd[14], cmd[15]]) as usize;
        let sent = cmd[16..16 + digest_len].to_vec();

        assert_eq!(
            sent, expected_digest,
            "TPM2_PolicyPCR must be sent the same digest that went into the policy digest"
        );
        assert_ne!(
            sent,
            vec![0xAAu8; 32],
            "sending pcr_values[0] verbatim is the defect this test pins"
        );
        assert!(
            !sent.is_empty(),
            "an empty pcrDigest tells the TPM to skip the PCR comparison entirely"
        );
    }

    #[test]
    fn policy_pcr_rejects_empty_pcr_values() {
        // Indexing pcr_values[0] used to panic here. Erroring matters beyond the panic: an
        // empty pcrDigest is meaningful to the TPM — it means "do not compare the PCRs" — so
        // quietly hashing nothing would produce a policy session that checks no PCRs at all.
        let policy = PolicyPcr::new(Vec::new(), one_selection());

        assert!(matches!(
            policy.pcr_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256),
            Err(TpmError::InvalidParameter)
        ));

        let mut acc = zero_digest();
        assert!(matches!(
            policy.update_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &mut acc),
            Err(TpmError::InvalidParameter)
        ));

        let device = MockTpmDevice::new(Vec::new());
        let mut tpm = Tpm2::with_software_crypto(Box::new(device));
        let session = Session::new(
            TPM_HANDLE::new(0x03000000),
            &[0u8; 32],
            TPMA_SESSION::continueSession,
            &[0u8; 32],
        );
        assert!(matches!(
            policy.execute(&mut tpm, &session),
            Err(TpmError::InvalidParameter)
        ));
    }

    // -----------------------------------------------------------------------------------
    // The two assertions that tell the session how the TPM will authorize it.
    // -----------------------------------------------------------------------------------

    #[test]
    fn policy_password_and_policy_auth_value_are_mutually_exclusive_on_a_session() {
        // The TPM's `isPasswordNeeded` and `isAuthValueNeeded` are mutually exclusive: each
        // command CLEARs the other (TPM 2.0 Part 3, TPM2_PolicyPassword / TPM2_PolicyAuthValue).
        // They select different response behaviour — a PolicyPassword session gets no response
        // authorization at all — so leaving a stale flag set makes the client expect the wrong
        // thing.
        let ok = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let device = MockTpmDevice::new(vec![
            MockResponse::Canned(ok.clone()),
            MockResponse::Canned(ok),
        ]);
        let mut tpm = Tpm2::with_software_crypto(Box::new(device));
        let session = Session::new(
            TPM_HANDLE::new(0x03000000),
            &[0u8; 32],
            TPMA_SESSION::continueSession,
            &[0u8; 32],
        );

        let after_password = PolicyPassword::new().execute(&mut tpm, &session).unwrap();
        assert!(after_password.needs_password);
        assert!(!after_password.needs_hmac);
        assert!(!after_password.expects_response_auth());

        let after_auth_value = PolicyAuthValue::new()
            .execute(&mut tpm, &after_password)
            .unwrap();
        assert!(after_auth_value.needs_hmac);
        assert!(!after_auth_value.needs_password);
        assert!(after_auth_value.expects_response_auth());
    }

    // -----------------------------------------------------------------------------------
    // Item 4: every assertion uses the digest shape of its `TSS.CPP` counterpart.
    //
    // The regression these pin: routing a single-extend assertion through `policy_update`
    // adds an extend over an empty `arg3`. Nothing in software notices; a real TPM produces a
    // different `policyDigest` and every session against it fails.
    // -----------------------------------------------------------------------------------

    fn digest_of(assertion: &dyn PolicyAssertion) -> Vec<u8> {
        let mut acc = zero_digest();
        assertion
            .update_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &mut acc)
            .unwrap();
        acc
    }

    #[test]
    fn policy_command_code_uses_a_single_extend() {
        // `PolicyCommandCode::UpdatePolicyDigest` (TpmPolicy.cpp:333):
        //     H(0^32 ‖ 0x0000016C ‖ 0x0000015B)      [TPM_CC_HMAC_Start]
        // This is the digest a real TPM reported when `policy_tree_sample` caught the
        // double-extend.
        let expected = hex("2c9437859508d8f2905a6fc9cc50eab46f7682ce7cd2a8714f67a92bf142dc36");
        let two_extends = hex("076e80efc2aae5ca7961d4e331bcf2cba1a84588a1502f176ce5507eb360fefa");

        let acc = digest_of(&PolicyCommandCode::new(TPM_CC::HMAC_Start));
        assert_eq!(acc, expected);
        assert_ne!(acc, two_extends);
    }

    #[test]
    fn policy_auth_value_and_policy_password_share_one_single_extend_digest() {
        // `PolicyAuthValue::UpdatePolicyDigest` (TpmPolicy.cpp:411) and
        // `PolicyPassword::UpdatePolicyDigest` (:425) are both, in their entirety,
        //     accumulator.Extend(Int32ToTpm(TPM_CC::PolicyAuthValue));
        // i.e. H(0^32 ‖ 0x0000016B). PolicyPassword deliberately uses the PolicyAuthValue
        // command code so one policy can be satisfied either way.
        let expected = hex("8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e");
        let two_extends = hex("202ca3645e334dfdf79bf341aca5451a735037951d4f532794059870c597e64c");

        let auth_value = digest_of(&PolicyAuthValue::new());
        let password = digest_of(&PolicyPassword::new());
        assert_eq!(auth_value, expected);
        assert_eq!(password, expected);
        assert_ne!(auth_value, two_extends);
    }

    #[test]
    fn policy_cp_hash_uses_a_single_extend() {
        // `PolicyCpHash::UpdatePolicyDigest` (TpmPolicy.cpp:349):
        //     H(0^32 ‖ 0x0000016E ‖ cpHashA)
        let expected = hex("52dc88a57fccbb92568bed93ff793b1c7a4fff0f20af825a9d1b06f903b0d87f");
        let cp_hash: Vec<u8> = (0x10u8..0x30).collect();
        assert_eq!(digest_of(&PolicyCpHash::new(cp_hash)), expected);
    }

    #[test]
    fn policy_name_hash_uses_a_single_extend() {
        // `PolicyNameHash::UpdatePolicyDigest` (TpmPolicy.cpp:395):
        //     H(0^32 ‖ 0x00000170 ‖ nameHash)
        let expected = hex("0b20d273d44c8f5ecd30dfe8cf4f441bc069f9b5daada74d94506b4d7bafbfc0");
        let name_hash: Vec<u8> = (0x40u8..0x60).collect();
        assert_eq!(digest_of(&PolicyNameHash::new(name_hash)), expected);
    }

    #[test]
    fn policy_counter_timer_uses_a_single_extend() {
        // `PolicyCounterTimer::UpdatePolicyDigest` (TpmPolicy.cpp:379):
        //     H(0^32 ‖ 0x0000016D ‖ H(operandB ‖ offset ‖ operation))
        let expected = hex("8ac1c2b12b4ea0df1c08b7b20d6199cee877e25fe29af227124b3f77d8ce89f2");
        let policy = PolicyCounterTimer::from_u64(1234, 8, TPM_EO::UNSIGNED_GT);
        assert_eq!(digest_of(&policy), expected);
    }

    #[test]
    fn policy_locality_uses_a_single_extend() {
        // `PolicyLocality::UpdatePolicyDigest` (TpmPolicy.cpp:239):
        //     H(0^32 ‖ 0x0000016F ‖ 0x01)     - TPMA_LOCALITY is one byte on the wire.
        let expected = hex("ddee6af14bf3c4e8127ced87bcf9a57e1c0c8ddb5e67735c8505f96f07b8dbb8");
        assert_eq!(
            digest_of(&PolicyLocality::new(TPMA_LOCALITY::LOC_ZERO)),
            expected
        );
    }

    #[test]
    fn policy_duplication_select_uses_a_single_extend() {
        // `PolicyDuplicationSelect::UpdatePolicyDigest` (TpmPolicy.cpp:565):
        //     H(0^32 ‖ 0x00000188 ‖ [objectName] ‖ newParentName ‖ includeObject)
        // The object Name is in the digest only when includeObject is set; the flag byte is
        // always there.
        let obj_name: Vec<u8> = [0x00u8, 0x0B].iter().copied().chain(0x80u8..0xA0).collect();
        let parent_name: Vec<u8> = [0x00u8, 0x0B].iter().copied().chain(0xA0u8..0xC0).collect();

        let with_object = hex("8947e4ab30b2738ba1ce93e886fa290c7184867f5a1d600d28dacbcf81a91320");
        let without_object =
            hex("10dbd0e9ac9f6f4170dac0ea69df9e7667c7b6becb0dee8097a6f79f95b59fa6");

        assert_eq!(
            digest_of(&PolicyDuplicationSelect::new(
                obj_name.clone(),
                parent_name.clone(),
                true
            )),
            with_object
        );
        assert_eq!(
            digest_of(&PolicyDuplicationSelect::new(obj_name, parent_name, false)),
            without_object
        );
    }

    #[test]
    fn policy_or_resets_the_accumulator_then_single_extends() {
        // `PolicyOr::UpdatePolicyDigest` (TpmPolicy.cpp:268):
        //     accumulator.Reset(); accumulator.Extend(0x00000171 ‖ digest1 ‖ digest2)
        // with each branch digest computed from its own zero accumulator.
        let expected = hex("8adcb4e659bf6cd70a892987b08fc8e021be1c8c390d99940d209dfdae62b4ed");

        let branches: Vec<Vec<Box<dyn PolicyAssertion>>> = vec![
            vec![Box::new(PolicyCommandCode::new(TPM_CC::HMAC_Start))],
            vec![Box::new(PolicyCommandCode::new(TPM_CC::Sign))],
        ];
        let policy = PolicyOr::new(branches);
        assert_eq!(digest_of(&policy), expected);

        // The Reset() is load-bearing: whatever came before must be discarded.
        let mut acc = vec![0xFFu8; 32];
        policy
            .update_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &mut acc)
            .unwrap();
        assert_eq!(acc, expected);
    }

    #[test]
    fn policy_tree_chains_assertions_in_the_order_they_were_added() {
        // Two single-extend assertions in sequence:
        //     H(H(0^32 ‖ 0x0000016F ‖ 0x01) ‖ 0x0000016C ‖ 0x0000015D)
        // This is the `PolicyLocality` + `PolicyCommandCode(Sign)` chain that
        // `policy_tree_sample` checks against a TPM trial session.
        let expected = hex("13e423a4dc7783a2f2f858ee32b576011e7f9f2111ead871bc10da2258a4b969");
        let tree = PolicyTree::new()
            .add(PolicyLocality::new(TPMA_LOCALITY::LOC_ZERO))
            .add(PolicyCommandCode::new(TPM_CC::Sign));
        assert_eq!(
            tree.get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn policy_authorize_resets_the_accumulator_then_uses_policy_update() {
        // `PolicyAuthorize::UpdatePolicyDigest` (TpmPolicy.cpp:509) is
        //     accumulator.Reset();
        //     PolicyUpdate(accumulator, TPM_CC::PolicyAuthorize, key.GetName(), PolicyRef);
        // so it is one of the four genuine two-extend assertions, preceded by a reset. The key
        // Name is an input here, not a value under test; the shape is what is asserted.
        let parameters = TPMU_PUBLIC_PARMS::keyedHashDetail(TPMS_KEYEDHASH_PARMS::new(&Some(
            TPMU_SCHEME_KEYEDHASH::hmac(TPMS_SCHEME_HMAC {
                hashAlg: TPM_ALG_ID::SHA256,
            }),
        )));
        let key = TPMT_PUBLIC::new(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
            &vec![],
            &Some(parameters),
            &Some(TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH::default())),
        );
        let policy_ref = b"reference".to_vec();
        let policy = PolicyAuthorize::new(
            vec![0x11u8; 32],
            policy_ref.clone(),
            key.clone(),
            TPMT_SIGNATURE::default(),
        );

        let name = key.get_name(&SOFTWARE_PROVIDER).unwrap();
        let first = Crypto::hash(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &[
                zero_digest().as_slice(),
                &TPM_CC::PolicyAuthorize.get_value().to_be_bytes(),
                name.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
        let expected = Crypto::hash(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &[first.as_slice(), policy_ref.as_slice()].concat(),
        )
        .unwrap();

        assert_eq!(digest_of(&policy), expected);

        // Reset: a non-zero starting accumulator must not change the result.
        let mut acc = vec![0x5Au8; 32];
        policy
            .update_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &mut acc)
            .unwrap();
        assert_eq!(acc, expected);
    }
}
