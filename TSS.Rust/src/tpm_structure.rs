/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#![allow(unused_variables)]

//! TPM type definitions

use crate::error::*;
use crate::tpm_buffer::*;
use crate::tpm_types::*;

/// Trait for structures that can be marshaled to/from TPM wire format
pub trait TpmStructure: TpmMarshaller {
    fn serialize(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;
    fn deserialize(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;

    /// Unmarshals this object in place from the TPM wire representation contained in the
    /// given buffer, and fails if the buffer did not hold a complete representation.
    ///
    /// Note that this populates `self`; use [`TpmBuffer::createObj`] to build a new object
    /// instead.
    #[allow(non_snake_case)]
    fn fromTpm(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {
        self.initFromTpm(buffer)?;
        buffer.check_status()
    }

    /// Unmarshals this object in place from its TPM wire representation contained in the
    /// given byte vector, and fails if the vector did not hold a complete representation.
    #[allow(non_snake_case)]
    fn fromBytes(&mut self, buffer: &mut Vec<u8>) -> Result<(), TpmError> {
        let mut tpm_buffer = TpmBuffer::from(buffer);
        self.initFromTpm(&mut tpm_buffer)?;
        tpm_buffer.check_status()
    }

    /// Decode one complete TPM value, rejecting truncated or trailing input.
    #[allow(non_snake_case)]
    fn fromBytesExact(bytes: &[u8]) -> Result<Self, TpmError>
    where
        Self: Default + Sized,
    {
        let mut buffer = TpmBuffer::from(bytes);
        let value = buffer.createObj::<Self>()?;
        if buffer.current_pos() != buffer.size() {
            return Err(TpmError::TrailingData);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod exact_decode_tests {
    use std::panic::catch_unwind;

    use super::*;

    #[test]
    fn exact_decode_round_trips() {
        let value = TPM2B_PRIVATE::new(&vec![0xaa, 0xbb]);
        let bytes = value.toBytes().unwrap();

        let decoded = TPM2B_PRIVATE::fromBytesExact(&bytes).unwrap();

        assert_eq!(decoded.buffer, value.buffer);
    }

    #[test]
    fn exact_decode_rejects_truncated_input() {
        assert!(matches!(
            TPM2B_PRIVATE::fromBytesExact(&[0, 2, 0xaa]),
            Err(TpmError::BufferUnderflow)
        ));
    }

    #[test]
    fn exact_decode_rejects_trailing_input() {
        assert!(matches!(
            TPM2B_PRIVATE::fromBytesExact(&[0, 1, 0xaa, 0xff]),
            Err(TpmError::TrailingData)
        ));
    }

    #[test]
    fn malformed_tpm2b_values_do_not_panic() {
        for length in 0..=64 {
            let bytes: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            assert!(catch_unwind(|| TPM2B_PUBLIC::fromBytesExact(&bytes)).is_ok());
            assert!(catch_unwind(|| TPM2B_PRIVATE::fromBytesExact(&bytes)).is_ok());
            assert!(catch_unwind(|| TPM2B_ENCRYPTED_SECRET::fromBytesExact(&bytes)).is_ok());
        }

        let oversized_array = [0xff; 8];
        assert!(catch_unwind(|| TPML_ALG::fromBytesExact(&oversized_array)).is_ok());
    }
}

/// Common trait for all TPM enumeration types
pub trait TpmEnum<T> {
    /// Get the numeric value of the enum
    fn get_value(&self) -> T;
    /// Create enum from a numeric value
    fn try_from_trait(value: u64) -> Result<Self, TpmError>
    where
        Self: Sized;
    fn new_from_trait(value: u64) -> Result<Self, TpmError>
    where
        Self: Sized;
}

/// Trait for TPM union types
pub trait TpmUnion: TpmStructure {}

/// <summary> Parameters of the TPM command request data structure field, to which session
/// based encryption can be applied (i.e. the first non-handle field marshaled in size-prefixed
/// form, if any) </summary>
pub struct SessEncInfo {
    /// <summary> Length of the size prefix in bytes. The size prefix contains the number of
    /// elements in the sized area filed (normally just bytes). </summary>
    pub size_len: u16,

    /// <summary> Length of an element of the sized area in bytes (in most cases 1) </summary>
    pub val_len: u16,
}

/// <summary> Base class for custom (not TPM 2.0 spec defined) auto-generated classes
/// representing a TPM command or response parameters and handles, if any. </summary>
///
/// <remarks> These data structures differ from the spec-defined ones derived directly from
/// the TpmStructure class in that their handle fields are not marshaled by their toTpm() and
/// initFrom() methods, but rather are acceesed and manipulated via an interface defined by
/// this structs and its derivatives ReqStructure and RespStructure. </remarks>
pub trait CmdStructure: TpmStructure {
    /// <returns> Number of TPM handles contained (as fields) in this data structure </returns>
    fn num_handles(&self) -> u16 {
        0
    }

    /// <returns> Non-zero size info of the encryptable command/response parameter if session
    /// based encryption can be applied to this object (i.e. its first non-handle field is
    /// marshaled in size-prefixed form). Otherwise returns zero initialized struct. </returns>
    fn sess_enc_info(&self) -> SessEncInfo {
        SessEncInfo {
            size_len: 0,
            val_len: 0,
        }
    }
}

/// <summary> Base class for custom (not TPM 2.0 spec defined) auto-generated data structures
/// representing a TPM command parameters and handles, if any. </summary>
pub trait ReqStructure: CmdStructure {
    /// <returns> A vector of TPM handles contained in this request data structure </returns>
    fn get_handles(&self) -> Vec<TPM_HANDLE>;

    /// <returns> Number of authorization TPM handles contained in this data structure </returns>
    fn num_auth_handles(&self) -> u16 {
        0
    }

    /// <summary> Serializable method </summary>
    fn type_name(&self) -> String {
        "ReqStructure".to_string()
    }
}

/// <summary> Base class for custom (not TPM 2.0 spec defined) auto-generated data structures
/// representing a TPM response parameters and handles, if any. </summary>
pub trait RespStructure: CmdStructure {
    /// <returns> this structure's handle field value </returns>
    fn get_handle(&self) -> TPM_HANDLE;

    /// <summary> Sets this structure's handle field (TPM_HANDLE) if it is present </summary>
    fn set_handle(&mut self, _handle: &TPM_HANDLE) {}

    /// <summary> Returns the name field from the response, if present </summary>
    fn get_resp_name(&self) -> Vec<u8> {
        Vec::new()
    }

    /// <summary> Serializable method </summary>
    fn type_name(&self) -> String {
        "RespStructure".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_tpm_populates_existing_receiver() -> Result<(), TpmError> {
        let expected_attributes = TPMA_OBJECT(
            TPMA_OBJECT::fixedTPM.0 | TPMA_OBJECT::userWithAuth.0 | TPMA_OBJECT::sign.0,
        );
        let public = TPMT_PUBLIC {
            nameAlg: TPM_ALG_ID::SHA256,
            objectAttributes: expected_attributes,
            authPolicy: vec![1, 2, 3],
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT::default(),
                scheme: Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
                keyBits: 2048,
                exponent: 0,
            })),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: vec![0xA5; 256],
            })),
        };

        let mut out = TpmBuffer::new(None);
        public.toTpm(&mut out)?;
        let serialized = out.trim().clone();
        let mut input = TpmBuffer::from(serialized.as_slice());
        let mut parsed = TPMT_PUBLIC::default();

        parsed.fromTpm(&mut input)?;

        assert_eq!(parsed.nameAlg, public.nameAlg);
        assert_eq!(parsed.objectAttributes.0, expected_attributes.0);
        assert_eq!(parsed.authPolicy, public.authPolicy);
        match parsed.unique {
            Some(TPMU_PUBLIC_ID::rsa(unique)) => assert_eq!(unique.buffer, vec![0xA5; 256]),
            _ => panic!("expected RSA public unique field"),
        }
        Ok(())
    }
}
