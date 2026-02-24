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
    #[allow(non_snake_case)]
    fn fromTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;
    #[allow(non_snake_case)]
    fn fromBytes(&mut self, buffer: &mut Vec<u8>) -> Result<(), TpmError>;
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
    fn get_resp_name(&self) -> Vec<u8> { Vec::new() }

    /// <summary> Serializable method </summary>
    fn type_name(&self) -> String {
        "RespStructure".to_string()
    }
}
