/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

//! TPM device communication implementations

use crate::error::TpmError;

#[cfg(target_os = "windows")]
use std::os::raw::c_void;
#[cfg(target_os = "windows")]
use std::ptr;
use windows::Win32::System::TpmBaseServices::*;

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Defines the TPM connection information flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmConnInfo {
    /// Platform hierarchy is enabled, and hardware platform functionality is available
    TpmPlatformAvailable = 0x01,
    /// Connection represents a TPM Resource Manager (TRM)
    TpmUsesTrm = 0x02,
    /// The TRM is in raw mode
    TpmInRawMode = 0x04,
    /// Physical presence signals are supported
    TpmSupportsPP = 0x08,
    /// System and TPM power control signals are not supported
    TpmNoPowerCtl = 0x10,
    /// TPM locality cannot be changed
    TpmNoLocalityCtl = 0x20,
    /// Connection medium is socket
    TpmSocketConn = 0x1000,
    /// Connection medium is OS/platform specific handle
    TpmTbsConn = 0x2000,
    /// Socket connection to old version of Intel's user mode TRM on Linux
    TpmLinuxOldUserModeTrm = 0x4000,
    /// Connection via TCG compliant TCTI connection interface
    TpmTctiConn = 0x8000,
}

/// Commands for TCP communication with TPM simulator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TcpTpmCommand {
    SignalPowerOn = 1,
    SignalPowerOff = 2,
    SignalPPOn = 3,
    SignalPPOff = 4,
    SignalHashStart = 5,
    SignalHashData = 6,
    SignalHashEnd = 7,
    SendCommand = 8,
    SignalCancelOn = 9,
    SignalCancelOff = 10,
    SignalNvOn = 11,
    SignalNvOff = 12,
    SignalKeyCacheOn = 13,
    SignalKeyCacheOff = 14,
    RemoteHandshake = 15,
    SetAlternativeResult = 16,
    SessionEnd = 20,
    Stop = 21,
    TestFailureMode = 30,
}

/// Main trait for TPM devices
pub trait TpmDevice {
    /// Connect to the TPM device
    fn connect(&mut self) -> Result<bool, TpmError>;

    /// Close the connection to the TPM device
    fn close(&mut self);

    /// Dispatch a command to the TPM
    fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError>;

    /// Get a response from the TPM
    fn get_response(&mut self) -> Result<Vec<u8>, TpmError>;

    /// Check if a response is ready
    fn response_is_ready(&self) -> Result<bool, TpmError>;

    /// Power control
    fn power_ctl(&mut self, _on: bool) -> Result<(), TpmError> {
        Err(TpmError::NotSupported("power_ctl".to_string()))
    }

    /// Assert physical presence
    fn assert_physical_presence(&mut self, _on: bool) -> Result<(), TpmError> {
        Err(TpmError::NotSupported(
            "assert_physical_presence".to_string(),
        ))
    }

    /// Set locality for subsequent commands
    fn set_locality(&mut self, _locality: u32) -> Result<(), TpmError> {
        Err(TpmError::NotSupported("set_locality".to_string()))
    }

    /// Check if platform is available
    fn platform_available(&self) -> bool {
        false
    }

    /// Check if power control is available
    fn power_ctl_available(&self) -> bool {
        self.platform_available() && !self.has_flag(TpmConnInfo::TpmNoPowerCtl as u32)
    }

    /// Check if locality control is available
    fn locality_ctl_available(&self) -> bool {
        self.platform_available() && !self.has_flag(TpmConnInfo::TpmNoLocalityCtl as u32)
    }

    /// Check if physical presence can be asserted
    fn implements_physical_presence(&self) -> bool {
        self.has_flag(TpmConnInfo::TpmSupportsPP as u32)
    }

    /// Power on convenience method
    fn power_on(&mut self) -> Result<(), TpmError> {
        self.power_ctl(true)
    }

    /// Power off convenience method
    fn power_off(&mut self) -> Result<(), TpmError> {
        self.power_ctl(false)
    }

    /// Power cycle convenience method
    fn power_cycle(&mut self) -> Result<(), TpmError> {
        self.power_ctl(false)?;
        self.power_ctl(true)
    }

    /// Physical presence on convenience method
    fn pp_on(&mut self) -> Result<(), TpmError> {
        self.assert_physical_presence(true)
    }

    /// Physical presence off convenience method
    fn pp_off(&mut self) -> Result<(), TpmError> {
        self.assert_physical_presence(false)
    }

    /// Check if a specific flag is set in TpmInfo
    fn has_flag(&self, flag: u32) -> bool;

    /// Get the TpmInfo flags
    fn get_tpm_info(&self) -> u32;
}

// /// TPM device implementation for TCP connection (simulator)
// pub struct TpmTcpDevice {
//     host_name: String,
//     port: u16,
//     command_socket: Option<TcpStream>,
//     signal_socket: Option<TcpStream>,
//     locality: u8,
//     tpm_info: u32,
// }

// impl TpmTcpDevice {
//     /// Create a new TpmTcpDevice
//     pub fn new(host_name: String, port: u16) -> Self {
//         TpmTcpDevice {
//             host_name,
//             port,
//             command_socket: None,
//             signal_socket: None,
//             locality: 0,
//             tpm_info: 0,
//         }
//     }

//     /// Set the target for the TCP connection
//     pub fn set_target(&mut self, host_name: String, port: u16) {
//         self.host_name = host_name;
//         self.port = port;
//         self.locality = 0;
//     }

//     /// Connect to the specified host and port
//     pub fn connect_to(&mut self, host_name: String, port: u16) -> Result<bool, TpmError> {
//         self.set_target(host_name, port);
//         self.connect()
//     }

//     // Helper function to send an integer in network byte order
//     fn send_int(socket: &mut TcpStream, value: u32) -> Result<(), TpmError> {
//         let value_bytes = value.to_be_bytes();
//         socket
//             .write_all(&value_bytes)
//             .map_err(|e| TpmError::IoError(e.to_string()))
//     }

//     // Helper function to receive an integer in network byte order
//     fn receive_int(socket: &mut TcpStream) -> Result<u32, TpmError> {
//         let mut buffer = [0u8; 4];
//         socket
//             .read_exact(&mut buffer)
//             .map_err(|e| TpmError::IoError(e.to_string()))?;
//         Ok(u32::from_be_bytes(buffer))
//     }

//     // Helper function to get acknowledgement from server
//     fn get_ack(socket: &mut TcpStream) -> Result<(), TpmError> {
//         let end_tag = Self::receive_int(socket)?;

//         if end_tag != 0 {
//             if end_tag == 1 {
//                 return Err(TpmError::CommandFailed);
//             } else {
//                 return Err(TpmError::BadEndTag);
//             }
//         }

//         Ok(())
//     }

//     // Helper function to send a command and get acknowledgement
//     fn send_cmd_and_get_ack(socket: &mut TcpStream, cmd: TcpTpmCommand) -> Result<(), TpmError> {
//         Self::send_int(socket, cmd as u32)?;
//         Self::get_ack(socket)
//     }

//     // Helper function to receive a variable-length array
//     fn recv_var_array(socket: &mut TcpStream) -> Result<Vec<u8>, TpmError> {
//         let len = Self::receive_int(socket)? as usize;
//         let mut buffer = vec![0u8; len];

//         socket
//             .read_exact(&mut buffer)
//             .map_err(|e| TpmError::IoError(e.to_string()))?;

//         Ok(buffer)
//     }
// }

// impl TpmDevice for TpmTcpDevice {
//     fn connect(&mut self) -> Result<bool, TpmError> {
//         // Close any existing connections
//         self.close();

//         // Connect to the signal port first
//         let signal_addr = format!("{}:{}", self.host_name, self.port + 1);
//         let signal_socket = TcpStream::connect(signal_addr)
//             .map_err(|e| TpmError::IoError(format!("Failed to connect to signal port: {}", e)))?;

//         // Connect to the command port
//         let command_addr = format!("{}:{}", self.host_name, self.port);
//         let command_socket = TcpStream::connect(command_addr)
//             .map_err(|e| TpmError::IoError(format!("Failed to connect to command port: {}", e)))?;

//         // Set read and write timeouts
//         command_socket
//             .set_read_timeout(Some(Duration::from_secs(5)))
//             .map_err(|e| TpmError::IoError(e.to_string()))?;
//         signal_socket
//             .set_read_timeout(Some(Duration::from_secs(5)))
//             .map_err(|e| TpmError::IoError(e.to_string()))?;

//         // Store the sockets
//         self.command_socket = Some(command_socket);
//         self.signal_socket = Some(signal_socket);

//         // Make sure the TPM protocol is running
//         if let Some(mut cmd_socket) = self.command_socket.as_ref().map(|s| s.try_clone().unwrap()) {
//             // Client version is 1
//             const CLIENT_VERSION: u32 = 1;

//             Self::send_int(&mut cmd_socket, TcpTpmCommand::RemoteHandshake as u32)?;
//             Self::send_int(&mut cmd_socket, CLIENT_VERSION)?;

//             let endpoint_ver = Self::receive_int(&mut cmd_socket)?;
//             if endpoint_ver != CLIENT_VERSION {
//                 return Err(TpmError::IncompatibleTpm);
//             }

//             // Get the endpoint TPM properties
//             self.tpm_info = Self::receive_int(&mut cmd_socket)?;

//             Self::get_ack(&mut cmd_socket)?;

//             Ok(true)
//         } else {
//             Err(TpmError::NotConnected)
//         }
//     }

//     fn close(&mut self) {
//         // Close command socket if open
//         if let Some(_) = self.command_socket.take() {
//             // Socket will be closed when dropped
//         }

//         // Close signal socket if open
//         if let Some(_) = self.signal_socket.take() {
//             // Socket will be closed when dropped
//         }
//     }

//     fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
//         if let Some(mut socket) = self.command_socket.as_ref().map(|s| s.try_clone().unwrap()) {
//             // Send the command header
//             Self::send_int(&mut socket, TcpTpmCommand::SendCommand as u32)?;
//             socket
//                 .write_all(&[self.locality])
//                 .map_err(|e| TpmError::IoError(e.to_string()))?;
//             Self::send_int(&mut socket, cmd_buf.len() as u32)?;

//             // Send the command data
//             socket
//                 .write_all(cmd_buf)
//                 .map_err(|e| TpmError::IoError(e.to_string()))?;

//             Ok(())
//         } else {
//             Err(TpmError::NotConnected)
//         }
//     }

//     fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
//         if let Some(mut socket) = self.command_socket.as_ref().map(|s| s.try_clone().unwrap()) {
//             // Get the response
//             let resp = Self::recv_var_array(&mut socket)?;

//             // Get the terminating ACK
//             let ack = Self::receive_int(&mut socket)?;
//             if ack != 0 {
//                 return Err(TpmError::BadEndTag);
//             }

//             Ok(resp)
//         } else {
//             Err(TpmError::NotConnected)
//         }
//     }

//     fn response_is_ready(&self) -> Result<bool, TpmError> {
//         if let Some(socket) = &self.command_socket {
//             // Create a read set with just this socket
//             let mut read_set = [socket
//                 .try_clone()
//                 .map_err(|e| TpmError::IoError(e.to_string()))?];

//             // Check if there's data to read with a zero timeout
//             match socket::select(
//                 &mut read_set,
//                 &mut [],
//                 &mut [],
//                 Some(&Duration::from_secs(0)),
//             ) {
//                 Ok(1) => Ok(true),
//                 Ok(_) => Ok(false),
//                 Err(e) => Err(TpmError::IoError(e.to_string())),
//             }
//         } else {
//             Err(TpmError::NotConnected)
//         }
//     }

//     fn power_ctl(&mut self, on: bool) -> Result<(), TpmError> {
//         if let Some(mut socket) = self.signal_socket.as_ref().map(|s| s.try_clone().unwrap()) {
//             let power_cmd = if on {
//                 TcpTpmCommand::SignalPowerOn
//             } else {
//                 TcpTpmCommand::SignalPowerOff
//             };

//             let nv_cmd = if on {
//                 TcpTpmCommand::SignalNvOn
//             } else {
//                 TcpTpmCommand::SignalNvOff
//             };

//             Self::send_cmd_and_get_ack(&mut socket, power_cmd)?;
//             Self::send_cmd_and_get_ack(&mut socket, nv_cmd)?;

//             Ok(())
//         } else {
//             Err(TpmError::NotConnected)
//         }
//     }

//     fn assert_physical_presence(&mut self, on: bool) -> Result<(), TpmError> {
//         if let Some(mut socket) = self.signal_socket.as_ref().map(|s| s.try_clone().unwrap()) {
//             let pp_cmd = if on {
//                 TcpTpmCommand::SignalPPOn
//             } else {
//                 TcpTpmCommand::SignalPPOff
//             };

//             Self::send_cmd_and_get_ack(&mut socket, pp_cmd)
//         } else {
//             Err(TpmError::NotConnected)
//         }
//     }

//     fn set_locality(&mut self, locality: u32) -> Result<(), TpmError> {
//         if locality > 255 {
//             return Err(TpmError::InvalidParameter);
//         }

//         self.locality = locality as u8;
//         Ok(())
//     }

//     fn platform_available(&self) -> bool {
//         self.has_flag(TpmConnInfo::TpmPlatformAvailable as u32)
//     }

//     fn has_flag(&self, flag: u32) -> bool {
//         (self.tpm_info & flag) != 0
//     }

//     fn get_tpm_info(&self) -> u32 {
//         self.tpm_info
//     }
// }

// Windows TBS (TPM Base Services) implementation
#[cfg(target_os = "windows")]
pub struct TpmTbsDevice {
    context: *mut c_void,
    result_buffer: [u8; 4096],
    res_size: u32,
    tpm_info: u32,
}

#[cfg(target_os = "windows")]
impl TpmTbsDevice {
    pub fn new() -> Self {
        TpmTbsDevice {
            context: ptr::null_mut(),
            result_buffer: [0; 4096],
            res_size: 0,
            tpm_info: 0,
        }
    }
}

#[cfg(target_os = "windows")]
impl TpmDevice for TpmTbsDevice {
    fn connect(&mut self) -> Result<bool, TpmError> {
        if !self.context.is_null() {
            return Ok(true); // Already connected
        }

        let mut params = TBS_CONTEXT_PARAMS2::default();
        params.version = TBS_CONTEXT_VERSION_TWO;
        params.Anonymous.Anonymous._bitfield = 4;
        params.Anonymous.asUINT32 = 4;

        let context_ptr = &mut self.context as *mut *mut c_void;
        let res = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                context_ptr,
            )
        };

        if res != TBS_SUCCESS {
            return Err(TpmError::TbsError(format!(
                "Failed to connect to TBS: {:?}",
                res
            )));
        }

        // Get device info to check if TPM 2.0 is available
        let mut info = TPM_DEVICE_INFO::default();
        let res = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
                &mut info as *mut _ as *mut c_void,
            )
        };

        if res != TBS_SUCCESS {
            return Err(TpmError::TbsError("Failed to get device info".to_string()));
        } else if info.tpmVersion != TPM_VERSION_20 {
            unsafe { Tbsip_Context_Close(self.context) };
            self.context = ptr::null_mut();
            return Err(TpmError::TbsError(
                "Platform does not contain a TPM 2.0".to_string(),
            ));
        }

        // Set appropriate flags
        self.tpm_info = TpmConnInfo::TpmTbsConn as u32;

        Ok(true)
    }

    fn close(&mut self) {
        if !self.context.is_null() {
            unsafe { Tbsip_Context_Close(self.context) };
            self.context = ptr::null_mut();
        }

        self.tpm_info = 0;
    }

    fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
        if self.context.is_null() {
            return Err(TpmError::NotConnected);
        }

        // Reset result buffer size
        self.res_size = self.result_buffer.len() as u32;

        // Submit command to TBS
        let res = unsafe {
            Tbsip_Submit_Command(
                self.context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd_buf,
                self.result_buffer.as_mut_ptr(),
                &mut self.res_size as *mut u32,
            )
        };

        if res != TBS_SUCCESS {
            return Err(TpmError::TbsError(format!(
                "TBS SubmitCommand error: 0x{:08x}",
                res
            )));
        }

        Ok(())
    }

    fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
        if self.res_size == 0 {
            return Err(TpmError::NoResponse);
        }

        let resp = self.result_buffer[0..self.res_size as usize].to_vec();
        self.res_size = 0;

        Ok(resp)
    }

    fn response_is_ready(&self) -> Result<bool, TpmError> {
        if self.context.is_null() {
            return Err(TpmError::NotConnected);
        }

        if self.res_size == 0 {
            return Err(TpmError::UnexpectedState);
        }

        // For Windows TBS, the response is always ready after dispatch_command
        Ok(true)
    }

    fn has_flag(&self, flag: u32) -> bool {
        (self.tpm_info & flag) != 0
    }

    fn get_tpm_info(&self) -> u32 {
        self.tpm_info
    }
}

// Linux TPM device implementation
#[cfg(target_os = "linux")]
pub struct TpmTbsDevice {
    dev_tpm: Option<File>,
    socket: Option<TcpStream>,
    tpm_info: u32,
}

#[cfg(target_os = "linux")]
impl TpmTbsDevice {
    pub fn new() -> Self {
        TpmTbsDevice {
            dev_tpm: None,
            socket: None,
            tpm_info: 0,
        }
    }

    fn connect_to_linux_user_mode_trm(&mut self) -> Result<bool, TpmError> {
        use std::path::Path;

        // Check if TRM libraries exist
        let old_trm = Path::new("/usr/lib/x86_64-linux-gnu/libtctisocket.so.0").exists()
            || Path::new("/usr/lib/i386-linux-gnu/libtctisocket.so.0").exists();

        let new_trm = Path::new("/usr/lib/x86_64-linux-gnu/libtcti-socket.so.0").exists()
            || Path::new("/usr/lib/i386-linux-gnu/libtcti-socket.so.0").exists()
            || Path::new("/usr/local/lib/libtss2-tcti-tabrmd.so.0").exists();

        if !(old_trm || new_trm) {
            return Ok(false);
        }

        // Connect to user mode TRM
        let mut socket = TcpStream::connect("127.0.0.1:2323")
            .map_err(|e| TpmError::IoError(format!("Failed to connect to user TRM: {}", e)))?;

        // No handshake needed with user mode TRM

        self.socket = Some(socket);
        self.tpm_info = TpmConnInfo::TpmSocketConn as u32
            | TpmConnInfo::TpmUsesTrm as u32
            | TpmConnInfo::TpmNoPowerCtl as u32
            | TpmConnInfo::TpmNoLocalityCtl as u32;

        if old_trm {
            self.tpm_info |= TpmConnInfo::TpmLinuxOldUserModeTrm as u32;
        }

        Ok(true)
    }
}

#[cfg(target_os = "linux")]
impl TpmDevice for TpmTbsDevice {
    fn connect(&mut self) -> Result<bool, TpmError> {
        if self.tpm_info != 0 {
            return Ok(true); // Already connected
        }

        // Try to open the direct TPM device
        match OpenOptions::new().read(true).write(true).open("/dev/tpm0") {
            Ok(file) => {
                self.dev_tpm = Some(file);
                self.tpm_info = TpmConnInfo::TpmTbsConn as u32
                    | TpmConnInfo::TpmNoPowerCtl as u32
                    | TpmConnInfo::TpmNoLocalityCtl as u32;
                return Ok(true);
            }
            Err(_) => {
                // Try TPM resource manager
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tpmrm0")
                {
                    Ok(file) => {
                        self.dev_tpm = Some(file);
                        self.tpm_info = TpmConnInfo::TpmTbsConn as u32
                            | TpmConnInfo::TpmUsesTrm as u32
                            | TpmConnInfo::TpmNoPowerCtl as u32
                            | TpmConnInfo::TpmNoLocalityCtl as u32;
                        return Ok(true);
                    }
                    Err(_) => {
                        // Try user mode TRM
                        return self.connect_to_linux_user_mode_trm();
                    }
                }
            }
        }
    }

    fn close(&mut self) {
        self.dev_tpm = None;
        self.socket = None;
        self.tpm_info = 0;
    }

    fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
        if self.tpm_info & (TpmConnInfo::TpmSocketConn as u32) != 0 {
            // Socket-based communication
            if let Some(socket) = self.socket.as_mut() {
                // Send command to the TPM
                let mut buf = vec![];

                // Command header
                buf.extend_from_slice(&(TcpTpmCommand::SendCommand as u32).to_be_bytes());
                buf.push(0); // locality
                buf.extend_from_slice(&(cmd_buf.len() as u32).to_be_bytes());

                if self.tpm_info & (TpmConnInfo::TpmLinuxOldUserModeTrm as u32) != 0 {
                    buf.push(0); // debugMsgLevel
                    buf.push(1); // commandSent
                }

                // Send header and command buffer
                socket
                    .write_all(&buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;
                socket
                    .write_all(cmd_buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;

                Ok(())
            } else {
                Err(TpmError::NotConnected)
            }
        } else if self.tpm_info & (TpmConnInfo::TpmTbsConn as u32) != 0 {
            // TPM device file communication
            if let Some(dev) = self.dev_tpm.as_mut() {
                // Write command to TPM device
                match dev.write_all(cmd_buf) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(TpmError::IoError(format!(
                        "Failed to write TPM command: {}",
                        e
                    ))),
                }
            } else {
                Err(TpmError::NotConnected)
            }
        } else {
            Err(TpmError::InvalidTpmType)
        }
    }

    fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
        if self.tpm_info & (TpmConnInfo::TpmSocketConn as u32) != 0 {
            // Socket-based communication
            if let Some(socket) = self.socket.as_mut() {
                // Receive array length
                let mut len_buf = [0u8; 4];
                socket
                    .read_exact(&mut len_buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;
                let len = u32::from_be_bytes(len_buf) as usize;

                // Read the response data
                let mut resp = vec![0u8; len];
                socket
                    .read_exact(&mut resp)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;

                // Get the terminating ACK
                let mut ack_buf = [0u8; 4];
                socket
                    .read_exact(&mut ack_buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;
                let ack = u32::from_be_bytes(ack_buf);

                if ack != 0 {
                    return Err(TpmError::BadEndTag);
                }

                Ok(resp)
            } else {
                Err(TpmError::NotConnected)
            }
        } else if self.tpm_info & (TpmConnInfo::TpmTbsConn as u32) != 0 {
            // TPM device file communication
            if let Some(dev) = self.dev_tpm.as_mut() {
                // Buffer for response
                let mut resp_buf = [0u8; 4096];

                // Read from TPM device
                match dev.read(&mut resp_buf) {
                    Ok(bytes_read) => {
                        if bytes_read < 10 {
                            // 10 is the mandatory response header size
                            return Err(TpmError::IoError(format!(
                                "Failed to read sufficient data from TPM: got {} bytes",
                                bytes_read
                            )));
                        }

                        Ok(resp_buf[0..bytes_read].to_vec())
                    }
                    Err(e) => Err(TpmError::IoError(format!(
                        "Failed to read TPM response: {}",
                        e
                    ))),
                }
            } else {
                Err(TpmError::NotConnected)
            }
        } else {
            Err(TpmError::InvalidTpmType)
        }
    }

    fn response_is_ready(&self) -> Result<bool, TpmError> {
        // For Linux implementations, the response is typically ready after a blocking read
        Ok(true)
    }

    fn has_flag(&self, flag: u32) -> bool {
        (self.tpm_info & flag) != 0
    }

    fn get_tpm_info(&self) -> u32 {
        self.tpm_info
    }
}

// /// Socket utility module
// mod socket {
//     use std::io;
//     use std::net::TcpStream;
//     use std::time::Duration;

//     #[cfg(unix)]
//     pub fn select(
//         read: &mut [TcpStream],
//         write: &mut [TcpStream],
//         except: &mut [TcpStream],
//         timeout: Option<&Duration>,
//     ) -> io::Result<usize> {
//         use libc::{fd_set, select, timeval, FD_ISSET, FD_SET, FD_ZERO};
//         use std::os::unix::io::AsRawFd;

//         unsafe {
//             let mut read_fds: fd_set = std::mem::zeroed();
//             let mut write_fds: fd_set = std::mem::zeroed();
//             let mut except_fds: fd_set = std::mem::zeroed();

//             FD_ZERO(&mut read_fds);
//             FD_ZERO(&mut write_fds);
//             FD_ZERO(&mut except_fds);

//             let mut max_fd = 0;

//             for stream in read.iter() {
//                 let fd = stream.as_raw_fd();
//                 FD_SET(fd, &mut read_fds);
//                 max_fd = std::cmp::max(max_fd, fd);
//             }

//             for stream in write.iter() {
//                 let fd = stream.as_raw_fd();
//                 FD_SET(fd, &mut write_fds);
//                 max_fd = std::cmp::max(max_fd, fd);
//             }

//             for stream in except.iter() {
//                 let fd = stream.as_raw_fd();
//                 FD_SET(fd, &mut except_fds);
//                 max_fd = std::cmp::max(max_fd, fd);
//             }

//             let mut tv: timeval = std::mem::zeroed();
//             let tv_ptr = if let Some(timeout) = timeout {
//                 tv.tv_sec = timeout.as_secs() as _;
//                 tv.tv_usec = (timeout.subsec_micros()) as _;
//                 &mut tv as *mut timeval
//             } else {
//                 std::ptr::null_mut()
//             };

//             let result = select(
//                 max_fd + 1,
//                 &mut read_fds,
//                 &mut write_fds,
//                 &mut except_fds,
//                 tv_ptr,
//             );

//             if result < 0 {
//                 return Err(io::Error::last_os_error());
//             }

//             // Count how many are ready
//             let mut ready_count = 0;

//             for stream in read.iter() {
//                 if FD_ISSET(stream.as_raw_fd(), &read_fds) {
//                     ready_count += 1;
//                 }
//             }

//             for stream in write.iter() {
//                 if FD_ISSET(stream.as_raw_fd(), &write_fds) {
//                     ready_count += 1;
//                 }
//             }

//             for stream in except.iter() {
//                 if FD_ISSET(stream.as_raw_fd(), &except_fds) {
//                     ready_count += 1;
//                 }
//             }

//             Ok(ready_count)
//         }
//     }

//     #[cfg(windows)]
//     pub fn select(
//         read: &mut [TcpStream],
//         write: &mut [TcpStream],
//         except: &mut [TcpStream],
//         timeout: Option<&Duration>,
//     ) -> io::Result<usize> {
//         use std::os::windows::io::AsRawSocket;
//         use windows::Win32::Networking::WinSock::{
//             fd_set, select, timeval, FD_ISSET, FD_SET, FD_ZERO,
//         };

//         unsafe {
//             let mut read_fds: fd_set = std::mem::zeroed();
//             let mut write_fds: fd_set = std::mem::zeroed();
//             let mut except_fds: fd_set = std::mem::zeroed();

//             FD_ZERO(&mut read_fds);
//             FD_ZERO(&mut write_fds);
//             FD_ZERO(&mut except_fds);

//             for stream in read.iter() {
//                 FD_SET(stream.as_raw_socket(), &mut read_fds);
//             }

//             for stream in write.iter() {
//                 FD_SET(stream.as_raw_socket(), &mut write_fds);
//             }

//             for stream in except.iter() {
//                 FD_SET(stream.as_raw_socket(), &mut except_fds);
//             }

//             let mut tv: timeval = std::mem::zeroed();
//             let tv_ptr = if let Some(timeout) = timeout {
//                 tv.tv_sec = timeout.as_secs() as i32;
//                 tv.tv_usec = (timeout.subsec_micros()) as i32;
//                 &mut tv as *mut timeval
//             } else {
//                 std::ptr::null_mut()
//             };

//             let result = select(
//                 0, // ignored on Windows
//                 &mut read_fds,
//                 &mut write_fds,
//                 &mut except_fds,
//                 tv_ptr,
//             );

//             if result == -1 {
//                 return Err(io::Error::last_os_error());
//             }

//             // Count how many are ready
//             let mut ready_count = 0;

//             for stream in read.iter() {
//                 if FD_ISSET(stream.as_raw_socket(), &read_fds) {
//                     ready_count += 1;
//                 }
//             }

//             for stream in write.iter() {
//                 if FD_ISSET(stream.as_raw_socket(), &write_fds) {
//                     ready_count += 1;
//                 }
//             }

//             for stream in except.iter() {
//                 if FD_ISSET(stream.as_raw_socket(), &except_fds) {
//                     ready_count += 1;
//                 }
//             }

//             Ok(ready_count as usize)
//         }
//     }
// }
