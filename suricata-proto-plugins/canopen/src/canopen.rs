// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! CANopen wire protocol parser.
//!
//! Parses CANopen frames transported over UDP (CAN-over-UDP encapsulation,
//! common in automotive/robotics test environments and SocketCAN tunneling).
//!
//! CANopen is a CAN-based higher-layer protocol for industrial automation,
//! robotics, and medical devices, defined by CiA (CAN in Automation).
//!
//! Reference: CiA 301 (CANopen Application Layer), CiA 302 (Framework)
//!
//! CAN-over-UDP encapsulation format:
//!   +---------------------------+
//!   | UDP Encap Header          |  4 bytes (sequence:16, flags:16)
//!   +---------------------------+
//!   | CAN Frame 1               |  16 bytes (COB-ID:32, DLC:8, pad:3, data:8)
//!   +---------------------------+
//!   | CAN Frame 2               |
//!   +---------------------------+
//!   | ...                       |
//!   +---------------------------+
//!
//! CANopen frame (CAN frame level):
//!   COB-ID: function_code (4 bits) + node_id (7 bits)

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// CAN-over-UDP encapsulation header size
pub const UDP_ENCAP_HEADER_SIZE: usize = 4;

/// CAN frame size in UDP encapsulation (COB-ID:4 + DLC:1 + pad:3 + data:8)
pub const CAN_FRAME_SIZE: usize = 16;

/// Maximum CAN data length
pub const CAN_MAX_DLC: u8 = 8;

// ============================================================================
// CANopen Function Codes
// ============================================================================

/// CANopen function code (derived from upper bits of COB-ID)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionCode {
    /// Network Management (COB-ID 0x000)
    NMT,
    /// Synchronization (COB-ID 0x080)
    SYNC,
    /// Emergency (COB-ID 0x080 + nodeID)
    EMCY,
    /// Transmit PDO 1 (COB-ID 0x180 + nodeID)
    TPDO1,
    /// Receive PDO 1 (COB-ID 0x200 + nodeID)
    RPDO1,
    /// Transmit PDO 2 (COB-ID 0x280 + nodeID)
    TPDO2,
    /// Receive PDO 2 (COB-ID 0x300 + nodeID)
    RPDO2,
    /// Transmit PDO 3 (COB-ID 0x380 + nodeID)
    TPDO3,
    /// Receive PDO 3 (COB-ID 0x400 + nodeID)
    RPDO3,
    /// Transmit PDO 4 (COB-ID 0x480 + nodeID)
    TPDO4,
    /// Receive PDO 4 (COB-ID 0x500 + nodeID)
    RPDO4,
    /// SDO Response / Transmit SDO (COB-ID 0x580 + nodeID)
    TSDO,
    /// SDO Request / Receive SDO (COB-ID 0x600 + nodeID)
    RSDO,
    /// NMT Error Control / Heartbeat (COB-ID 0x700 + nodeID)
    NMTErrorControl,
    /// Unknown function code
    Unknown(u16),
}

impl FunctionCode {
    /// Determine function code from COB-ID
    pub fn from_cob_id(cob_id: u16) -> (Self, u8) {
        let cob_id = cob_id & 0x7FF; // mask to 11 bits

        if cob_id == 0x000 {
            return (Self::NMT, 0);
        }
        if cob_id == 0x080 {
            return (Self::SYNC, 0);
        }

        let node_id = (cob_id & 0x7F) as u8;
        let func_base = cob_id & 0x780; // upper 4 bits shifted

        match func_base {
            0x080 => (Self::EMCY, node_id),
            0x180 => (Self::TPDO1, node_id),
            0x200 => (Self::RPDO1, node_id),
            0x280 => (Self::TPDO2, node_id),
            0x300 => (Self::RPDO2, node_id),
            0x380 => (Self::TPDO3, node_id),
            0x400 => (Self::RPDO3, node_id),
            0x480 => (Self::TPDO4, node_id),
            0x500 => (Self::RPDO4, node_id),
            0x580 => (Self::TSDO, node_id),
            0x600 => (Self::RSDO, node_id),
            0x700 => (Self::NMTErrorControl, node_id),
            _ => (Self::Unknown(cob_id), node_id),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::NMT => "NMT",
            Self::SYNC => "SYNC",
            Self::EMCY => "EMCY",
            Self::TPDO1 => "TPDO1",
            Self::RPDO1 => "RPDO1",
            Self::TPDO2 => "TPDO2",
            Self::RPDO2 => "RPDO2",
            Self::TPDO3 => "TPDO3",
            Self::RPDO3 => "RPDO3",
            Self::TPDO4 => "TPDO4",
            Self::RPDO4 => "RPDO4",
            Self::TSDO => "TSDO",
            Self::RSDO => "RSDO",
            Self::NMTErrorControl => "NMT_ERROR_CTRL",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for FunctionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// NMT Commands
// ============================================================================

/// NMT (Network Management) command specifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NmtCommand {
    /// Start Remote Node
    Start = 0x01,
    /// Stop Remote Node
    Stop = 0x02,
    /// Enter Pre-Operational
    PreOperational = 0x80,
    /// Reset Node
    ResetNode = 0x81,
    /// Reset Communication
    ResetCommunication = 0x82,
}

impl NmtCommand {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Start),
            0x02 => Some(Self::Stop),
            0x80 => Some(Self::PreOperational),
            0x81 => Some(Self::ResetNode),
            0x82 => Some(Self::ResetCommunication),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Start => "Start",
            Self::Stop => "Stop",
            Self::PreOperational => "PreOperational",
            Self::ResetNode => "ResetNode",
            Self::ResetCommunication => "ResetCommunication",
        }
    }
}

impl fmt::Display for NmtCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// SDO Command Specifiers
// ============================================================================

/// SDO (Service Data Object) command specifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdoCommand {
    /// Initiate Download Request (write, client -> server)
    InitiateDownloadRequest,
    /// Initiate Download Response
    InitiateDownloadResponse,
    /// Initiate Upload Request (read, client -> server)
    InitiateUploadRequest,
    /// Initiate Upload Response
    InitiateUploadResponse,
    /// Segment Download Request
    SegmentDownloadRequest,
    /// Segment Download Response
    SegmentDownloadResponse,
    /// Segment Upload Request
    SegmentUploadRequest,
    /// Segment Upload Response
    SegmentUploadResponse,
    /// Abort Transfer
    Abort,
    /// Unknown
    Unknown(u8),
}

impl SdoCommand {
    /// Parse SDO command specifier from the first byte of SDO data
    pub fn from_command_byte(v: u8) -> Self {
        let ccs = (v >> 5) & 0x07; // client command specifier (bits 7-5)
        match ccs {
            0 => Self::SegmentDownloadRequest,
            1 => Self::InitiateDownloadRequest,
            2 => Self::InitiateUploadRequest,
            3 => Self::SegmentUploadRequest,
            4 => Self::Abort,
            _ => Self::Unknown(v),
        }
    }

    /// Parse SDO server response command specifier
    pub fn from_response_byte(v: u8) -> Self {
        let scs = (v >> 5) & 0x07; // server command specifier (bits 7-5)
        match scs {
            0 => Self::SegmentUploadResponse,
            1 => Self::SegmentDownloadResponse,
            2 => Self::InitiateUploadResponse,
            3 => Self::InitiateDownloadResponse,
            4 => Self::Abort,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::InitiateDownloadRequest => "InitiateDownloadReq",
            Self::InitiateDownloadResponse => "InitiateDownloadResp",
            Self::InitiateUploadRequest => "InitiateUploadReq",
            Self::InitiateUploadResponse => "InitiateUploadResp",
            Self::SegmentDownloadRequest => "SegmentDownloadReq",
            Self::SegmentDownloadResponse => "SegmentDownloadResp",
            Self::SegmentUploadRequest => "SegmentUploadReq",
            Self::SegmentUploadResponse => "SegmentUploadResp",
            Self::Abort => "Abort",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for SdoCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// CANopen Frame
// ============================================================================

/// A parsed CANopen frame
#[derive(Debug, Clone)]
pub struct CanopenFrame {
    /// CAN Object Identifier (11-bit COB-ID)
    pub cob_id: u16,
    /// Node ID (lower 7 bits of COB-ID)
    pub node_id: u8,
    /// Function code (derived from COB-ID)
    pub function_code: FunctionCode,
    /// Data Length Code (0-8)
    pub dlc: u8,
    /// CAN data payload (up to 8 bytes)
    pub data: Vec<u8>,
    /// Hex representation of data
    pub data_hex: String,
    /// NMT command (if this is an NMT frame)
    pub nmt_command: Option<NmtCommand>,
    /// SDO command (if this is an SDO frame)
    pub sdo_command: Option<SdoCommand>,
    /// SDO index (if this is an SDO frame with index)
    pub sdo_index: Option<u16>,
    /// SDO subindex (if this is an SDO frame with subindex)
    pub sdo_subindex: Option<u8>,
}

// ============================================================================
// Parsed CANopen Message (CAN-over-UDP)
// ============================================================================

/// A parsed CAN-over-UDP message containing one or more CANopen frames
#[derive(Debug, Clone)]
pub struct CanopenMessage {
    /// UDP encapsulation sequence number
    pub sequence: u16,
    /// Encapsulation flags
    pub flags: u16,
    /// CANopen frames
    pub frames: Vec<CanopenFrame>,
}

impl CanopenMessage {
    /// Check if any frame is an NMT command
    pub fn has_nmt(&self) -> bool {
        self.frames.iter().any(|f| f.function_code == FunctionCode::NMT)
    }

    /// Check if any frame is an SDO transfer
    pub fn has_sdo(&self) -> bool {
        self.frames.iter().any(|f| {
            matches!(f.function_code, FunctionCode::TSDO | FunctionCode::RSDO)
        })
    }

    /// Check if any frame is a PDO
    pub fn has_pdo(&self) -> bool {
        self.frames.iter().any(|f| {
            matches!(
                f.function_code,
                FunctionCode::TPDO1
                    | FunctionCode::TPDO2
                    | FunctionCode::TPDO3
                    | FunctionCode::TPDO4
                    | FunctionCode::RPDO1
                    | FunctionCode::RPDO2
                    | FunctionCode::RPDO3
                    | FunctionCode::RPDO4
            )
        })
    }

    /// Check if any frame is an emergency
    pub fn has_emergency(&self) -> bool {
        self.frames.iter().any(|f| f.function_code == FunctionCode::EMCY)
    }
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    InvalidDlc(u8),
    BadFrame(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::InvalidDlc(d) => write!(f, "invalid DLC: {}", d),
            Self::BadFrame(msg) => write!(f, "frame parse error: {}", msg),
        }
    }
}

/// Probe a UDP payload for CAN-over-UDP encapsulation.
///
/// Checks for valid CAN frame structure: COB-ID in valid range, DLC 0-8.
pub fn probe_canopen(buf: &[u8]) -> bool {
    // Need at least encap header + one CAN frame
    if buf.len() < UDP_ENCAP_HEADER_SIZE + CAN_FRAME_SIZE {
        return false;
    }

    // Check the first CAN frame after the encapsulation header
    let frame_start = UDP_ENCAP_HEADER_SIZE;

    // COB-ID (4 bytes, little-endian) — should have upper bits clear for standard CAN
    let cob_id_raw = u32::from_le_bytes([
        buf[frame_start],
        buf[frame_start + 1],
        buf[frame_start + 2],
        buf[frame_start + 3],
    ]);

    // Standard CAN: COB-ID should be 11-bit (0x000-0x7FF)
    // Extended frames use bit 31, RTR uses bit 30
    let cob_id = (cob_id_raw & 0x7FF) as u16;

    // DLC should be 0-8
    let dlc = buf[frame_start + 4];
    if dlc > CAN_MAX_DLC {
        return false;
    }

    // Validate COB-ID is in reasonable CANopen range (0x000-0x7FF)
    if cob_id <= 0x7FF {
        // Check if this looks like a valid CANopen function code
        let (fc, _) = FunctionCode::from_cob_id(cob_id);
        if !matches!(fc, FunctionCode::Unknown(_)) || cob_id == 0 {
            return true;
        }
    }

    false
}

/// Convert bytes to hex string
fn bytes_to_hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Parse a single CAN frame from the buffer (16 bytes).
fn parse_can_frame(buf: &[u8]) -> Result<CanopenFrame, ParseError> {
    if buf.len() < CAN_FRAME_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let cob_id_raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let cob_id = (cob_id_raw & 0x7FF) as u16;
    let dlc = buf[4];

    if dlc > CAN_MAX_DLC {
        return Err(ParseError::InvalidDlc(dlc));
    }

    let (function_code, node_id) = FunctionCode::from_cob_id(cob_id);

    // Extract data (bytes 8-15 in the 16-byte frame, up to DLC bytes)
    let data_start = 8;
    let data_end = data_start + dlc as usize;
    let data = buf[data_start..data_end].to_vec();
    let data_hex = bytes_to_hex(&data);

    // Parse NMT command
    let nmt_command = if function_code == FunctionCode::NMT && dlc >= 1 {
        NmtCommand::from_u8(data[0])
    } else {
        None
    };

    // Parse SDO fields
    let (sdo_command, sdo_index, sdo_subindex) = match function_code {
        FunctionCode::RSDO if dlc >= 1 => {
            let cmd = SdoCommand::from_command_byte(data[0]);
            let (idx, sub) = if dlc >= 4 {
                let index = u16::from_le_bytes([data[1], data[2]]);
                let subindex = data[3];
                (Some(index), Some(subindex))
            } else {
                (None, None)
            };
            (Some(cmd), idx, sub)
        }
        FunctionCode::TSDO if dlc >= 1 => {
            let cmd = SdoCommand::from_response_byte(data[0]);
            let (idx, sub) = if dlc >= 4 {
                let index = u16::from_le_bytes([data[1], data[2]]);
                let subindex = data[3];
                (Some(index), Some(subindex))
            } else {
                (None, None)
            };
            (Some(cmd), idx, sub)
        }
        _ => (None, None, None),
    };

    Ok(CanopenFrame {
        cob_id,
        node_id,
        function_code,
        dlc,
        data,
        data_hex,
        nmt_command,
        sdo_command,
        sdo_index,
        sdo_subindex,
    })
}

/// Parse a complete CAN-over-UDP message.
pub fn parse_message(buf: &[u8]) -> Result<CanopenMessage, ParseError> {
    if buf.len() < UDP_ENCAP_HEADER_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let sequence = u16::from_le_bytes([buf[0], buf[1]]);
    let flags = u16::from_le_bytes([buf[2], buf[3]]);

    let mut frames = Vec::new();
    let mut offset = UDP_ENCAP_HEADER_SIZE;

    while offset + CAN_FRAME_SIZE <= buf.len() {
        match parse_can_frame(&buf[offset..]) {
            Ok(frame) => frames.push(frame),
            Err(_) => break,
        }
        offset += CAN_FRAME_SIZE;
    }

    Ok(CanopenMessage {
        sequence,
        flags,
        frames,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_code_from_cob_id() {
        let (fc, nid) = FunctionCode::from_cob_id(0x000);
        assert_eq!(fc, FunctionCode::NMT);
        assert_eq!(nid, 0);

        let (fc, nid) = FunctionCode::from_cob_id(0x080);
        assert_eq!(fc, FunctionCode::SYNC);
        assert_eq!(nid, 0);

        let (fc, nid) = FunctionCode::from_cob_id(0x185);
        assert_eq!(fc, FunctionCode::TPDO1);
        assert_eq!(nid, 5);

        let (fc, nid) = FunctionCode::from_cob_id(0x60A);
        assert_eq!(fc, FunctionCode::RSDO);
        assert_eq!(nid, 10);

        let (fc, nid) = FunctionCode::from_cob_id(0x70F);
        assert_eq!(fc, FunctionCode::NMTErrorControl);
        assert_eq!(nid, 15);
    }

    #[test]
    fn test_nmt_commands() {
        assert_eq!(NmtCommand::from_u8(0x01), Some(NmtCommand::Start));
        assert_eq!(NmtCommand::from_u8(0x02), Some(NmtCommand::Stop));
        assert_eq!(NmtCommand::from_u8(0x81), Some(NmtCommand::ResetNode));
        assert_eq!(NmtCommand::from_u8(0x00), None);
        assert_eq!(NmtCommand::Start.name(), "Start");
    }

    #[test]
    fn test_sdo_command_parse() {
        // Initiate Download Request: CCS=1 -> byte = 0x20-0x23
        let cmd = SdoCommand::from_command_byte(0x23); // 001_00011
        assert!(matches!(cmd, SdoCommand::InitiateDownloadRequest));

        // Initiate Upload Request: CCS=2 -> byte = 0x40-0x43
        let cmd = SdoCommand::from_command_byte(0x40); // 010_00000
        assert!(matches!(cmd, SdoCommand::InitiateUploadRequest));

        // Abort: CCS=4 -> byte = 0x80
        let cmd = SdoCommand::from_command_byte(0x80); // 100_00000
        assert!(matches!(cmd, SdoCommand::Abort));
    }

    #[test]
    fn test_parse_can_frame() {
        // Build a CAN frame: COB-ID=0x601 (RSDO node 1), DLC=8
        // SDO initiate download: cmd=0x23, index=0x6040, subindex=0x00, data=0x06000000
        let mut buf = [0u8; 16];
        // COB-ID = 0x601 (little-endian)
        buf[0] = 0x01;
        buf[1] = 0x06;
        buf[2] = 0x00;
        buf[3] = 0x00;
        // DLC = 8
        buf[4] = 8;
        // pad bytes 5-7
        // data at bytes 8-15
        buf[8] = 0x23;  // SDO initiate download (CCS=1, n=0, e=1, s=1)
        buf[9] = 0x40;  // index low byte
        buf[10] = 0x60; // index high byte
        buf[11] = 0x00; // subindex
        buf[12] = 0x06; // data
        buf[13] = 0x00;
        buf[14] = 0x00;
        buf[15] = 0x00;

        let frame = parse_can_frame(&buf).unwrap();
        assert_eq!(frame.cob_id, 0x601);
        assert_eq!(frame.node_id, 1);
        assert_eq!(frame.function_code, FunctionCode::RSDO);
        assert_eq!(frame.dlc, 8);
        assert!(frame.sdo_command.is_some());
        assert_eq!(frame.sdo_index, Some(0x6040));
        assert_eq!(frame.sdo_subindex, Some(0x00));
    }

    #[test]
    fn test_probe_canopen() {
        // Build a valid CAN-over-UDP message
        let mut buf = vec![0u8; UDP_ENCAP_HEADER_SIZE + CAN_FRAME_SIZE];
        // Encap header: seq=1, flags=0
        buf[0] = 0x01; buf[1] = 0x00;
        buf[2] = 0x00; buf[3] = 0x00;
        // CAN frame: COB-ID=0x181 (TPDO1 node 1), DLC=4
        buf[4] = 0x81; buf[5] = 0x01; buf[6] = 0x00; buf[7] = 0x00;
        buf[8] = 4; // DLC
        // data at 12-19
        buf[12] = 0x01; buf[13] = 0x02; buf[14] = 0x03; buf[15] = 0x04;

        assert!(probe_canopen(&buf));

        // Invalid: DLC > 8
        buf[8] = 9;
        assert!(!probe_canopen(&buf));

        // Too short
        assert!(!probe_canopen(&[0x00, 0x01]));
    }
}
