// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! IEC 60870-5-104 (IEC 104) wire protocol parser.
//!
//! IEC 104 is the TCP transport profile of IEC 60870-5-101, used for
//! telecontrol in power grid SCADA systems. It runs over TCP port 2404.
//!
//! Wire format:
//!   APCI (Application Protocol Control Information) — 6 bytes:
//!     Start byte: 0x68
//!     Length:      1 byte (remaining bytes after length field)
//!     Control:     4 bytes (format-dependent)
//!
//!   Three APDU formats:
//!     I-frame (Information): carries ASDU data
//!       Control: send_seq (15 bits) | 0 | recv_seq (15 bits) | 0
//!     S-frame (Supervisory): flow control only
//!       Control: 0x01 | 0x00 | recv_seq (15 bits) | 0
//!     U-frame (Unnumbered): connection management
//!       Control: function bits | 0x03 | 0x00 | 0x00 | 0x00
//!
//!   ASDU (Application Service Data Unit) — inside I-frames:
//!     Type ID:      1 byte (information type)
//!     SQ + NumObj:  1 byte (structure qualifier + object count)
//!     COT:          1-2 bytes (cause of transmission)
//!     CA:           1-2 bytes (common address / station address)
//!     IOA:          3 bytes (information object address)
//!     Data:         variable
//!
//! Reference: IEC 60870-5-104:2006

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// Start byte for all IEC 104 APDUs
pub const START_BYTE: u8 = 0x68;

/// Default TCP port
pub const DEFAULT_PORT: u16 = 2404;

/// Maximum APDU length (253 bytes per spec)
pub const MAX_APDU_LENGTH: u8 = 253;

// ============================================================================
// APDU Frame Types
// ============================================================================

/// APDU frame type determined by control field bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// I-frame: carries ASDU (information transfer)
    I,
    /// S-frame: supervisory (acknowledge only)
    S,
    /// U-frame: unnumbered (connection management)
    U,
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I => write!(f, "I"),
            Self::S => write!(f, "S"),
            Self::U => write!(f, "U"),
        }
    }
}

/// U-frame function types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UFunction {
    /// Start Data Transfer Activation
    StartDTAct,
    /// Start Data Transfer Confirmation
    StartDTCon,
    /// Stop Data Transfer Activation
    StopDTAct,
    /// Stop Data Transfer Confirmation
    StopDTCon,
    /// Test Frame Activation
    TestFRAct,
    /// Test Frame Confirmation
    TestFRCon,
}

impl UFunction {
    pub fn from_control(ctrl: u8) -> Option<Self> {
        match ctrl & 0xFC {
            0x04 => Some(Self::StartDTAct),
            0x08 => Some(Self::StartDTCon),
            0x10 => Some(Self::StopDTAct),
            0x20 => Some(Self::StopDTCon),
            0x40 => Some(Self::TestFRAct),
            0x80 => Some(Self::TestFRCon),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::StartDTAct => "STARTDT_ACT",
            Self::StartDTCon => "STARTDT_CON",
            Self::StopDTAct => "STOPDT_ACT",
            Self::StopDTCon => "STOPDT_CON",
            Self::TestFRAct => "TESTFR_ACT",
            Self::TestFRCon => "TESTFR_CON",
        }
    }

    /// Security-relevant: StartDT/StopDT control data flow
    pub fn is_control(&self) -> bool {
        matches!(
            self,
            Self::StartDTAct | Self::StartDTCon | Self::StopDTAct | Self::StopDTCon
        )
    }
}

impl fmt::Display for UFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// ASDU Type IDs
// ============================================================================

/// ASDU type identifier — determines the information type and structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeId(pub u8);

impl TypeId {
    // Process information in monitoring direction
    pub const M_SP_NA: Self = Self(1);   // Single-point information
    pub const M_DP_NA: Self = Self(3);   // Double-point information
    pub const M_ST_NA: Self = Self(5);   // Step position information
    pub const M_BO_NA: Self = Self(7);   // Bitstring of 32 bits
    pub const M_ME_NA: Self = Self(9);   // Measured value, normalized
    pub const M_ME_NB: Self = Self(11);  // Measured value, scaled
    pub const M_ME_NC: Self = Self(13);  // Measured value, short floating point
    pub const M_IT_NA: Self = Self(15);  // Integrated totals
    pub const M_SP_TB: Self = Self(30);  // Single-point with time tag CP56Time2a
    pub const M_DP_TB: Self = Self(31);  // Double-point with time tag
    pub const M_ME_TF: Self = Self(36);  // Measured value, short float with time tag

    // Process information in control direction
    pub const C_SC_NA: Self = Self(45);  // Single command
    pub const C_DC_NA: Self = Self(46);  // Double command
    pub const C_RC_NA: Self = Self(47);  // Regulating step command
    pub const C_SE_NA: Self = Self(48);  // Set-point, normalized
    pub const C_SE_NB: Self = Self(49);  // Set-point, scaled
    pub const C_SE_NC: Self = Self(50);  // Set-point, short floating point
    pub const C_BO_NA: Self = Self(51);  // Bitstring of 32 bits command
    pub const C_SC_TA: Self = Self(58);  // Single command with time tag
    pub const C_DC_TA: Self = Self(59);  // Double command with time tag
    pub const C_SE_TA: Self = Self(61);  // Set-point, normalized with time tag

    // System information in control direction
    pub const C_IC_NA: Self = Self(100); // Interrogation command
    pub const C_CI_NA: Self = Self(101); // Counter interrogation command
    pub const C_RD_NA: Self = Self(102); // Read command
    pub const C_CS_NA: Self = Self(103); // Clock synchronization command
    pub const C_TS_NA: Self = Self(104); // Test command
    pub const C_RP_NA: Self = Self(105); // Reset process command
    pub const C_CD_NA: Self = Self(106); // Delay acquisition command

    // File transfer
    pub const F_FR_NA: Self = Self(120); // File ready
    pub const F_SR_NA: Self = Self(121); // Section ready
    pub const F_SC_NA: Self = Self(122); // Call directory / select file
    pub const F_LS_NA: Self = Self(123); // Last section / segment
    pub const F_AF_NA: Self = Self(124); // Ack file / section
    pub const F_SG_NA: Self = Self(125); // Segment
    pub const F_DR_TA: Self = Self(126); // Directory

    pub fn name(&self) -> &'static str {
        match self.0 {
            1 => "M_SP_NA (Single-point)",
            3 => "M_DP_NA (Double-point)",
            5 => "M_ST_NA (Step position)",
            7 => "M_BO_NA (Bitstring 32-bit)",
            9 => "M_ME_NA (Measured normalized)",
            11 => "M_ME_NB (Measured scaled)",
            13 => "M_ME_NC (Measured float)",
            15 => "M_IT_NA (Integrated totals)",
            30 => "M_SP_TB (Single-point + time)",
            31 => "M_DP_TB (Double-point + time)",
            36 => "M_ME_TF (Measured float + time)",
            45 => "C_SC_NA (Single command)",
            46 => "C_DC_NA (Double command)",
            47 => "C_RC_NA (Regulating step)",
            48 => "C_SE_NA (Set-point normalized)",
            49 => "C_SE_NB (Set-point scaled)",
            50 => "C_SE_NC (Set-point float)",
            51 => "C_BO_NA (Bitstring command)",
            58 => "C_SC_TA (Single command + time)",
            59 => "C_DC_TA (Double command + time)",
            61 => "C_SE_TA (Set-point normalized + time)",
            100 => "C_IC_NA (Interrogation)",
            101 => "C_CI_NA (Counter interrogation)",
            102 => "C_RD_NA (Read)",
            103 => "C_CS_NA (Clock sync)",
            104 => "C_TS_NA (Test command)",
            105 => "C_RP_NA (Reset process)",
            106 => "C_CD_NA (Delay acquisition)",
            120..=126 => "File transfer",
            _ => "Unknown",
        }
    }

    /// Is this a control (command) direction type?
    pub fn is_command(&self) -> bool {
        (45..=69).contains(&self.0) || (100..=106).contains(&self.0)
    }

    /// Is this a monitoring direction type?
    pub fn is_monitoring(&self) -> bool {
        (1..=44).contains(&self.0)
    }

    /// Is this a direct control action (switches, set-points)?
    pub fn is_control_action(&self) -> bool {
        (45..=51).contains(&self.0) || (58..=64).contains(&self.0)
    }

    /// Is this a system management command?
    pub fn is_system_command(&self) -> bool {
        (100..=106).contains(&self.0)
    }

    /// Is this file transfer?
    pub fn is_file_transfer(&self) -> bool {
        (120..=127).contains(&self.0)
    }
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.name())
    }
}

// ============================================================================
// Cause of Transmission
// ============================================================================

/// Cause of Transmission (COT)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CauseOfTransmission(pub u8);

impl CauseOfTransmission {
    pub const PERIODIC: Self = Self(1);
    pub const BACKGROUND: Self = Self(2);
    pub const SPONTANEOUS: Self = Self(3);
    pub const INITIALIZED: Self = Self(4);
    pub const REQUEST: Self = Self(5);
    pub const ACTIVATION: Self = Self(6);
    pub const ACTIVATION_CON: Self = Self(7);
    pub const DEACTIVATION: Self = Self(8);
    pub const DEACTIVATION_CON: Self = Self(9);
    pub const ACTIVATION_TERM: Self = Self(10);
    pub const RETURN_REMOTE: Self = Self(11);
    pub const RETURN_LOCAL: Self = Self(12);
    pub const FILE_TRANSFER: Self = Self(13);
    pub const INTERROGATION: Self = Self(20);
    pub const UNKNOWN_TYPE: Self = Self(44);
    pub const UNKNOWN_COT: Self = Self(45);
    pub const UNKNOWN_CA: Self = Self(46);
    pub const UNKNOWN_IOA: Self = Self(47);

    pub fn name(&self) -> &'static str {
        match self.0 {
            1 => "periodic",
            2 => "background",
            3 => "spontaneous",
            4 => "initialized",
            5 => "request",
            6 => "activation",
            7 => "activation_con",
            8 => "deactivation",
            9 => "deactivation_con",
            10 => "activation_term",
            11 => "return_remote",
            12 => "return_local",
            13 => "file_transfer",
            20 => "interrogation",
            44 => "unknown_type",
            45 => "unknown_cot",
            46 => "unknown_ca",
            47 => "unknown_ioa",
            _ => "reserved",
        }
    }

    /// Is this a negative acknowledgement?
    pub fn is_negative(&self) -> bool {
        self.0 >= 44 && self.0 <= 47
    }
}

impl fmt::Display for CauseOfTransmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// APCI header (6 bytes)
#[derive(Debug, Clone)]
pub struct Apci {
    /// Total APDU length (value from length byte)
    pub length: u8,
    /// Frame type (I, S, or U)
    pub frame_type: FrameType,
    /// Raw control field (4 bytes)
    pub control: [u8; 4],
}

impl Apci {
    /// For I-frames: send sequence number
    pub fn send_seq(&self) -> Option<u16> {
        if self.frame_type == FrameType::I {
            Some(((self.control[1] as u16) << 7) | ((self.control[0] as u16) >> 1))
        } else {
            None
        }
    }

    /// For I-frames and S-frames: receive sequence number
    pub fn recv_seq(&self) -> Option<u16> {
        match self.frame_type {
            FrameType::I | FrameType::S => {
                Some(((self.control[3] as u16) << 7) | ((self.control[2] as u16) >> 1))
            }
            FrameType::U => None,
        }
    }

    /// For U-frames: the function type
    pub fn u_function(&self) -> Option<UFunction> {
        if self.frame_type == FrameType::U {
            UFunction::from_control(self.control[0])
        } else {
            None
        }
    }
}

/// ASDU (inside I-frames)
#[derive(Debug, Clone)]
pub struct Asdu {
    /// Type identifier
    pub type_id: TypeId,
    /// Structure qualifier: SQ bit (bit 7) + number of objects (bits 0-6)
    pub sq: bool,
    pub num_objects: u8,
    /// Cause of transmission
    pub cot: CauseOfTransmission,
    /// Originator address (0 if COT is 1 byte)
    pub originator: u8,
    /// Common address (station address)
    pub common_address: u16,
    /// Information object addresses found in this ASDU
    pub ioa_list: Vec<u32>,
}

/// A fully parsed IEC 104 APDU
#[derive(Debug, Clone)]
pub struct Apdu {
    pub apci: Apci,
    /// ASDU payload (only present in I-frames)
    pub asdu: Option<Asdu>,
}

/// A parsed IEC 104 message (may contain multiple APDUs in one TCP segment)
#[derive(Debug, Clone)]
pub struct Iec104Message {
    pub apdus: Vec<Apdu>,
}

impl Iec104Message {
    /// Count of I-frames (carrying data)
    pub fn i_frame_count(&self) -> usize {
        self.apdus.iter().filter(|a| a.apci.frame_type == FrameType::I).count()
    }

    /// Count of control commands
    pub fn command_count(&self) -> usize {
        self.apdus
            .iter()
            .filter_map(|a| a.asdu.as_ref())
            .filter(|asdu| asdu.type_id.is_command())
            .count()
    }

    /// Count of direct control actions (switches, set-points)
    pub fn control_action_count(&self) -> usize {
        self.apdus
            .iter()
            .filter_map(|a| a.asdu.as_ref())
            .filter(|asdu| asdu.type_id.is_control_action())
            .count()
    }

    /// Check if message contains U-frame control functions
    pub fn has_u_control(&self) -> bool {
        self.apdus.iter().any(|a| {
            a.apci.u_function().map(|f| f.is_control()).unwrap_or(false)
        })
    }
}

// ============================================================================
// Parser
// ============================================================================

#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadStartByte(u8),
    BadLength(u8),
    Truncated,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadStartByte(b) => write!(f, "invalid start byte: 0x{:02x} (expected 0x68)", b),
            Self::BadLength(l) => write!(f, "invalid APDU length: {}", l),
            Self::Truncated => write!(f, "truncated APDU"),
        }
    }
}

/// Probe: check if buffer starts with IEC 104 start byte
pub fn probe_iec104(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[0] == START_BYTE && buf[1] >= 4 && buf[1] <= MAX_APDU_LENGTH
}

/// Determine frame type from control field
fn frame_type(control: &[u8; 4]) -> FrameType {
    if control[0] & 0x01 == 0 {
        FrameType::I
    } else if control[0] & 0x03 == 0x01 {
        FrameType::S
    } else {
        FrameType::U
    }
}

/// Parse a single APDU from the buffer. Returns (apdu, bytes_consumed).
fn parse_apdu(buf: &[u8]) -> Result<(Apdu, usize), ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::TooShort(buf.len()));
    }
    if buf[0] != START_BYTE {
        return Err(ParseError::BadStartByte(buf[0]));
    }

    let length = buf[1];
    if length < 4 {
        return Err(ParseError::BadLength(length));
    }

    let total_len = 2 + length as usize; // start + length + payload
    if buf.len() < total_len {
        return Err(ParseError::Truncated);
    }

    let mut control = [0u8; 4];
    control.copy_from_slice(&buf[2..6]);
    let ft = frame_type(&control);

    let apci = Apci {
        length,
        frame_type: ft,
        control,
    };

    // Parse ASDU for I-frames (data starts at offset 6)
    let asdu = if ft == FrameType::I && total_len > 6 {
        parse_asdu(&buf[6..total_len]).ok()
    } else {
        None
    };

    Ok((Apdu { apci, asdu }, total_len))
}

/// Parse ASDU from I-frame payload
fn parse_asdu(buf: &[u8]) -> Result<Asdu, ParseError> {
    if buf.len() < 6 {
        return Err(ParseError::TooShort(buf.len()));
    }

    let type_id = TypeId(buf[0]);
    let sq = buf[1] & 0x80 != 0;
    let num_objects = buf[1] & 0x7F;

    // COT: 1 byte in this simplified parser (2-byte COT for extended format)
    let cot = CauseOfTransmission(buf[2] & 0x3F);
    let originator = 0; // simplified: assume 1-byte COT

    // Common address: 2 bytes little-endian
    let common_address = (buf[4] as u16) | ((buf[5] as u16) << 8);

    // Parse IOAs (3 bytes each, little-endian)
    let mut ioa_list = Vec::new();
    let mut offset = 6;

    if sq {
        // Sequence: one IOA, then consecutive values
        if offset + 3 <= buf.len() {
            let ioa = (buf[offset] as u32)
                | ((buf[offset + 1] as u32) << 8)
                | ((buf[offset + 2] as u32) << 16);
            ioa_list.push(ioa);
        }
    } else {
        // Non-sequence: each object has its own IOA
        for _ in 0..num_objects {
            if offset + 3 > buf.len() {
                break;
            }
            let ioa = (buf[offset] as u32)
                | ((buf[offset + 1] as u32) << 8)
                | ((buf[offset + 2] as u32) << 16);
            ioa_list.push(ioa);
            // Skip past IOA + data (we don't parse values, just addresses)
            // Approximate: assume minimum 1 byte of data per object
            offset += 4;
        }
    }

    Ok(Asdu {
        type_id,
        sq,
        num_objects,
        cot,
        originator,
        common_address,
        ioa_list,
    })
}

/// Parse all APDUs from a TCP segment
pub fn parse_message(buf: &[u8]) -> Result<Iec104Message, ParseError> {
    let mut apdus = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        // Skip any non-start bytes (shouldn't happen but be robust)
        if buf[offset] != START_BYTE {
            offset += 1;
            continue;
        }
        if offset + 2 > buf.len() {
            break;
        }

        match parse_apdu(&buf[offset..]) {
            Ok((apdu, consumed)) => {
                apdus.push(apdu);
                offset += consumed;
            }
            Err(ParseError::Truncated) => break, // partial APDU at end
            Err(_) => {
                offset += 1; // skip bad byte
            }
        }
    }

    if apdus.is_empty() && !buf.is_empty() {
        return Err(ParseError::TooShort(buf.len()));
    }

    Ok(Iec104Message { apdus })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_iec104() {
        // Valid: start=0x68, length=4 (minimum), 4 control bytes
        assert!(probe_iec104(&[0x68, 0x04, 0x01, 0x00, 0x00, 0x00]));
        // Too short
        assert!(!probe_iec104(&[0x68, 0x04, 0x01]));
        // Wrong start byte
        assert!(!probe_iec104(&[0x69, 0x04, 0x01, 0x00, 0x00, 0x00]));
        // Length too small
        assert!(!probe_iec104(&[0x68, 0x02, 0x01, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_parse_u_frame_startdt() {
        // STARTDT_ACT: 0x68 0x04 0x07 0x00 0x00 0x00
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.apdus.len(), 1);
        assert_eq!(msg.apdus[0].apci.frame_type, FrameType::U);
        assert_eq!(
            msg.apdus[0].apci.u_function().unwrap(),
            UFunction::StartDTAct
        );
    }

    #[test]
    fn test_parse_s_frame() {
        // S-frame: 0x68 0x04 0x01 0x00 0x02 0x00 (recv_seq=1)
        let buf = [0x68, 0x04, 0x01, 0x00, 0x02, 0x00];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.apdus.len(), 1);
        assert_eq!(msg.apdus[0].apci.frame_type, FrameType::S);
        assert_eq!(msg.apdus[0].apci.recv_seq(), Some(1));
    }

    #[test]
    fn test_parse_i_frame_with_asdu() {
        // I-frame with ASDU: interrogation command (C_IC_NA, type 100)
        // APCI: 0x68, len=14, send_seq=0, recv_seq=0
        // ASDU: type=100, SQ=0, num_obj=1, COT=6 (activation), CA=1, IOA=0
        let buf = [
            0x68, 0x0E, // start, length=14
            0x00, 0x00, 0x00, 0x00, // I-frame control (seq 0/0)
            100,  // type_id = C_IC_NA
            0x01, // SQ=0, num_objects=1
            0x06, // COT=6 (activation)
            0x00, // originator=0
            0x01, 0x00, // common_address=1
            0x00, 0x00, 0x00, // IOA=0
            0x14, // QOI=20 (station interrogation)
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.apdus.len(), 1);
        assert_eq!(msg.apdus[0].apci.frame_type, FrameType::I);
        let asdu = msg.apdus[0].asdu.as_ref().unwrap();
        assert_eq!(asdu.type_id.0, 100);
        assert!(asdu.type_id.is_system_command());
        assert_eq!(asdu.cot, CauseOfTransmission::ACTIVATION);
        assert_eq!(asdu.common_address, 1);
    }

    #[test]
    fn test_type_id_classification() {
        assert!(TypeId(1).is_monitoring());
        assert!(TypeId(45).is_command());
        assert!(TypeId(45).is_control_action());
        assert!(TypeId(100).is_system_command());
        assert!(!TypeId(1).is_command());
        assert!(!TypeId(100).is_control_action());
    }

    #[test]
    fn test_u_function_names() {
        assert_eq!(UFunction::StartDTAct.name(), "STARTDT_ACT");
        assert_eq!(UFunction::TestFRCon.name(), "TESTFR_CON");
        assert!(UFunction::StartDTAct.is_control());
        assert!(!UFunction::TestFRAct.is_control());
    }

    #[test]
    fn test_multiple_apdus() {
        // Two U-frames back to back
        let buf = [
            0x68, 0x04, 0x07, 0x00, 0x00, 0x00, // STARTDT_ACT
            0x68, 0x04, 0x0B, 0x00, 0x00, 0x00, // STARTDT_CON
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.apdus.len(), 2);
        assert_eq!(msg.apdus[0].apci.u_function().unwrap(), UFunction::StartDTAct);
        assert_eq!(msg.apdus[1].apci.u_function().unwrap(), UFunction::StartDTCon);
    }
}
