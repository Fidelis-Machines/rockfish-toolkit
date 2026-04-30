// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! S7comm wire protocol parser.
//!
//! Parses the S7comm protocol used by Siemens S7 PLCs, which runs over
//! TPKT (RFC 1006) + COTP (ISO 8073) on TCP port 102.
//!
//! Also detects S7comm+ (extended protocol, magic 0x72).
//!
//! Wire format:
//!   +------------------+
//!   | TPKT Header      |  4 bytes (version, reserved, length)
//!   +------------------+
//!   | COTP Header      |  variable (length, PDU type, ...)
//!   +------------------+
//!   | S7comm Header    |  10+ bytes (protocol_id, msg_type, ...)
//!   +------------------+
//!   | S7comm Params    |  variable
//!   +------------------+
//!   | S7comm Data      |  variable
//!   +------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// TPKT version (always 3)
pub const TPKT_VERSION: u8 = 0x03;

/// TPKT reserved byte (always 0)
pub const TPKT_RESERVED: u8 = 0x00;

/// TPKT header size
pub const TPKT_HEADER_SIZE: usize = 4;

/// S7comm protocol ID
pub const S7COMM_PROTOCOL_ID: u8 = 0x32;

/// S7comm+ protocol magic
pub const S7COMM_PLUS_MAGIC: u8 = 0x72;

/// S7comm header size (minimum)
pub const S7COMM_HEADER_SIZE: usize = 10;

/// Default TCP port for ISO-TSAP / S7comm
pub const S7COMM_PORT: u16 = 102;

// ============================================================================
// COTP PDU Types
// ============================================================================

/// COTP PDU type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CotpPduType {
    /// DT Data (0xF0)
    DtData = 0xF0,
    /// Connection Request (0xE0)
    ConnectionRequest = 0xE0,
    /// Connection Confirm (0xD0)
    ConnectionConfirm = 0xD0,
    /// Disconnect Request (0x80)
    DisconnectRequest = 0x80,
    /// Disconnect Confirm (0xC0)
    DisconnectConfirm = 0xC0,
    /// Expedited Data (0x10)
    ExpeditedData = 0x10,
    /// Data Acknowledge (0x60)
    DataAcknowledge = 0x60,
}

impl CotpPduType {
    pub fn from_u8(v: u8) -> Option<Self> {
        // PDU type is in upper nibble for some types
        match v & 0xF0 {
            0xF0 => Some(Self::DtData),
            0xE0 => Some(Self::ConnectionRequest),
            0xD0 => Some(Self::ConnectionConfirm),
            0x80 => Some(Self::DisconnectRequest),
            0xC0 => Some(Self::DisconnectConfirm),
            0x10 => Some(Self::ExpeditedData),
            0x60 => Some(Self::DataAcknowledge),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::DtData => "DT_DATA",
            Self::ConnectionRequest => "CR",
            Self::ConnectionConfirm => "CC",
            Self::DisconnectRequest => "DR",
            Self::DisconnectConfirm => "DC",
            Self::ExpeditedData => "ED",
            Self::DataAcknowledge => "AK",
        }
    }
}

impl fmt::Display for CotpPduType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// S7comm Message Types
// ============================================================================

/// S7comm message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// Job request (0x01)
    Job = 0x01,
    /// Acknowledgement without data (0x02)
    Ack = 0x02,
    /// Acknowledgement with data (0x03)
    AckData = 0x03,
    /// User data (0x07)
    UserData = 0x07,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Job),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::AckData),
            0x07 => Some(Self::UserData),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Job => "Job",
            Self::Ack => "Ack",
            Self::AckData => "AckData",
            Self::UserData => "UserData",
        }
    }
}

impl fmt::Display for MsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// S7comm Function Codes
// ============================================================================

/// S7comm function code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FunctionCode {
    /// CPU services / communication setup (0xF0)
    Setup = 0xF0,
    /// Read variable (0x04)
    ReadVar = 0x04,
    /// Write variable (0x05)
    WriteVar = 0x05,
    /// Request download (0x1A)
    Download = 0x1A,
    /// Upload (0x1D)
    Upload = 0x1D,
    /// Start upload (0x1E)
    StartUpload = 0x1E,
    /// End upload (0x1F)
    EndUpload = 0x1F,
    /// PLC control (0x28)
    PlcControl = 0x28,
    /// PLC stop (0x29)
    PlcStop = 0x29,
}

impl FunctionCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0xF0 => Some(Self::Setup),
            0x04 => Some(Self::ReadVar),
            0x05 => Some(Self::WriteVar),
            0x1A => Some(Self::Download),
            0x1D => Some(Self::Upload),
            0x1E => Some(Self::StartUpload),
            0x1F => Some(Self::EndUpload),
            0x28 => Some(Self::PlcControl),
            0x29 => Some(Self::PlcStop),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Setup => "Setup",
            Self::ReadVar => "ReadVar",
            Self::WriteVar => "WriteVar",
            Self::Download => "Download",
            Self::Upload => "Upload",
            Self::StartUpload => "StartUpload",
            Self::EndUpload => "EndUpload",
            Self::PlcControl => "PlcControl",
            Self::PlcStop => "PlcStop",
        }
    }

    /// Security-relevant function codes (write, download, control, stop)
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Self::WriteVar
                | Self::Download
                | Self::PlcControl
                | Self::PlcStop
        )
    }
}

impl fmt::Display for FunctionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// S7comm Area Identifiers
// ============================================================================

/// S7comm memory area identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Area {
    /// System info (0x03)
    SysInfo = 0x03,
    /// System flags (0x05)
    SysFlags = 0x05,
    /// Analog inputs (0x06)
    AnalogInputs = 0x06,
    /// Analog outputs (0x07)
    AnalogOutputs = 0x07,
    /// Direct peripheral access (0x80)
    DirectPeripheral = 0x80,
    /// Inputs (0x81)
    Inputs = 0x81,
    /// Outputs (0x82)
    Outputs = 0x82,
    /// Flags / Merkers (0x83)
    Flags = 0x83,
    /// Data blocks (0x84)
    DataBlocks = 0x84,
    /// Instance data blocks (0x85)
    InstanceDB = 0x85,
    /// Local data (0x86)
    LocalData = 0x86,
    /// Counter (0x1C)
    Counter = 0x1C,
    /// Timer (0x1D)
    Timer = 0x1D,
}

impl Area {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x03 => Some(Self::SysInfo),
            0x05 => Some(Self::SysFlags),
            0x06 => Some(Self::AnalogInputs),
            0x07 => Some(Self::AnalogOutputs),
            0x80 => Some(Self::DirectPeripheral),
            0x81 => Some(Self::Inputs),
            0x82 => Some(Self::Outputs),
            0x83 => Some(Self::Flags),
            0x84 => Some(Self::DataBlocks),
            0x85 => Some(Self::InstanceDB),
            0x86 => Some(Self::LocalData),
            0x1C => Some(Self::Counter),
            0x1D => Some(Self::Timer),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::SysInfo => "SysInfo",
            Self::SysFlags => "SysFlags",
            Self::AnalogInputs => "AI",
            Self::AnalogOutputs => "AO",
            Self::DirectPeripheral => "P",
            Self::Inputs => "I",
            Self::Outputs => "Q",
            Self::Flags => "M",
            Self::DataBlocks => "DB",
            Self::InstanceDB => "DI",
            Self::LocalData => "L",
            Self::Counter => "C",
            Self::Timer => "T",
        }
    }
}

impl fmt::Display for Area {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// Parsed TPKT header
#[derive(Debug, Clone)]
pub struct TpktHeader {
    pub version: u8,
    pub reserved: u8,
    pub length: u16,
}

/// Parsed COTP header
#[derive(Debug, Clone)]
pub struct CotpHeader {
    pub length: u8,
    pub pdu_type: CotpPduType,
    pub pdu_type_raw: u8,
}

/// Parsed S7comm header
#[derive(Debug, Clone)]
pub struct S7commHeader {
    pub protocol_id: u8,
    pub msg_type: MsgType,
    pub msg_type_raw: u8,
    pub reserved: u16,
    pub pdu_ref: u16,
    pub param_length: u16,
    pub data_length: u16,
    /// Error class (present in Ack-Data)
    pub error_class: Option<u8>,
    /// Error code (present in Ack-Data)
    pub error_code: Option<u8>,
}

/// A fully parsed S7comm PDU (one TPKT frame)
#[derive(Debug, Clone)]
pub struct S7commMessage {
    pub tpkt: TpktHeader,
    pub cotp: CotpHeader,
    /// S7comm header (None for COTP-only frames like CR/CC)
    pub s7_header: Option<S7commHeader>,
    /// Function code extracted from parameters
    pub function_code: Option<FunctionCode>,
    pub function_code_raw: Option<u8>,
    /// Area identifier from read/write parameters
    pub area: Option<Area>,
    pub area_raw: Option<u8>,
    /// DB number from read/write parameters
    pub db_number: Option<u16>,
    /// Whether this is S7comm+ (extended protocol)
    pub is_s7comm_plus: bool,
    /// Raw parameter bytes
    pub param_data: Vec<u8>,
    /// Raw data bytes
    pub data: Vec<u8>,
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadTpkt,
    BadCotp,
    BadS7comm(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadTpkt => write!(f, "invalid TPKT header"),
            Self::BadCotp => write!(f, "invalid COTP header"),
            Self::BadS7comm(msg) => write!(f, "S7comm parse error: {}", msg),
        }
    }
}

/// Check if a buffer starts with a TPKT header and contains S7comm.
/// Used for protocol probing in Suricata.
pub fn probe_s7comm(buf: &[u8]) -> bool {
    // Minimum: TPKT(4) + COTP(2) + S7comm header byte
    if buf.len() < 7 {
        return false;
    }

    // Check TPKT header
    if buf[0] != TPKT_VERSION || buf[1] != TPKT_RESERVED {
        return false;
    }

    let tpkt_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if tpkt_len < 7 {
        return false;
    }

    // COTP header length byte
    let cotp_len = buf[4] as usize;
    if cotp_len < 1 {
        return false;
    }

    // Check COTP PDU type
    let cotp_pdu_type = buf[5] & 0xF0;

    // For COTP CR/CC, we accept as valid S7comm connection setup
    if cotp_pdu_type == 0xE0 || cotp_pdu_type == 0xD0 {
        return true;
    }

    // For DT Data, check for S7comm or S7comm+ protocol ID
    if cotp_pdu_type == 0xF0 {
        let s7_offset = 4 + 1 + cotp_len;
        if buf.len() > s7_offset {
            let proto_id = buf[s7_offset];
            return proto_id == S7COMM_PROTOCOL_ID || proto_id == S7COMM_PLUS_MAGIC;
        }
    }

    false
}

/// Parse a TPKT header (4 bytes).
fn parse_tpkt(buf: &[u8]) -> Result<TpktHeader, ParseError> {
    if buf.len() < TPKT_HEADER_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }
    if buf[0] != TPKT_VERSION {
        return Err(ParseError::BadTpkt);
    }

    Ok(TpktHeader {
        version: buf[0],
        reserved: buf[1],
        length: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// Parse a COTP header.
fn parse_cotp(buf: &[u8]) -> Result<(CotpHeader, usize), ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::BadCotp);
    }

    let length = buf[0];
    let pdu_type_raw = buf[1];
    let pdu_type = CotpPduType::from_u8(pdu_type_raw).ok_or(ParseError::BadCotp)?;

    // Total COTP header size = length byte + length value
    let cotp_size = 1 + length as usize;

    Ok((
        CotpHeader {
            length,
            pdu_type,
            pdu_type_raw,
        },
        cotp_size,
    ))
}

/// Parse an S7comm header (minimum 10 bytes, 12 for AckData).
fn parse_s7comm_header(buf: &[u8]) -> Result<S7commHeader, ParseError> {
    if buf.len() < S7COMM_HEADER_SIZE {
        return Err(ParseError::BadS7comm("header too short".into()));
    }

    let protocol_id = buf[0];
    if protocol_id != S7COMM_PROTOCOL_ID {
        return Err(ParseError::BadS7comm(format!(
            "bad protocol_id 0x{:02x}",
            protocol_id
        )));
    }

    let msg_type_raw = buf[1];
    let msg_type = MsgType::from_u8(msg_type_raw)
        .ok_or_else(|| ParseError::BadS7comm(format!("unknown msg_type 0x{:02x}", msg_type_raw)))?;

    let reserved = u16::from_be_bytes([buf[2], buf[3]]);
    let pdu_ref = u16::from_be_bytes([buf[4], buf[5]]);
    let param_length = u16::from_be_bytes([buf[6], buf[7]]);
    let data_length = u16::from_be_bytes([buf[8], buf[9]]);

    let (error_class, error_code) = if msg_type == MsgType::AckData && buf.len() >= 12 {
        (Some(buf[10]), Some(buf[11]))
    } else {
        (None, None)
    };

    Ok(S7commHeader {
        protocol_id,
        msg_type,
        msg_type_raw,
        reserved,
        pdu_ref,
        param_length,
        data_length,
        error_class,
        error_code,
    })
}

/// Parse a complete S7comm PDU from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<S7commMessage, ParseError> {
    // Parse TPKT
    let tpkt = parse_tpkt(buf)?;

    // Parse COTP (starts at offset 4)
    let cotp_start = TPKT_HEADER_SIZE;
    if buf.len() < cotp_start + 2 {
        return Err(ParseError::TooShort(buf.len()));
    }
    let (cotp, cotp_size) = parse_cotp(&buf[cotp_start..])?;

    // For COTP CR/CC, there is no S7comm payload
    if cotp.pdu_type == CotpPduType::ConnectionRequest
        || cotp.pdu_type == CotpPduType::ConnectionConfirm
        || cotp.pdu_type == CotpPduType::DisconnectRequest
        || cotp.pdu_type == CotpPduType::DisconnectConfirm
    {
        return Ok(S7commMessage {
            tpkt,
            cotp,
            s7_header: None,
            function_code: None,
            function_code_raw: None,
            area: None,
            area_raw: None,
            db_number: None,
            is_s7comm_plus: false,
            param_data: Vec::new(),
            data: Vec::new(),
        });
    }

    // S7comm payload starts after COTP
    let s7_start = cotp_start + cotp_size;
    if buf.len() <= s7_start {
        return Err(ParseError::TooShort(buf.len()));
    }

    // Check for S7comm+ (magic 0x72)
    let is_s7comm_plus = buf[s7_start] == S7COMM_PLUS_MAGIC;

    if is_s7comm_plus {
        // S7comm+ is a different protocol; store raw data
        let raw_data = buf[s7_start..].to_vec();
        return Ok(S7commMessage {
            tpkt,
            cotp,
            s7_header: None,
            function_code: None,
            function_code_raw: None,
            area: None,
            area_raw: None,
            db_number: None,
            is_s7comm_plus: true,
            param_data: raw_data,
            data: Vec::new(),
        });
    }

    // Parse S7comm header
    let s7_header = parse_s7comm_header(&buf[s7_start..])?;

    let header_size = if s7_header.msg_type == MsgType::AckData {
        12
    } else {
        S7COMM_HEADER_SIZE
    };

    // Extract parameter and data sections
    let param_start = s7_start + header_size;
    let param_end = param_start + s7_header.param_length as usize;
    let data_start = param_end;
    let data_end = data_start + s7_header.data_length as usize;

    let param_data = if param_end <= buf.len() {
        buf[param_start..param_end].to_vec()
    } else if param_start < buf.len() {
        buf[param_start..].to_vec()
    } else {
        Vec::new()
    };

    let data = if data_end <= buf.len() {
        buf[data_start..data_end].to_vec()
    } else if data_start < buf.len() {
        buf[data_start..].to_vec()
    } else {
        Vec::new()
    };

    // Extract function code from first parameter byte
    let function_code_raw = param_data.first().copied();
    let function_code = function_code_raw.and_then(FunctionCode::from_u8);

    // Extract area and DB number from read/write parameters
    let (area, area_raw, db_number) = extract_read_write_area(&param_data, &function_code);

    Ok(S7commMessage {
        tpkt,
        cotp,
        s7_header: Some(s7_header),
        function_code,
        function_code_raw,
        area,
        area_raw,
        db_number,
        is_s7comm_plus,
        param_data,
        data,
    })
}

/// Extract area and DB number from read/write variable parameters.
fn extract_read_write_area(
    param_data: &[u8],
    function_code: &Option<FunctionCode>,
) -> (Option<Area>, Option<u8>, Option<u16>) {
    match function_code {
        Some(FunctionCode::ReadVar) | Some(FunctionCode::WriteVar) => {
            // Read/Write var parameter structure:
            // byte 0: function code
            // byte 1: item count
            // For each item (12 bytes each):
            //   byte 0: variable specification (0x12)
            //   byte 1: address specification length
            //   byte 2: syntax ID
            //   byte 3: transport size
            //   bytes 4-5: length
            //   bytes 6-7: DB number
            //   byte 8: area
            //   bytes 9-11: address (3 bytes)
            if param_data.len() >= 10 {
                let area_raw = param_data[9];
                let area = Area::from_u8(area_raw);
                let db_number = u16::from_be_bytes([param_data[7], param_data[8]]);
                (area, Some(area_raw), Some(db_number))
            } else {
                (None, None, None)
            }
        }
        _ => (None, None, None),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_s7comm_tpkt_cotp_cr() {
        // TPKT header + COTP CR
        let buf = [
            0x03, 0x00, 0x00, 0x16, // TPKT: version=3, reserved=0, length=22
            0x11,                   // COTP: length=17
            0xE0,                   // COTP: PDU type = CR
            0x00, 0x00, 0x00, 0x01, 0x00, 0xC1, 0x02, 0x01,
            0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
        ];
        assert!(probe_s7comm(&buf));
    }

    #[test]
    fn test_probe_s7comm_dt_data() {
        // TPKT + COTP DT + S7comm header
        let buf = [
            0x03, 0x00, 0x00, 0x19, // TPKT: version=3, reserved=0, length=25
            0x02,                   // COTP: length=2
            0xF0, 0x80,             // COTP: PDU type = DT Data, TPDU nr
            0x32,                   // S7comm: protocol_id = 0x32
            0x01,                   // msg_type = Job
            0x00, 0x00,             // reserved
            0x00, 0x01,             // pdu_ref = 1
            0x00, 0x08,             // param_length = 8
            0x00, 0x00,             // data_length = 0
            0xF0,                   // function code = Setup
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0,
        ];
        assert!(probe_s7comm(&buf));
    }

    #[test]
    fn test_probe_s7comm_negative() {
        assert!(!probe_s7comm(b"HTTP/1.1"));
        assert!(!probe_s7comm(&[0x03, 0x01])); // bad reserved byte
        assert!(!probe_s7comm(&[0x04, 0x00, 0x00, 0x10, 0x02, 0xF0])); // bad TPKT version
    }

    #[test]
    fn test_parse_cotp_cr() {
        let buf = [
            0x03, 0x00, 0x00, 0x16, // TPKT
            0x11, 0xE0,             // COTP: length=17, PDU type=CR
            0x00, 0x00, 0x00, 0x01, 0x00, 0xC1, 0x02, 0x01,
            0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.tpkt.version, TPKT_VERSION);
        assert_eq!(msg.tpkt.length, 22);
        assert_eq!(msg.cotp.pdu_type, CotpPduType::ConnectionRequest);
        assert!(msg.s7_header.is_none());
    }

    #[test]
    fn test_parse_s7comm_setup() {
        let buf = [
            0x03, 0x00, 0x00, 0x19, // TPKT
            0x02, 0xF0, 0x80,       // COTP: DT Data
            0x32,                   // S7comm protocol_id
            0x01,                   // msg_type = Job
            0x00, 0x00,             // reserved
            0x00, 0x01,             // pdu_ref = 1
            0x00, 0x08,             // param_length = 8
            0x00, 0x00,             // data_length = 0
            0xF0,                   // function code = Setup (0xF0)
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0,
        ];
        let msg = parse_message(&buf).unwrap();
        let hdr = msg.s7_header.as_ref().unwrap();
        assert_eq!(hdr.protocol_id, S7COMM_PROTOCOL_ID);
        assert_eq!(hdr.msg_type, MsgType::Job);
        assert_eq!(hdr.pdu_ref, 1);
        assert_eq!(msg.function_code, Some(FunctionCode::Setup));
    }

    #[test]
    fn test_msg_type_names() {
        assert_eq!(MsgType::Job.name(), "Job");
        assert_eq!(MsgType::AckData.name(), "AckData");
        assert_eq!(MsgType::UserData.name(), "UserData");
    }
}
