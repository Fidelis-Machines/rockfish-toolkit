// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EtherNet/IP (CIP) wire protocol parser.
//!
//! Parses the EtherNet/IP encapsulation protocol and the embedded
//! Common Industrial Protocol (CIP) layer used in industrial automation.
//!
//! Reference: ODVA EtherNet/IP Specification (Volume 2)
//!
//! Wire format:
//!   +---------------------------+
//!   | Encapsulation Header      |  24 bytes
//!   +---------------------------+
//!   | Command-Specific Data     |  Variable
//!   +---------------------------+
//!   | CIP Layer (if applicable) |  Variable
//!   +---------------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// EtherNet/IP default TCP port
pub const ENIP_TCP_PORT: u16 = 44818;

/// EtherNet/IP default UDP port
pub const ENIP_UDP_PORT: u16 = 2222;

/// Encapsulation header size
pub const ENIP_HEADER_SIZE: usize = 24;

// ============================================================================
// Encapsulation Commands
// ============================================================================

/// EtherNet/IP encapsulation command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnipCommand {
    Nop,
    ListServices,
    ListIdentity,
    ListInterfaces,
    RegisterSession,
    UnregisterSession,
    SendRRData,
    SendUnitData,
    IndicateStatus,
    Cancel,
    Unknown(u16),
}

impl EnipCommand {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0000 => Self::Nop,
            0x0004 => Self::ListServices,
            0x0063 => Self::ListIdentity,
            0x0064 => Self::ListInterfaces,
            0x0065 => Self::RegisterSession,
            0x0066 => Self::UnregisterSession,
            0x006F => Self::SendRRData,
            0x0070 => Self::SendUnitData,
            0x0072 => Self::IndicateStatus,
            0x0073 => Self::Cancel,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Nop => "NOP",
            Self::ListServices => "ListServices",
            Self::ListIdentity => "ListIdentity",
            Self::ListInterfaces => "ListInterfaces",
            Self::RegisterSession => "RegisterSession",
            Self::UnregisterSession => "UnregisterSession",
            Self::SendRRData => "SendRRData",
            Self::SendUnitData => "SendUnitData",
            Self::IndicateStatus => "IndicateStatus",
            Self::Cancel => "Cancel",
            Self::Unknown(_) => "Unknown",
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Nop => 0x0000,
            Self::ListServices => 0x0004,
            Self::ListIdentity => 0x0063,
            Self::ListInterfaces => 0x0064,
            Self::RegisterSession => 0x0065,
            Self::UnregisterSession => 0x0066,
            Self::SendRRData => 0x006F,
            Self::SendUnitData => 0x0070,
            Self::IndicateStatus => 0x0072,
            Self::Cancel => 0x0073,
            Self::Unknown(v) => *v,
        }
    }
}

impl fmt::Display for EnipCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown(0x{:04x})", v),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// CIP Service Codes
// ============================================================================

/// CIP service codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipService {
    GetAttributeAll,
    SetAttributeAll,
    GetAttributeList,
    SetAttributeList,
    Reset,
    Start,
    Stop,
    GetAttributeSingle,
    SetAttributeSingle,
    FindNextObjectInstance,
    ReadTag,
    WriteTag,
    WriteTagFragmented,
    ForwardOpen,
    ForwardClose,
    UnconnectedSend,
    MultipleServicePacket,
    Unknown(u8),
}

impl CipService {
    pub fn from_u8(v: u8) -> Self {
        // Strip the response bit (0x80)
        let svc = v & 0x7F;
        match svc {
            0x01 => Self::GetAttributeAll,
            0x02 => Self::SetAttributeAll,
            0x03 => Self::GetAttributeList,
            0x04 => Self::SetAttributeList,
            0x05 => Self::Reset,
            0x06 => Self::Start,
            0x07 => Self::Stop,
            0x0E => Self::GetAttributeSingle,
            0x10 => Self::SetAttributeSingle,
            0x11 => Self::FindNextObjectInstance,
            0x4C => Self::ReadTag,
            0x4D => Self::WriteTag,
            0x4E => Self::ForwardClose,
            0x52 => Self::UnconnectedSend,
            0x53 => Self::WriteTagFragmented,
            0x54 => Self::ForwardOpen,
            0x0A => Self::MultipleServicePacket,
            _ => Self::Unknown(svc),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::GetAttributeAll => "Get_Attribute_All",
            Self::SetAttributeAll => "Set_Attribute_All",
            Self::GetAttributeList => "Get_Attribute_List",
            Self::SetAttributeList => "Set_Attribute_List",
            Self::Reset => "Reset",
            Self::Start => "Start",
            Self::Stop => "Stop",
            Self::GetAttributeSingle => "Get_Attribute_Single",
            Self::SetAttributeSingle => "Set_Attribute_Single",
            Self::FindNextObjectInstance => "Find_Next_Object_Instance",
            Self::ReadTag => "Read_Tag",
            Self::WriteTag => "Write_Tag",

            Self::WriteTagFragmented => "Write_Tag_Fragmented",
            Self::ForwardOpen => "Forward_Open",
            Self::ForwardClose => "Forward_Close",
            Self::UnconnectedSend => "Unconnected_Send",
            Self::MultipleServicePacket => "Multiple_Service_Packet",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Whether the raw service byte indicates a response
    pub fn is_response(raw: u8) -> bool {
        raw & 0x80 != 0
    }
}

impl fmt::Display for CipService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// EtherNet/IP encapsulation header (24 bytes)
#[derive(Debug, Clone)]
pub struct EnipHeader {
    pub command: EnipCommand,
    pub length: u16,
    pub session_handle: u32,
    pub status: u32,
    pub sender_context: [u8; 8],
    pub options: u32,
}

/// CIP message parsed from the encapsulation data
#[derive(Debug, Clone)]
pub struct CipMessage {
    pub service: CipService,
    pub is_response: bool,
    pub class_id: u16,
    pub instance_id: u16,
    pub attribute_id: u16,
    pub status: u8,
    pub data_len: usize,
}

/// Identity item from ListIdentity response
#[derive(Debug, Clone)]
pub struct IdentityItem {
    pub vendor_id: u16,
    pub device_type: u16,
    pub product_code: u16,
    pub revision_major: u8,
    pub revision_minor: u8,
    pub serial_number: u32,
    pub product_name: String,
}

/// A fully parsed EtherNet/IP message
#[derive(Debug, Clone)]
pub struct EnipMessage {
    pub header: EnipHeader,
    pub cip: Option<CipMessage>,
    pub identity: Option<IdentityItem>,
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadCommand(u16),
    InvalidCip(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadCommand(c) => write!(f, "unknown command 0x{:04x}", c),
            Self::InvalidCip(msg) => write!(f, "CIP parse error: {}", msg),
        }
    }
}

/// Check if a buffer looks like an EtherNet/IP encapsulation header.
/// Used for protocol probing in Suricata.
pub fn probe_enip(buf: &[u8]) -> bool {
    if buf.len() < ENIP_HEADER_SIZE {
        return false;
    }
    let cmd = u16::from_le_bytes([buf[0], buf[1]]);
    let length = u16::from_le_bytes([buf[2], buf[3]]);

    // Validate command is a known value
    let valid_cmd = matches!(
        cmd,
        0x0000 | 0x0004 | 0x0063 | 0x0064 | 0x0065 | 0x0066 | 0x006F | 0x0070 | 0x0072 | 0x0073
    );
    if !valid_cmd {
        return false;
    }

    // Length should be reasonable
    if length as usize + ENIP_HEADER_SIZE > 65535 {
        return false;
    }

    true
}

/// Read a u16 little-endian from buffer
fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read a u32 little-endian from buffer
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

/// Parse the encapsulation header (24 bytes).
pub fn parse_header(buf: &[u8]) -> Result<EnipHeader, ParseError> {
    if buf.len() < ENIP_HEADER_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let command = EnipCommand::from_u16(read_u16_le(buf, 0));
    let length = read_u16_le(buf, 2);
    let session_handle = read_u32_le(buf, 4);
    let status = read_u32_le(buf, 8);

    let mut sender_context = [0u8; 8];
    sender_context.copy_from_slice(&buf[12..20]);

    let options = read_u32_le(buf, 20);

    Ok(EnipHeader {
        command,
        length,
        session_handle,
        status,
        sender_context,
        options,
    })
}

/// Parse a CIP path to extract class, instance, and attribute IDs.
fn parse_cip_path(buf: &[u8]) -> (u16, u16, u16) {
    let mut class_id = 0u16;
    let mut instance_id = 0u16;
    let mut attribute_id = 0u16;
    let mut offset = 0;

    while offset + 2 <= buf.len() {
        let segment_type = buf[offset];
        match segment_type {
            0x20 => {
                // 8-bit class ID
                if offset + 2 <= buf.len() {
                    class_id = buf[offset + 1] as u16;
                    offset += 2;
                } else {
                    break;
                }
            }
            0x21 => {
                // 16-bit class ID
                if offset + 4 <= buf.len() {
                    class_id = read_u16_le(buf, offset + 2);
                    offset += 4;
                } else {
                    break;
                }
            }
            0x24 => {
                // 8-bit instance ID
                if offset + 2 <= buf.len() {
                    instance_id = buf[offset + 1] as u16;
                    offset += 2;
                } else {
                    break;
                }
            }
            0x25 => {
                // 16-bit instance ID
                if offset + 4 <= buf.len() {
                    instance_id = read_u16_le(buf, offset + 2);
                    offset += 4;
                } else {
                    break;
                }
            }
            0x30 => {
                // 8-bit attribute ID
                if offset + 2 <= buf.len() {
                    attribute_id = buf[offset + 1] as u16;
                    offset += 2;
                } else {
                    break;
                }
            }
            0x31 => {
                // 16-bit attribute ID
                if offset + 4 <= buf.len() {
                    attribute_id = read_u16_le(buf, offset + 2);
                    offset += 4;
                } else {
                    break;
                }
            }
            _ => {
                // Unknown segment, skip
                break;
            }
        }
    }

    (class_id, instance_id, attribute_id)
}

/// Parse a CIP message from the encapsulation data.
/// CIP is encapsulated within SendRRData and SendUnitData commands.
fn parse_cip(buf: &[u8]) -> Result<CipMessage, ParseError> {
    // Common Packet Format: item count (2) + items
    // Skip CPF header to get to CIP layer
    if buf.len() < 6 {
        return Err(ParseError::InvalidCip("CIP data too short".into()));
    }

    // Interface handle (4 bytes) + timeout (2 bytes) for SendRRData
    let mut offset = 6;

    // Item count
    if offset + 2 > buf.len() {
        return Err(ParseError::InvalidCip("no item count".into()));
    }
    let item_count = read_u16_le(buf, offset);
    offset += 2;

    // Skip through items to find connected/unconnected data item
    for _ in 0..item_count {
        if offset + 4 > buf.len() {
            break;
        }
        let item_type = read_u16_le(buf, offset);
        let item_length = read_u16_le(buf, offset + 2) as usize;
        offset += 4;

        // Unconnected Data Item (0x00B2) or Connected Data Item (0x00B1)
        if (item_type == 0x00B2 || item_type == 0x00B1) && item_length > 0 {
            if offset + item_length <= buf.len() && item_length >= 2 {
                let cip_data = &buf[offset..offset + item_length];
                let service_byte = cip_data[0];
                let is_response = CipService::is_response(service_byte);
                let service = CipService::from_u8(service_byte);

                let (class_id, instance_id, attribute_id) = if !is_response && cip_data.len() >= 2
                {
                    let path_size = (cip_data[1] as usize) * 2; // path size in words
                    if cip_data.len() >= 2 + path_size {
                        parse_cip_path(&cip_data[2..2 + path_size])
                    } else {
                        (0, 0, 0)
                    }
                } else {
                    (0, 0, 0)
                };

                let status = if is_response && cip_data.len() >= 4 {
                    cip_data[2] // general status
                } else {
                    0
                };

                return Ok(CipMessage {
                    service,
                    is_response,
                    class_id,
                    instance_id,
                    attribute_id,
                    status,
                    data_len: item_length,
                });
            }
        }

        offset += item_length;
    }

    Err(ParseError::InvalidCip("no CIP data item found".into()))
}

/// Parse identity information from ListIdentity response.
fn parse_identity(buf: &[u8]) -> Option<IdentityItem> {
    // Item count (2) + CIP Identity item
    if buf.len() < 4 {
        return None;
    }

    let item_count = read_u16_le(buf, 0);
    if item_count == 0 {
        return None;
    }

    let mut offset = 2;
    // Type ID (2) + Length (2)
    if offset + 4 > buf.len() {
        return None;
    }
    let _item_type = read_u16_le(buf, offset);
    let item_length = read_u16_le(buf, offset + 2) as usize;
    offset += 4;

    if offset + item_length > buf.len() || item_length < 33 {
        return None;
    }

    // Skip protocol version (2) + socket address (16)
    offset += 18;

    if offset + 14 > buf.len() {
        return None;
    }

    let vendor_id = read_u16_le(buf, offset);
    let device_type = read_u16_le(buf, offset + 2);
    let product_code = read_u16_le(buf, offset + 4);
    let revision_major = buf[offset + 6];
    let revision_minor = buf[offset + 7];
    // Skip status (2)
    let serial_number = read_u32_le(buf, offset + 10);
    offset += 14;

    // Product name (1 byte length + string)
    let product_name = if offset < buf.len() {
        let name_len = buf[offset] as usize;
        offset += 1;
        if offset + name_len <= buf.len() {
            std::str::from_utf8(&buf[offset..offset + name_len])
                .unwrap_or("<invalid>")
                .to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Some(IdentityItem {
        vendor_id,
        device_type,
        product_code,
        revision_major,
        revision_minor,
        serial_number,
        product_name,
    })
}

/// Parse a complete EtherNet/IP message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<EnipMessage, ParseError> {
    let header = parse_header(buf)?;
    let data = &buf[ENIP_HEADER_SIZE..];

    let cip = match header.command {
        EnipCommand::SendRRData | EnipCommand::SendUnitData => parse_cip(data).ok(),
        _ => None,
    };

    let identity = if header.command == EnipCommand::ListIdentity && header.status == 0 {
        parse_identity(data)
    } else {
        None
    };

    Ok(EnipMessage {
        header,
        cip,
        identity,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_enip_header(command: u16, length: u16, session: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ENIP_HEADER_SIZE);
        buf.extend_from_slice(&command.to_le_bytes());
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&session.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // status
        buf.extend_from_slice(&[0u8; 8]); // sender context
        buf.extend_from_slice(&0u32.to_le_bytes()); // options
        buf
    }

    #[test]
    fn test_probe_enip_register_session() {
        let buf = make_enip_header(0x0065, 4, 0);
        assert!(probe_enip(&buf));
    }

    #[test]
    fn test_probe_enip_list_identity() {
        let buf = make_enip_header(0x0063, 0, 0);
        assert!(probe_enip(&buf));
    }

    #[test]
    fn test_probe_enip_invalid() {
        assert!(!probe_enip(b"HTTP/1.1 200"));
        assert!(!probe_enip(&[0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_parse_header() {
        let buf = make_enip_header(0x0065, 4, 0x12345678);
        let header = parse_header(&buf).unwrap();
        assert_eq!(header.command, EnipCommand::RegisterSession);
        assert_eq!(header.length, 4);
        assert_eq!(header.session_handle, 0x12345678);
    }

    #[test]
    fn test_command_names() {
        assert_eq!(EnipCommand::RegisterSession.name(), "RegisterSession");
        assert_eq!(EnipCommand::SendRRData.name(), "SendRRData");
        assert_eq!(EnipCommand::ListIdentity.name(), "ListIdentity");
    }

    #[test]
    fn test_cip_service_codes() {
        assert_eq!(CipService::from_u8(0x4C).name(), "Read_Tag");
        assert_eq!(CipService::from_u8(0x4D).name(), "Write_Tag");
        assert_eq!(CipService::from_u8(0x54).name(), "Forward_Open");
        assert_eq!(CipService::from_u8(0x0E).name(), "Get_Attribute_Single");
    }

    #[test]
    fn test_cip_response_bit() {
        assert!(!CipService::is_response(0x4C));
        assert!(CipService::is_response(0xCC)); // 0x4C | 0x80
    }

    #[test]
    fn test_parse_cip_path() {
        // Class 0x02, Instance 0x01, Attribute 0x05
        let path = [0x20, 0x02, 0x24, 0x01, 0x30, 0x05];
        let (class, instance, attr) = parse_cip_path(&path);
        assert_eq!(class, 0x02);
        assert_eq!(instance, 0x01);
        assert_eq!(attr, 0x05);
    }
}
