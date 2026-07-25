// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! PROFINET wire protocol parser.
//!
//! Parses PROFINET DCP (Discovery and Configuration Protocol) frames
//! carried over UDP port 34964.
//!
//! PROFINET is primarily a Layer 2 protocol (EtherType 0x8892 for RT,
//! 0x8893 for PTCP). This parser focuses on the DCP discovery variant
//! that runs over UDP, which Suricata can process at the app-layer.
//!
//! Wire format (DCP over UDP):
//!   +------------------+
//!   | Frame ID         |  2 bytes (identifies frame type)
//!   +------------------+
//!   | Service ID       |  1 byte (Get/Set/Identify/Hello)
//!   +------------------+
//!   | Service Type     |  1 byte (Request/Response)
//!   +------------------+
//!   | Xid              |  4 bytes (transaction ID)
//!   +------------------+
//!   | Response Delay   |  2 bytes
//!   +------------------+
//!   | DCP Data Length  |  2 bytes
//!   +------------------+
//!   | DCP Blocks       |  variable
//!   +------------------+
//!
//! NOTE: For Layer 2 PROFINET RT/IRT monitoring (EtherType 0x8892/0x8893),
//! a separate Suricata decoder plugin or ethertype hook is needed. This
//! parser handles only the IP-layer DCP variant.

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// PROFINET RT EtherType
pub const PROFINET_ETHERTYPE_RT: u16 = 0x8892;

/// PROFINET PTCP EtherType
pub const PROFINET_ETHERTYPE_PTCP: u16 = 0x8893;

/// PROFINET DCP UDP port (discovery)
pub const PROFINET_DCP_PORT: u16 = 34964;

/// PROFINET alarm UDP port
pub const PROFINET_ALARM_PORT: u16 = 34962;

/// Minimum DCP header size (frame_id + service_id + service_type + xid + resp_delay + dcp_len)
pub const DCP_HEADER_SIZE: usize = 12;

// ============================================================================
// Frame ID Ranges
// ============================================================================

/// Classify a frame ID into its type category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// RT Class 3 Cyclic (0x0000-0x7FFF)
    RtClass3Cyclic,
    /// RT Class 1 Cyclic (0x8000-0xBFFF)
    RtClass1Cyclic,
    /// RT Class Acyclic (0xC000-0xFBFF)
    RtClassAcyclic,
    /// Alarm (0xFC00-0xFCFF)
    Alarm,
    /// DCP (0xFE00-0xFEFF)
    Dcp,
    /// Reserved (0xFF00-0xFFFF)
    Reserved,
    /// Unknown / other range
    Unknown,
}

impl FrameType {
    pub fn from_frame_id(id: u16) -> Self {
        match id {
            0x0000..=0x7FFF => Self::RtClass3Cyclic,
            0x8000..=0xBFFF => Self::RtClass1Cyclic,
            0xC000..=0xFBFF => Self::RtClassAcyclic,
            0xFC00..=0xFCFF => Self::Alarm,
            0xFD00..=0xFDFF => Self::Unknown,
            0xFE00..=0xFEFF => Self::Dcp,
            0xFF00..=0xFFFF => Self::Reserved,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::RtClass3Cyclic => "rt_class3_cyclic",
            Self::RtClass1Cyclic => "rt_class1_cyclic",
            Self::RtClassAcyclic => "rt_class_acyclic",
            Self::Alarm => "alarm",
            Self::Dcp => "dcp",
            Self::Reserved => "reserved",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// DCP Service Types
// ============================================================================

/// DCP Service ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DcpServiceId {
    /// Get (0x03)
    Get = 0x03,
    /// Set (0x04)
    Set = 0x04,
    /// Identify (0x05)
    Identify = 0x05,
    /// Hello (0x06)
    Hello = 0x06,
}

impl DcpServiceId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x03 => Some(Self::Get),
            0x04 => Some(Self::Set),
            0x05 => Some(Self::Identify),
            0x06 => Some(Self::Hello),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Get => "Get",
            Self::Set => "Set",
            Self::Identify => "Identify",
            Self::Hello => "Hello",
        }
    }

    /// Security-relevant service types (Set changes device configuration)
    pub fn is_security_relevant(&self) -> bool {
        matches!(self, Self::Set)
    }
}

impl fmt::Display for DcpServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// DCP Service Type (request/response modifier)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DcpServiceType {
    /// Request (0x00)
    Request = 0x00,
    /// Response Success (0x01)
    ResponseSuccess = 0x01,
    /// Response Unsupported (0x05)
    ResponseUnsupported = 0x05,
}

impl DcpServiceType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Request),
            0x01 => Some(Self::ResponseSuccess),
            0x05 => Some(Self::ResponseUnsupported),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::ResponseSuccess => "Response-Success",
            Self::ResponseUnsupported => "Response-Unsupported",
        }
    }
}

impl fmt::Display for DcpServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// DCP Block Types
// ============================================================================

/// DCP Block option (type + suboption)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcpBlockOption {
    pub option: u8,
    pub suboption: u8,
}

impl DcpBlockOption {
    pub fn name(&self) -> &'static str {
        match (self.option, self.suboption) {
            (0x01, 0x01) => "MAC-Address",
            (0x01, 0x02) => "IP-Parameter",
            (0x01, 0x03) => "Full-IP-Suite",
            (0x02, 0x01) => "Type-of-Station",
            (0x02, 0x02) => "Name-of-Station",
            (0x02, 0x03) => "Device-ID",
            (0x02, 0x04) => "Device-Role",
            (0x02, 0x05) => "Device-Options",
            (0x02, 0x06) => "Alias-Name",
            (0x02, 0x07) => "Device-Instance",
            (0x02, 0x08) => "OEM-Device-ID",
            (0x03, _) => "DHCP",
            (0x04, _) => "Control",
            (0x05, _) => "Device-Initiative",
            (0xFF, _) => "All-Selector",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for DcpBlockOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}.{})", self.name(), self.option, self.suboption)
    }
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// Parsed DCP block
#[derive(Debug, Clone)]
pub struct DcpBlock {
    pub option: DcpBlockOption,
    pub block_length: u16,
    /// Extracted value (for string-type blocks)
    pub value_string: Option<String>,
    /// Raw block data
    pub raw_data: Vec<u8>,
}

/// A fully parsed PROFINET DCP message
#[derive(Debug, Clone)]
pub struct ProfinetMessage {
    /// Frame ID (2 bytes)
    pub frame_id: u16,
    /// Frame type classification
    pub frame_type: FrameType,
    /// DCP Service ID
    pub service_id: Option<DcpServiceId>,
    pub service_id_raw: u8,
    /// DCP Service Type (request/response)
    pub service_type: Option<DcpServiceType>,
    pub service_type_raw: u8,
    /// Transaction ID
    pub xid: u32,
    /// Response delay
    pub response_delay: u16,
    /// DCP data length
    pub dcp_data_length: u16,
    /// Parsed DCP blocks
    pub blocks: Vec<DcpBlock>,
    /// Extracted station name (from Name-of-Station block)
    pub station_name: Option<String>,
    /// Extracted device ID (from Device-ID block)
    pub device_id: Option<String>,
    /// Extracted IP address (from IP-Parameter block)
    pub ip_address: Option<String>,
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadHeader(String),
    BadBlock(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadHeader(msg) => write!(f, "invalid DCP header: {}", msg),
            Self::BadBlock(msg) => write!(f, "DCP block parse error: {}", msg),
        }
    }
}

/// Probe a UDP payload for PROFINET DCP.
///
/// DCP frames have a frame_id in the DCP range (0xFE00-0xFEFF) or
/// alarm range (0xFC00-0xFCFF) and a valid service ID.
pub fn probe_profinet(buf: &[u8]) -> bool {
    if buf.len() < DCP_HEADER_SIZE {
        return false;
    }

    let frame_id = u16::from_be_bytes([buf[0], buf[1]]);
    let frame_type = FrameType::from_frame_id(frame_id);

    // Accept DCP and Alarm frame types
    if !matches!(frame_type, FrameType::Dcp | FrameType::Alarm | FrameType::RtClassAcyclic) {
        return false;
    }

    // Validate service ID
    let service_id = buf[2];
    if DcpServiceId::from_u8(service_id).is_none() {
        return false;
    }

    true
}

/// Parse DCP blocks from the data portion of a DCP frame.
fn parse_dcp_blocks(buf: &[u8]) -> Vec<DcpBlock> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset + 4 <= buf.len() {
        let option = buf[offset];
        let suboption = buf[offset + 1];
        let block_length = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        offset += 4;

        let data_end = (offset + block_length as usize).min(buf.len());
        let raw_data = buf[offset..data_end].to_vec();

        // Try to extract string value for known string-type blocks
        let value_string = match (option, suboption) {
            (0x02, 0x01) | (0x02, 0x02) | (0x02, 0x06) => {
                // Type-of-Station, Name-of-Station, Alias-Name
                // Skip 2-byte block info (block_qualifier)
                if raw_data.len() > 2 {
                    std::str::from_utf8(&raw_data[2..]).ok().map(|s| s.trim_end_matches('\0').to_string())
                } else {
                    std::str::from_utf8(&raw_data).ok().map(|s| s.trim_end_matches('\0').to_string())
                }
            }
            (0x02, 0x03) => {
                // Device-ID: 2-byte block_qualifier + 2-byte vendor_id + 2-byte device_id
                if raw_data.len() >= 6 {
                    Some(format!(
                        "{:04x}:{:04x}",
                        u16::from_be_bytes([raw_data[2], raw_data[3]]),
                        u16::from_be_bytes([raw_data[4], raw_data[5]])
                    ))
                } else {
                    None
                }
            }
            (0x01, 0x02) => {
                // IP-Parameter: 2-byte block_qualifier + 4-byte IP + 4-byte mask + 4-byte gateway
                if raw_data.len() >= 6 {
                    let ip_start = 2;
                    if raw_data.len() >= ip_start + 4 {
                        Some(format!(
                            "{}.{}.{}.{}",
                            raw_data[ip_start],
                            raw_data[ip_start + 1],
                            raw_data[ip_start + 2],
                            raw_data[ip_start + 3]
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        blocks.push(DcpBlock {
            option: DcpBlockOption { option, suboption },
            block_length,
            value_string,
            raw_data,
        });

        // Advance past data, with 2-byte padding alignment
        offset = data_end;
        if block_length % 2 != 0 && offset < buf.len() {
            offset += 1; // padding byte
        }
    }

    blocks
}

/// Parse a complete PROFINET DCP message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<ProfinetMessage, ParseError> {
    if buf.len() < DCP_HEADER_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let frame_id = u16::from_be_bytes([buf[0], buf[1]]);
    let frame_type = FrameType::from_frame_id(frame_id);
    let service_id_raw = buf[2];
    let service_id = DcpServiceId::from_u8(service_id_raw);
    let service_type_raw = buf[3];
    let service_type = DcpServiceType::from_u8(service_type_raw);
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let response_delay = u16::from_be_bytes([buf[8], buf[9]]);
    let dcp_data_length = u16::from_be_bytes([buf[10], buf[11]]);

    // Parse DCP blocks from remaining data
    let block_data_end = (DCP_HEADER_SIZE + dcp_data_length as usize).min(buf.len());
    let blocks = if DCP_HEADER_SIZE < block_data_end {
        parse_dcp_blocks(&buf[DCP_HEADER_SIZE..block_data_end])
    } else {
        Vec::new()
    };

    // Extract well-known fields from blocks
    let mut station_name = None;
    let mut device_id = None;
    let mut ip_address = None;

    for block in &blocks {
        match (block.option.option, block.option.suboption) {
            (0x02, 0x02) => station_name = block.value_string.clone(),
            (0x02, 0x03) => device_id = block.value_string.clone(),
            (0x01, 0x02) => ip_address = block.value_string.clone(),
            _ => {}
        }
    }

    Ok(ProfinetMessage {
        frame_id,
        frame_type,
        service_id,
        service_id_raw,
        service_type,
        service_type_raw,
        xid,
        response_delay,
        dcp_data_length,
        blocks,
        station_name,
        device_id,
        ip_address,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_classification() {
        assert_eq!(FrameType::from_frame_id(0x0100), FrameType::RtClass3Cyclic);
        assert_eq!(FrameType::from_frame_id(0x8100), FrameType::RtClass1Cyclic);
        assert_eq!(FrameType::from_frame_id(0xC100), FrameType::RtClassAcyclic);
        assert_eq!(FrameType::from_frame_id(0xFC10), FrameType::Alarm);
        assert_eq!(FrameType::from_frame_id(0xFE00), FrameType::Dcp);
        assert_eq!(FrameType::from_frame_id(0xFF00), FrameType::Reserved);
    }

    #[test]
    fn test_probe_profinet_dcp_identify() {
        // Minimal DCP Identify request
        let buf = [
            0xFE, 0xFE,             // Frame ID: DCP Identify Multicast
            0x05,                   // Service ID: Identify
            0x00,                   // Service Type: Request
            0x00, 0x00, 0x00, 0x01, // Xid
            0x00, 0x01,             // Response delay
            0x00, 0x04,             // DCP data length
            0xFF, 0xFF, 0x00, 0x00, // All-Selector block
        ];
        assert!(probe_profinet(&buf));
    }

    #[test]
    fn test_probe_profinet_negative() {
        assert!(!probe_profinet(b"HTTP/1.1"));
        assert!(!probe_profinet(&[0x00, 0x01, 0x05, 0x00])); // RT Class 3 with DCP service ID
        assert!(!probe_profinet(&[0xFE, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // bad service ID
    }

    #[test]
    fn test_parse_dcp_identify() {
        let buf = [
            0xFE, 0xFE,             // Frame ID: DCP Identify
            0x05,                   // Service ID: Identify
            0x00,                   // Service Type: Request
            0x00, 0x00, 0x00, 0x42, // Xid = 0x42
            0x00, 0x80,             // Response delay
            0x00, 0x04,             // DCP data length = 4
            0xFF, 0xFF, 0x00, 0x00, // All-Selector block
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.frame_id, 0xFEFE);
        assert_eq!(msg.frame_type, FrameType::Dcp);
        assert_eq!(msg.service_id, Some(DcpServiceId::Identify));
        assert_eq!(msg.xid, 0x42);
        assert_eq!(msg.dcp_data_length, 4);
    }

    #[test]
    fn test_dcp_service_names() {
        assert_eq!(DcpServiceId::Get.name(), "Get");
        assert_eq!(DcpServiceId::Set.name(), "Set");
        assert_eq!(DcpServiceId::Identify.name(), "Identify");
        assert_eq!(DcpServiceId::Hello.name(), "Hello");
    }

    #[test]
    fn test_dcp_block_option_names() {
        let opt = DcpBlockOption { option: 0x02, suboption: 0x02 };
        assert_eq!(opt.name(), "Name-of-Station");
        let opt2 = DcpBlockOption { option: 0x01, suboption: 0x02 };
        assert_eq!(opt2.name(), "IP-Parameter");
    }
}
