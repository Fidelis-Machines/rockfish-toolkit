// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EtherCAT wire protocol parser.
//!
//! Parses EtherCAT frames (EtherType 0x88A4) including the frame header,
//! datagram headers, and mailbox protocol identification.
//!
//! For Suricata app-layer integration, this handles EtherCAT datagrams
//! encapsulated in UDP (EoE tunneling, monitoring taps) as well as
//! providing the framework for raw L2 frame decoding.
//!
//! Reference: IEC 61158-4-12 (EtherCAT Data Link Layer)
//!
//! Wire format:
//!   +------------------------+
//!   | EtherCAT Frame Header  |  2 bytes (length:11, reserved:1, type:4)
//!   +------------------------+
//!   | Datagram 1             |  12-byte header + variable data + 2-byte WKC
//!   +------------------------+
//!   | Datagram 2             |
//!   +------------------------+
//!   | ...                    |
//!   +------------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// EtherCAT EtherType
pub const ETHERCAT_ETHERTYPE: u16 = 0x88A4;

/// Minimum EtherCAT frame size (2-byte header + 12-byte datagram header minimum)
pub const ETHERCAT_MIN_FRAME_SIZE: usize = 2;

/// Datagram header size (command + index + slave_address + length_flags + irq)
pub const DATAGRAM_HEADER_SIZE: usize = 10;

/// Working counter size appended after datagram data
pub const WORKING_COUNTER_SIZE: usize = 2;

// ============================================================================
// EtherCAT Frame Header
// ============================================================================

/// EtherCAT frame type (upper 4 bits of header word)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// EtherCAT command PDU (most common)
    Command = 0x01,
    /// Network Variable
    NetworkVariable = 0x04,
    /// Mailbox
    Mailbox = 0x05,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Command),
            0x04 => Some(Self::NetworkVariable),
            0x05 => Some(Self::Mailbox),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Command => "Command",
            Self::NetworkVariable => "NetworkVariable",
            Self::Mailbox => "Mailbox",
        }
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Parsed EtherCAT frame header (2 bytes)
#[derive(Debug, Clone)]
pub struct EthercatFrameHeader {
    /// Data length in bytes (11 bits)
    pub length: u16,
    /// Reserved bit
    pub reserved: bool,
    /// Frame type (4 bits)
    pub frame_type: u8,
}

// ============================================================================
// EtherCAT Commands
// ============================================================================

/// EtherCAT datagram command type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// No operation
    NOP = 0,
    /// Auto-increment physical read
    APRD = 1,
    /// Auto-increment physical write
    APWR = 2,
    /// Auto-increment physical read-write
    APRW = 3,
    /// Configured address physical read
    FPRD = 4,
    /// Configured address physical write
    FPWR = 5,
    /// Configured address physical read-write
    FPRW = 6,
    /// Broadcast read
    BRD = 7,
    /// Broadcast write
    BWR = 8,
    /// Broadcast read-write
    BRW = 9,
    /// Logical memory read
    LRD = 10,
    /// Logical memory write
    LWR = 11,
    /// Logical memory read-write
    LRW = 12,
    /// Auto-increment physical read multiple write
    ARMW = 13,
    /// Configured address physical read multiple write
    FRMW = 14,
}

impl Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NOP),
            1 => Some(Self::APRD),
            2 => Some(Self::APWR),
            3 => Some(Self::APRW),
            4 => Some(Self::FPRD),
            5 => Some(Self::FPWR),
            6 => Some(Self::FPRW),
            7 => Some(Self::BRD),
            8 => Some(Self::BWR),
            9 => Some(Self::BRW),
            10 => Some(Self::LRD),
            11 => Some(Self::LWR),
            12 => Some(Self::LRW),
            13 => Some(Self::ARMW),
            14 => Some(Self::FRMW),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::NOP => "NOP",
            Self::APRD => "APRD",
            Self::APWR => "APWR",
            Self::APRW => "APRW",
            Self::FPRD => "FPRD",
            Self::FPWR => "FPWR",
            Self::FPRW => "FPRW",
            Self::BRD => "BRD",
            Self::BWR => "BWR",
            Self::BRW => "BRW",
            Self::LRD => "LRD",
            Self::LWR => "LWR",
            Self::LRW => "LRW",
            Self::ARMW => "ARMW",
            Self::FRMW => "FRMW",
        }
    }

    /// Whether this is a cyclic (process data) command
    pub fn is_cyclic(&self) -> bool {
        matches!(self, Self::LRD | Self::LWR | Self::LRW)
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Mailbox Types
// ============================================================================

/// EtherCAT mailbox protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MailboxType {
    /// Error
    ERR = 0x00,
    /// ADS over EtherCAT
    AoE = 0x01,
    /// Ethernet over EtherCAT
    EoE = 0x02,
    /// CANopen over EtherCAT
    CoE = 0x03,
    /// File over EtherCAT
    FoE = 0x04,
    /// Servo over EtherCAT
    SoE = 0x05,
    /// Vendor-specific
    VoE = 0x0F,
}

impl MailboxType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::ERR),
            0x01 => Some(Self::AoE),
            0x02 => Some(Self::EoE),
            0x03 => Some(Self::CoE),
            0x04 => Some(Self::FoE),
            0x05 => Some(Self::SoE),
            0x0F => Some(Self::VoE),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ERR => "ERR",
            Self::AoE => "AoE",
            Self::EoE => "EoE",
            Self::CoE => "CoE",
            Self::FoE => "FoE",
            Self::SoE => "SoE",
            Self::VoE => "VoE",
        }
    }
}

impl fmt::Display for MailboxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// EtherCAT Datagram
// ============================================================================

/// A parsed EtherCAT datagram
#[derive(Debug, Clone)]
pub struct EthercatDatagram {
    /// Command type
    pub command: u8,
    /// Datagram index (used for matching request/response)
    pub index: u8,
    /// Slave address (4 bytes: depends on command type)
    /// For APRD/APWR: auto-increment address (position + offset)
    /// For FPRD/FPWR: configured station address + memory offset
    /// For LRD/LWR/LRW: 32-bit logical address
    pub slave_address: u32,
    /// Data length (11 bits from length/flags word)
    pub data_length: u16,
    /// More datagrams follow (bit 15 of length/flags)
    pub more_follows: bool,
    /// IRQ value
    pub irq: u16,
    /// Working counter (incremented by slaves that processed the datagram)
    pub working_counter: u16,
    /// Mailbox type if this is a mailbox datagram
    pub mailbox_type: Option<MailboxType>,
    /// Whether this is a cyclic (process data) command
    pub is_cyclic: bool,
}

// ============================================================================
// Parsed EtherCAT Message
// ============================================================================

/// A fully parsed EtherCAT message (frame header + datagrams)
#[derive(Debug, Clone)]
pub struct EthercatMessage {
    pub header: EthercatFrameHeader,
    pub datagrams: Vec<EthercatDatagram>,
}

impl EthercatMessage {
    /// Check if this message contains any cyclic (process data) commands
    pub fn has_cyclic_data(&self) -> bool {
        self.datagrams.iter().any(|d| d.is_cyclic)
    }

    /// Check if this message contains mailbox data
    pub fn has_mailbox(&self) -> bool {
        self.datagrams.iter().any(|d| d.mailbox_type.is_some())
    }

    /// Get total data length across all datagrams
    pub fn total_data_length(&self) -> usize {
        self.datagrams.iter().map(|d| d.data_length as usize).sum()
    }
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    InvalidFrameType(u8),
    InvalidCommand(u8),
    BadDatagram(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::InvalidFrameType(t) => write!(f, "invalid frame type: 0x{:02x}", t),
            Self::InvalidCommand(c) => write!(f, "invalid command: 0x{:02x}", c),
            Self::BadDatagram(msg) => write!(f, "datagram parse error: {}", msg),
        }
    }
}

/// Probe a buffer for EtherCAT protocol.
///
/// For UDP encapsulation: checks if the payload looks like a valid EtherCAT
/// frame by examining the frame header and first datagram command byte.
///
/// For raw Ethernet: checks for EtherType 0x88A4 at offset 12-13.
pub fn probe_ethercat(buf: &[u8]) -> bool {
    // Try as raw EtherCAT frame (UDP encapsulated or after EtherType)
    if buf.len() >= 4 {
        let header_word = u16::from_le_bytes([buf[0], buf[1]]);
        let frame_type = ((header_word >> 12) & 0x0F) as u8;
        let length = header_word & 0x07FF;

        // Valid frame type and reasonable length
        if FrameType::from_u8(frame_type).is_some() && (length as usize) <= buf.len() {
            // Check first datagram command byte
            if buf.len() >= 3 {
                let cmd = buf[2];
                if Command::from_u8(cmd).is_some() {
                    return true;
                }
            }
        }
    }

    // Try as raw Ethernet frame with EtherType
    if buf.len() >= 16 {
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype == ETHERCAT_ETHERTYPE {
            return true;
        }
    }

    false
}

/// Read a u16 from buffer in little-endian (EtherCAT is always little-endian).
fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read a u32 from buffer in little-endian.
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

/// Parse the EtherCAT frame header (2 bytes, little-endian).
pub fn parse_frame_header(buf: &[u8]) -> Result<EthercatFrameHeader, ParseError> {
    if buf.len() < ETHERCAT_MIN_FRAME_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let header_word = read_u16_le(buf, 0);
    let length = header_word & 0x07FF;        // bits 0-10
    let reserved = (header_word >> 11) & 1 != 0; // bit 11
    let frame_type = ((header_word >> 12) & 0x0F) as u8; // bits 12-15

    Ok(EthercatFrameHeader {
        length,
        reserved,
        frame_type,
    })
}

/// Try to detect mailbox type from datagram data.
/// Mailbox header: length (2 bytes), address (2 bytes), reserved (2 bytes), type (1 byte), count (1 byte)
fn detect_mailbox_type(data: &[u8]) -> Option<MailboxType> {
    if data.len() >= 8 {
        let mbox_type = data[6] & 0x0F;
        MailboxType::from_u8(mbox_type)
    } else {
        None
    }
}

/// Parse EtherCAT datagrams from the buffer (after the 2-byte frame header).
pub fn parse_datagrams(buf: &[u8]) -> Vec<EthercatDatagram> {
    let mut datagrams = Vec::new();
    let mut offset = 0;

    loop {
        if offset + DATAGRAM_HEADER_SIZE > buf.len() {
            break;
        }

        let command = buf[offset];
        let index = buf[offset + 1];
        let slave_address = read_u32_le(buf, offset + 2);
        let length_flags = read_u16_le(buf, offset + 6);
        let data_length = length_flags & 0x07FF;
        let more_follows = (length_flags >> 15) & 1 != 0;
        let irq = read_u16_le(buf, offset + 8);

        let data_start = offset + DATAGRAM_HEADER_SIZE;
        let data_end = data_start + data_length as usize;
        let wkc_end = data_end + WORKING_COUNTER_SIZE;

        if wkc_end > buf.len() {
            break;
        }

        let working_counter = read_u16_le(buf, data_end);
        let data = &buf[data_start..data_end];

        let cmd = Command::from_u8(command);
        let is_cyclic = cmd.map_or(false, |c| c.is_cyclic());

        // Detect mailbox type for mailbox-capable commands (typically FPRD/FPWR to mailbox address)
        let mailbox_type = if data.len() >= 8 {
            detect_mailbox_type(data)
        } else {
            None
        };

        datagrams.push(EthercatDatagram {
            command,
            index,
            slave_address,
            data_length,
            more_follows,
            irq,
            working_counter,
            mailbox_type,
            is_cyclic,
        });

        if !more_follows {
            break;
        }

        offset = wkc_end;
    }

    datagrams
}

/// Parse a complete EtherCAT message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<EthercatMessage, ParseError> {
    let header = parse_frame_header(buf)?;
    let datagrams = if buf.len() > ETHERCAT_MIN_FRAME_SIZE {
        parse_datagrams(&buf[ETHERCAT_MIN_FRAME_SIZE..])
    } else {
        Vec::new()
    };
    Ok(EthercatMessage { header, datagrams })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_names() {
        assert_eq!(Command::from_u8(0), Some(Command::NOP));
        assert_eq!(Command::from_u8(1), Some(Command::APRD));
        assert_eq!(Command::from_u8(12), Some(Command::LRW));
        assert_eq!(Command::from_u8(255), None);
        assert_eq!(Command::LRW.name(), "LRW");
        assert!(Command::LRW.is_cyclic());
        assert!(!Command::FPRD.is_cyclic());
    }

    #[test]
    fn test_mailbox_types() {
        assert_eq!(MailboxType::from_u8(0x00), Some(MailboxType::ERR));
        assert_eq!(MailboxType::from_u8(0x03), Some(MailboxType::CoE));
        assert_eq!(MailboxType::from_u8(0x05), Some(MailboxType::SoE));
        assert_eq!(MailboxType::from_u8(0xFF), None);
        assert_eq!(MailboxType::CoE.name(), "CoE");
    }

    #[test]
    fn test_parse_frame_header() {
        // Frame type = 0x01 (Command), length = 0x2C (44 bytes)
        // Header word LE: type(4) | reserved(1) | length(11) = 0x1 << 12 | 0 << 11 | 0x2C = 0x102C
        let buf: [u8; 2] = [0x2C, 0x10]; // little-endian: 0x102C
        let header = parse_frame_header(&buf).unwrap();
        assert_eq!(header.length, 0x2C);
        assert_eq!(header.frame_type, 0x01);
        assert!(!header.reserved);
    }

    #[test]
    fn test_parse_datagram() {
        // Build a minimal datagram:
        // command=12 (LRW), index=1, slave_addr=0x00001000, length=4 (no more follows), irq=0
        // data: [0x01, 0x02, 0x03, 0x04], working_counter=1
        let mut buf = Vec::new();
        buf.push(12u8);                           // command: LRW
        buf.push(1u8);                            // index
        buf.extend_from_slice(&0x00001000u32.to_le_bytes()); // slave_address
        buf.extend_from_slice(&4u16.to_le_bytes()); // length_flags (4 bytes, no more follows)
        buf.extend_from_slice(&0u16.to_le_bytes()); // irq
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // data
        buf.extend_from_slice(&1u16.to_le_bytes()); // working_counter

        let datagrams = parse_datagrams(&buf);
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].command, 12);
        assert_eq!(datagrams[0].index, 1);
        assert_eq!(datagrams[0].slave_address, 0x00001000);
        assert_eq!(datagrams[0].data_length, 4);
        assert_eq!(datagrams[0].working_counter, 1);
        assert!(datagrams[0].is_cyclic);
        assert!(!datagrams[0].more_follows);
    }

    #[test]
    fn test_probe_ethercat() {
        // Valid EtherCAT frame: type=0x01, length=12, first datagram cmd=LRW(12)
        let mut buf = vec![0u8; 16];
        // header word: 0x1 << 12 | 12 = 0x100C
        buf[0] = 0x0C;
        buf[1] = 0x10;
        buf[2] = 12; // LRW command
        assert!(probe_ethercat(&buf));

        // Invalid: bad command byte
        buf[2] = 0xFF;
        assert!(!probe_ethercat(&buf));

        // Too short
        assert!(!probe_ethercat(&[0x00]));
    }

    #[test]
    fn test_parse_complete_message() {
        // Build a complete EtherCAT message with one LRW datagram
        let mut buf = Vec::new();
        // Frame header: type=0x01, length=16 (datagram header 10 + data 4 + wkc 2)
        let header_word: u16 = (0x01 << 12) | 16;
        buf.extend_from_slice(&header_word.to_le_bytes());
        // Datagram
        buf.push(12u8);                           // command: LRW
        buf.push(0u8);                            // index
        buf.extend_from_slice(&0x00000000u32.to_le_bytes()); // slave_address
        buf.extend_from_slice(&4u16.to_le_bytes()); // length=4, no more
        buf.extend_from_slice(&0u16.to_le_bytes()); // irq
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // data
        buf.extend_from_slice(&2u16.to_le_bytes()); // working_counter=2

        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.header.frame_type, 0x01);
        assert_eq!(msg.header.length, 16);
        assert_eq!(msg.datagrams.len(), 1);
        assert_eq!(msg.datagrams[0].working_counter, 2);
        assert!(msg.has_cyclic_data());
    }
}
