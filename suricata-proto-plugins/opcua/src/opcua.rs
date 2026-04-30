// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! OPC UA (Open Platform Communications Unified Architecture) wire protocol parser.
//!
//! Parses the OPC UA binary protocol over TCP (port 4840).
//!
//! Reference: OPC UA Specification Part 6 — Mappings
//!
//! Wire format:
//!   +------------------+
//!   | Message Header   |  8 bytes (type[3] + chunk[1] + size[4])
//!   +------------------+
//!   | Secure Channel   |  Variable (channel ID, token, sequence)
//!   +------------------+
//!   | Service Request  |  Variable (node ID encoded service)
//!   +------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// OPC UA default TCP port
pub const OPCUA_PORT: u16 = 4840;

/// Minimum message size (header only)
pub const OPCUA_MIN_MSG_SIZE: usize = 8;

// ============================================================================
// Message Types
// ============================================================================

/// OPC UA message type (3-byte ASCII header)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Hello — client connection initiation
    Hello,
    /// Acknowledge — server response to Hello
    Acknowledge,
    /// Error — error response
    Error,
    /// OpenSecureChannel request/response
    OpenSecureChannel,
    /// CloseSecureChannel request/response
    CloseSecureChannel,
    /// Generic secured message (contains service requests)
    Message,
    /// Reverse Hello (server-initiated)
    ReverseHello,
}

impl MessageType {
    pub fn from_bytes(b: &[u8; 3]) -> Option<Self> {
        match b {
            b"HEL" => Some(Self::Hello),
            b"ACK" => Some(Self::Acknowledge),
            b"ERR" => Some(Self::Error),
            b"OPN" => Some(Self::OpenSecureChannel),
            b"CLO" => Some(Self::CloseSecureChannel),
            b"MSG" => Some(Self::Message),
            b"RHE" => Some(Self::ReverseHello),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::Acknowledge => "Acknowledge",
            Self::Error => "Error",
            Self::OpenSecureChannel => "OpenSecureChannel",
            Self::CloseSecureChannel => "CloseSecureChannel",
            Self::Message => "Message",
            Self::ReverseHello => "ReverseHello",
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Chunk type (4th byte of header)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    /// Final chunk
    Final,
    /// Intermediate chunk
    Intermediate,
    /// Abort
    Abort,
}

impl ChunkType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'F' => Some(Self::Final),
            b'C' => Some(Self::Intermediate),
            b'A' => Some(Self::Abort),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Final => "Final",
            Self::Intermediate => "Intermediate",
            Self::Abort => "Abort",
        }
    }
}

// ============================================================================
// Security Mode
// ============================================================================

/// OPC UA security mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    None,
    Sign,
    SignAndEncrypt,
}

impl SecurityMode {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::None,
            2 => Self::Sign,
            3 => Self::SignAndEncrypt,
            _ => Self::None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Sign => "Sign",
            Self::SignAndEncrypt => "SignAndEncrypt",
        }
    }
}

impl fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Service Types
// ============================================================================

/// Known OPC UA service request/response types (by numeric node ID)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    CreateSession,
    ActivateSession,
    CloseSession,
    Read,
    Write,
    Browse,
    BrowseNext,
    Call,
    Publish,
    CreateSubscription,
    DeleteSubscription,
    CreateMonitoredItems,
    TranslateBrowsePathsToNodeIds,
    OpenSecureChannel,
    CloseSecureChannel,
    GetEndpoints,
    FindServers,
    Unknown(u16),
}

impl ServiceType {
    /// Decode from the expanded node ID numeric identifier.
    /// These are the well-known request node IDs from the OPC UA spec.
    pub fn from_node_id(id: u16) -> Self {
        match id {
            461 | 462 => Self::CreateSession,
            467 | 468 => Self::ActivateSession,
            473 | 474 => Self::CloseSession,
            631 | 632 => Self::Read,
            673 | 674 => Self::Write,
            527 | 528 => Self::Browse,
            533 | 534 => Self::BrowseNext,
            712 | 713 => Self::Call,
            826 | 827 => Self::Publish,
            787 | 788 => Self::CreateSubscription,
            847 | 848 => Self::DeleteSubscription,
            751 | 752 => Self::CreateMonitoredItems,
            554 | 555 => Self::TranslateBrowsePathsToNodeIds,
            446 | 449 => Self::OpenSecureChannel,
            452 | 453 => Self::CloseSecureChannel,
            428 | 429 => Self::GetEndpoints,
            422 | 423 => Self::FindServers,
            _ => Self::Unknown(id),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateSession => "CreateSession",
            Self::ActivateSession => "ActivateSession",
            Self::CloseSession => "CloseSession",
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Browse => "Browse",
            Self::BrowseNext => "BrowseNext",
            Self::Call => "Call",
            Self::Publish => "Publish",
            Self::CreateSubscription => "CreateSubscription",
            Self::DeleteSubscription => "DeleteSubscription",
            Self::CreateMonitoredItems => "CreateMonitoredItems",
            Self::TranslateBrowsePathsToNodeIds => "TranslateBrowsePathsToNodeIds",
            Self::OpenSecureChannel => "OpenSecureChannel",
            Self::CloseSecureChannel => "CloseSecureChannel",
            Self::GetEndpoints => "GetEndpoints",
            Self::FindServers => "FindServers",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "Unknown({})", id),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// OPC UA message header (first 8 bytes)
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub message_type: MessageType,
    pub chunk_type: ChunkType,
    pub message_size: u32,
}

/// Hello message fields
#[derive(Debug, Clone)]
pub struct HelloMessage {
    pub protocol_version: u32,
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
    pub endpoint_url: String,
}

/// Acknowledge message fields
#[derive(Debug, Clone)]
pub struct AcknowledgeMessage {
    pub protocol_version: u32,
    pub receive_buffer_size: u32,
    pub send_buffer_size: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
}

/// Error message fields
#[derive(Debug, Clone)]
pub struct ErrorMessage {
    pub error_code: u32,
    pub reason: String,
}

/// Secure channel header (present in OPN, CLO, MSG)
#[derive(Debug, Clone)]
pub struct SecureChannelHeader {
    pub secure_channel_id: u32,
    pub security_token_id: u32,
    pub sequence_number: u32,
    pub request_id: u32,
}

/// A fully parsed OPC UA message
#[derive(Debug, Clone)]
pub struct OpcuaMessage {
    pub header: MessageHeader,
    pub content: MessageContent,
}

/// Decoded message content
#[derive(Debug, Clone)]
pub enum MessageContent {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Secure(SecureMessageContent),
    /// Unparsed content
    Raw(Vec<u8>),
}

/// Content of a secured message (OPN, CLO, MSG)
#[derive(Debug, Clone)]
pub struct SecureMessageContent {
    pub channel_header: SecureChannelHeader,
    pub security_policy: Option<String>,
    pub security_mode: SecurityMode,
    pub service_type: Option<ServiceType>,
    pub node_ids: Vec<String>,
    pub status_code: u32,
    pub endpoint_url: Option<String>,
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadMessageType,
    BadChunkType,
    InvalidField(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadMessageType => write!(f, "invalid OPC UA message type"),
            Self::BadChunkType => write!(f, "invalid chunk type byte"),
            Self::InvalidField(msg) => write!(f, "invalid field: {}", msg),
        }
    }
}

/// Check if a buffer starts with an OPC UA message header.
/// Used for protocol probing in Suricata.
pub fn probe_opcua(buf: &[u8]) -> bool {
    if buf.len() < OPCUA_MIN_MSG_SIZE {
        return false;
    }
    let type_bytes: [u8; 3] = [buf[0], buf[1], buf[2]];
    if MessageType::from_bytes(&type_bytes).is_none() {
        return false;
    }
    // Validate chunk type
    if ChunkType::from_byte(buf[3]).is_none() {
        return false;
    }
    // Validate message size is reasonable
    let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    size >= OPCUA_MIN_MSG_SIZE as u32 && size <= 0x00FF_FFFF
}

/// Read a u32 little-endian from buffer
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

/// Read an OPC UA byte string (4-byte length prefix + data).
/// Returns (string_value, bytes_consumed).
fn read_ua_string(buf: &[u8], offset: usize) -> Result<(String, usize), ParseError> {
    if offset + 4 > buf.len() {
        return Err(ParseError::TooShort(buf.len()));
    }
    let len = read_u32_le(buf, offset) as i32;
    if len < 0 {
        // Null string
        return Ok((String::new(), 4));
    }
    let len = len as usize;
    if offset + 4 + len > buf.len() {
        return Err(ParseError::TooShort(buf.len()));
    }
    let s = std::str::from_utf8(&buf[offset + 4..offset + 4 + len])
        .unwrap_or("<invalid utf8>")
        .to_string();
    Ok((s, 4 + len))
}

/// Parse the message header (first 8 bytes).
pub fn parse_header(buf: &[u8]) -> Result<MessageHeader, ParseError> {
    if buf.len() < OPCUA_MIN_MSG_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }
    let type_bytes: [u8; 3] = [buf[0], buf[1], buf[2]];
    let message_type =
        MessageType::from_bytes(&type_bytes).ok_or(ParseError::BadMessageType)?;
    let chunk_type = ChunkType::from_byte(buf[3]).ok_or(ParseError::BadChunkType)?;
    let message_size = read_u32_le(buf, 4);

    Ok(MessageHeader {
        message_type,
        chunk_type,
        message_size,
    })
}

/// Parse a Hello message body (after 8-byte header).
fn parse_hello(buf: &[u8]) -> Result<HelloMessage, ParseError> {
    if buf.len() < 28 {
        return Err(ParseError::TooShort(buf.len()));
    }
    let protocol_version = read_u32_le(buf, 0);
    let receive_buffer_size = read_u32_le(buf, 4);
    let send_buffer_size = read_u32_le(buf, 8);
    let max_message_size = read_u32_le(buf, 12);
    let max_chunk_count = read_u32_le(buf, 16);
    let (endpoint_url, _) = read_ua_string(buf, 20)?;

    Ok(HelloMessage {
        protocol_version,
        receive_buffer_size,
        send_buffer_size,
        max_message_size,
        max_chunk_count,
        endpoint_url,
    })
}

/// Parse an Acknowledge message body.
fn parse_acknowledge(buf: &[u8]) -> Result<AcknowledgeMessage, ParseError> {
    if buf.len() < 20 {
        return Err(ParseError::TooShort(buf.len()));
    }
    Ok(AcknowledgeMessage {
        protocol_version: read_u32_le(buf, 0),
        receive_buffer_size: read_u32_le(buf, 4),
        send_buffer_size: read_u32_le(buf, 8),
        max_message_size: read_u32_le(buf, 12),
        max_chunk_count: read_u32_le(buf, 16),
    })
}

/// Parse an Error message body.
fn parse_error(buf: &[u8]) -> Result<ErrorMessage, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::TooShort(buf.len()));
    }
    let error_code = read_u32_le(buf, 0);
    let reason = if buf.len() >= 8 {
        read_ua_string(buf, 4).map(|(s, _)| s).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(ErrorMessage { error_code, reason })
}

/// Decode a NodeId from the buffer. Returns (namespace_index, numeric_id, bytes_consumed).
fn decode_node_id(buf: &[u8], offset: usize) -> Option<(u16, u16, usize)> {
    if offset >= buf.len() {
        return None;
    }
    let encoding = buf[offset];
    match encoding & 0x0F {
        0x00 => {
            // Two-byte node ID
            if offset + 2 > buf.len() {
                return None;
            }
            Some((0, buf[offset + 1] as u16, 2))
        }
        0x01 => {
            // Four-byte node ID
            if offset + 4 > buf.len() {
                return None;
            }
            let ns = buf[offset + 1] as u16;
            let id = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]);
            Some((ns, id, 4))
        }
        _ => None,
    }
}

/// Parse a secure message (OPN, CLO, MSG) body.
fn parse_secure_message(
    buf: &[u8],
    msg_type: MessageType,
) -> Result<SecureMessageContent, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::TooShort(buf.len()));
    }

    let secure_channel_id = read_u32_le(buf, 0);
    let mut offset = 4;

    let mut security_policy = None;
    let mut security_mode = SecurityMode::None;

    // OPN messages have security header with policy URI
    if msg_type == MessageType::OpenSecureChannel {
        if offset + 4 <= buf.len() {
            let (policy, consumed) = read_ua_string(buf, offset).unwrap_or((String::new(), 4));
            if !policy.is_empty() {
                security_policy = Some(policy);
            }
            offset += consumed;
        }
        // Skip sender certificate and receiver certificate thumbprint
        // sender certificate
        if offset + 4 <= buf.len() {
            let cert_len = read_u32_le(buf, offset) as i32;
            offset += 4;
            if cert_len > 0 {
                offset += cert_len as usize;
            }
        }
        // receiver certificate thumbprint
        if offset + 4 <= buf.len() {
            let thumb_len = read_u32_le(buf, offset) as i32;
            offset += 4;
            if thumb_len > 0 {
                offset += thumb_len as usize;
            }
        }
    }

    // Sequence header (sequence number + request ID)
    let mut sequence_number = 0;
    let mut request_id = 0;
    if offset + 8 <= buf.len() {
        sequence_number = read_u32_le(buf, offset);
        request_id = read_u32_le(buf, offset + 4);
        offset += 8;
    }

    let security_token_id = 0;

    // Try to decode the service node ID from the body
    let mut service_type = None;
    let mut node_ids = Vec::new();
    let status_code = 0u32;
    let mut endpoint_url = None;

    if offset < buf.len() {
        if let Some((ns, id, consumed)) = decode_node_id(buf, offset) {
            let svc = ServiceType::from_node_id(id);
            service_type = Some(svc);
            node_ids.push(format!("ns={}; i={}", ns, id));
            offset += consumed;

            // Try to extract security mode from OpenSecureChannel request body
            if msg_type == MessageType::OpenSecureChannel {
                // Skip request header (many fields) — look for security mode field
                // The security mode is at a known offset in the OPN request
                if offset + 32 <= buf.len() {
                    // Skip authentication token, timestamp, request handle, etc.
                    let mode_val = read_u32_le(buf, offset + 16);
                    if mode_val >= 1 && mode_val <= 3 {
                        security_mode = SecurityMode::from_u32(mode_val);
                    }
                }
            }

            // For MSG messages, try to extract endpoint URL from CreateSession
            if matches!(svc, ServiceType::CreateSession) && offset + 20 <= buf.len() {
                // Try to find endpoint URL in the body
                if let Ok((url, _)) = read_ua_string(buf, offset.min(buf.len().saturating_sub(4)))
                {
                    if url.starts_with("opc.tcp://") {
                        endpoint_url = Some(url);
                    }
                }
            }
        }
    }

    Ok(SecureMessageContent {
        channel_header: SecureChannelHeader {
            secure_channel_id,
            security_token_id,
            sequence_number,
            request_id,
        },
        security_policy,
        security_mode,
        service_type,
        node_ids,
        status_code,
        endpoint_url,
    })
}

/// Parse a complete OPC UA message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<OpcuaMessage, ParseError> {
    let header = parse_header(buf)?;
    let body = &buf[OPCUA_MIN_MSG_SIZE..];

    let content = match header.message_type {
        MessageType::Hello => MessageContent::Hello(parse_hello(body)?),
        MessageType::Acknowledge => MessageContent::Acknowledge(parse_acknowledge(body)?),
        MessageType::Error => MessageContent::Error(parse_error(body)?),
        MessageType::OpenSecureChannel
        | MessageType::CloseSecureChannel
        | MessageType::Message => {
            MessageContent::Secure(parse_secure_message(body, header.message_type)?)
        }
        _ => MessageContent::Raw(body.to_vec()),
    };

    Ok(OpcuaMessage { header, content })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_opcua_hello() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"HELF"); // HEL + Final chunk
        buf.extend_from_slice(&32u32.to_le_bytes()); // message size
        buf.extend_from_slice(&[0u8; 24]); // body padding
        assert!(probe_opcua(&buf));
    }

    #[test]
    fn test_probe_opcua_msg() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"MSGF");
        buf.extend_from_slice(&64u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 56]);
        assert!(probe_opcua(&buf));
    }

    #[test]
    fn test_probe_opcua_invalid() {
        assert!(!probe_opcua(b"HTTP/1.1"));
        assert!(!probe_opcua(b"HEL")); // too short
        assert!(!probe_opcua(b"XXXF\x08\x00\x00\x00")); // bad type
    }

    #[test]
    fn test_parse_header() {
        let mut buf = vec![0u8; 8];
        buf[0..3].copy_from_slice(b"OPN");
        buf[3] = b'F';
        buf[4..8].copy_from_slice(&128u32.to_le_bytes());

        let header = parse_header(&buf).unwrap();
        assert_eq!(header.message_type, MessageType::OpenSecureChannel);
        assert_eq!(header.chunk_type, ChunkType::Final);
        assert_eq!(header.message_size, 128);
    }

    #[test]
    fn test_parse_hello_message() {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(b"HELF");
        let size_placeholder = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes()); // placeholder

        // Body
        buf.extend_from_slice(&0u32.to_le_bytes()); // protocol version
        buf.extend_from_slice(&8192u32.to_le_bytes()); // receive buffer
        buf.extend_from_slice(&8192u32.to_le_bytes()); // send buffer
        buf.extend_from_slice(&0u32.to_le_bytes()); // max message size
        buf.extend_from_slice(&0u32.to_le_bytes()); // max chunk count

        let url = b"opc.tcp://localhost:4840";
        buf.extend_from_slice(&(url.len() as u32).to_le_bytes());
        buf.extend_from_slice(url);

        let total_size = buf.len() as u32;
        buf[size_placeholder..size_placeholder + 4]
            .copy_from_slice(&total_size.to_le_bytes());

        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.header.message_type, MessageType::Hello);
        if let MessageContent::Hello(hello) = &msg.content {
            assert_eq!(hello.endpoint_url, "opc.tcp://localhost:4840");
            assert_eq!(hello.receive_buffer_size, 8192);
        } else {
            panic!("Expected Hello content");
        }
    }

    #[test]
    fn test_message_type_names() {
        assert_eq!(MessageType::Hello.name(), "Hello");
        assert_eq!(MessageType::OpenSecureChannel.name(), "OpenSecureChannel");
        assert_eq!(MessageType::Message.name(), "Message");
    }

    #[test]
    fn test_security_mode() {
        assert_eq!(SecurityMode::from_u32(1).name(), "None");
        assert_eq!(SecurityMode::from_u32(2).name(), "Sign");
        assert_eq!(SecurityMode::from_u32(3).name(), "SignAndEncrypt");
    }
}
