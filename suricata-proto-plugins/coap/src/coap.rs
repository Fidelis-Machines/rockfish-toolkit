// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! CoAP (Constrained Application Protocol) wire protocol parser.
//!
//! Parses CoAP messages as defined in RFC 7252. CoAP is a lightweight
//! RESTful protocol for constrained IoT devices, running over UDP
//! port 5683 (plaintext) and 5684 (DTLS).
//!
//! Wire format:
//!   +------------------+
//!   | Version (2 bits) |  Always 0x01
//!   | Type (2 bits)    |  CON/NON/ACK/RST
//!   | TKL (4 bits)     |  Token length
//!   +------------------+
//!   | Code (8 bits)    |  class.detail format
//!   +------------------+
//!   | Message ID       |  16 bits
//!   +------------------+
//!   | Token            |  0-8 bytes (TKL length)
//!   +------------------+
//!   | Options          |  variable (delta-encoded)
//!   +------------------+
//!   | 0xFF             |  Payload marker (optional)
//!   +------------------+
//!   | Payload          |  variable
//!   +------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// CoAP version (always 1)
pub const COAP_VERSION: u8 = 0x01;

/// CoAP default UDP port (plaintext)
pub const COAP_PORT: u16 = 5683;

/// CoAP default DTLS port
pub const COAP_DTLS_PORT: u16 = 5684;

/// Payload marker byte
pub const PAYLOAD_MARKER: u8 = 0xFF;

/// Minimum CoAP message size (header only, no token, no options)
pub const COAP_MIN_SIZE: usize = 4;

// ============================================================================
// Message Types
// ============================================================================

/// CoAP message type (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Confirmable (0)
    Con = 0,
    /// Non-confirmable (1)
    Non = 1,
    /// Acknowledgement (2)
    Ack = 2,
    /// Reset (3)
    Rst = 3,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Con),
            1 => Some(Self::Non),
            2 => Some(Self::Ack),
            3 => Some(Self::Rst),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Con => "CON",
            Self::Non => "NON",
            Self::Ack => "ACK",
            Self::Rst => "RST",
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Code Classes and Methods
// ============================================================================

/// CoAP code (class.detail format)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code {
    pub class: u8,
    pub detail: u8,
}

impl Code {
    /// Construct from raw code byte
    pub fn from_raw(raw: u8) -> Self {
        Self {
            class: (raw >> 5) & 0x07,
            detail: raw & 0x1F,
        }
    }

    /// Get raw byte value
    pub fn raw(&self) -> u8 {
        (self.class << 5) | (self.detail & 0x1F)
    }

    /// Check if this is a request code (class 0, detail > 0)
    pub fn is_request(&self) -> bool {
        self.class == 0 && self.detail > 0
    }

    /// Check if this is a success response (class 2)
    pub fn is_success(&self) -> bool {
        self.class == 2
    }

    /// Check if this is a client error (class 4)
    pub fn is_client_error(&self) -> bool {
        self.class == 4
    }

    /// Check if this is a server error (class 5)
    pub fn is_server_error(&self) -> bool {
        self.class == 5
    }

    /// Check if this is an empty message (0.00)
    pub fn is_empty(&self) -> bool {
        self.class == 0 && self.detail == 0
    }

    /// Human-readable method name for requests
    pub fn method_name(&self) -> Option<&'static str> {
        if self.class != 0 {
            return None;
        }
        match self.detail {
            1 => Some("GET"),
            2 => Some("POST"),
            3 => Some("PUT"),
            4 => Some("DELETE"),
            5 => Some("FETCH"),
            6 => Some("PATCH"),
            7 => Some("iPATCH"),
            _ => None,
        }
    }

    /// Human-readable response name
    pub fn response_name(&self) -> Option<&'static str> {
        match (self.class, self.detail) {
            (2, 1) => Some("Created"),
            (2, 2) => Some("Deleted"),
            (2, 3) => Some("Valid"),
            (2, 4) => Some("Changed"),
            (2, 5) => Some("Content"),
            (4, 0) => Some("BadRequest"),
            (4, 1) => Some("Unauthorized"),
            (4, 2) => Some("BadOption"),
            (4, 3) => Some("Forbidden"),
            (4, 4) => Some("NotFound"),
            (4, 5) => Some("MethodNotAllowed"),
            (4, 6) => Some("NotAcceptable"),
            (4, 12) => Some("PreconditionFailed"),
            (4, 13) => Some("RequestEntityTooLarge"),
            (4, 15) => Some("UnsupportedContentFormat"),
            (5, 0) => Some("InternalServerError"),
            (5, 1) => Some("NotImplemented"),
            (5, 2) => Some("BadGateway"),
            (5, 3) => Some("ServiceUnavailable"),
            (5, 4) => Some("GatewayTimeout"),
            (5, 5) => Some("ProxyingNotSupported"),
            _ => None,
        }
    }

    /// Human-readable display name
    pub fn display_name(&self) -> String {
        if let Some(m) = self.method_name() {
            return m.to_string();
        }
        if let Some(r) = self.response_name() {
            return r.to_string();
        }
        if self.is_empty() {
            return "Empty".to_string();
        }
        format!("{}.{:02}", self.class, self.detail)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02} ({})", self.class, self.detail, self.display_name())
    }
}

// ============================================================================
// Options
// ============================================================================

/// Well-known CoAP option numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum OptionNumber {
    IfMatch = 1,
    UriHost = 3,
    ETag = 4,
    IfNoneMatch = 5,
    Observe = 6,
    UriPort = 7,
    LocationPath = 8,
    UriPath = 11,
    ContentFormat = 12,
    MaxAge = 14,
    UriQuery = 15,
    Accept = 17,
    LocationQuery = 20,
    Block2 = 23,
    Block1 = 27,
    Size2 = 28,
    ProxyUri = 35,
    ProxyScheme = 39,
    Size1 = 60,
}

impl OptionNumber {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::IfMatch),
            3 => Some(Self::UriHost),
            4 => Some(Self::ETag),
            5 => Some(Self::IfNoneMatch),
            6 => Some(Self::Observe),
            7 => Some(Self::UriPort),
            8 => Some(Self::LocationPath),
            11 => Some(Self::UriPath),
            12 => Some(Self::ContentFormat),
            14 => Some(Self::MaxAge),
            15 => Some(Self::UriQuery),
            17 => Some(Self::Accept),
            20 => Some(Self::LocationQuery),
            23 => Some(Self::Block2),
            27 => Some(Self::Block1),
            28 => Some(Self::Size2),
            35 => Some(Self::ProxyUri),
            39 => Some(Self::ProxyScheme),
            60 => Some(Self::Size1),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::IfMatch => "If-Match",
            Self::UriHost => "Uri-Host",
            Self::ETag => "ETag",
            Self::IfNoneMatch => "If-None-Match",
            Self::Observe => "Observe",
            Self::UriPort => "Uri-Port",
            Self::LocationPath => "Location-Path",
            Self::UriPath => "Uri-Path",
            Self::ContentFormat => "Content-Format",
            Self::MaxAge => "Max-Age",
            Self::UriQuery => "Uri-Query",
            Self::Accept => "Accept",
            Self::LocationQuery => "Location-Query",
            Self::Block2 => "Block2",
            Self::Block1 => "Block1",
            Self::Size2 => "Size2",
            Self::ProxyUri => "Proxy-Uri",
            Self::ProxyScheme => "Proxy-Scheme",
            Self::Size1 => "Size1",
        }
    }

    /// Is this a string-valued option?
    pub fn is_string(&self) -> bool {
        matches!(
            self,
            Self::UriHost
                | Self::LocationPath
                | Self::UriPath
                | Self::UriQuery
                | Self::LocationQuery
                | Self::ProxyUri
                | Self::ProxyScheme
        )
    }
}

/// Content format identifiers
pub fn content_format_name(id: u16) -> &'static str {
    match id {
        0 => "text/plain",
        40 => "application/link-format",
        41 => "application/xml",
        42 => "application/octet-stream",
        47 => "application/exi",
        50 => "application/json",
        60 => "application/cbor",
        11542 => "application/vnd.oma.lwm2m+tlv",
        11543 => "application/vnd.oma.lwm2m+json",
        _ => "unknown",
    }
}

/// Parsed CoAP option
#[derive(Debug, Clone)]
pub struct CoapOption {
    /// Option number (accumulated delta)
    pub number: u16,
    /// Option name (if known)
    pub name: Option<&'static str>,
    /// Option value as bytes
    pub value: Vec<u8>,
    /// Option value as string (for string-type options)
    pub value_string: Option<String>,
    /// Option value as integer (for uint-type options)
    pub value_uint: Option<u64>,
}

// ============================================================================
// Parsed Message
// ============================================================================

/// A fully parsed CoAP message
#[derive(Debug, Clone)]
pub struct CoapMessage {
    /// Version (always 1)
    pub version: u8,
    /// Message type (CON/NON/ACK/RST)
    pub msg_type: MessageType,
    /// Token length
    pub token_length: u8,
    /// Code (class.detail)
    pub code: Code,
    /// Message ID
    pub message_id: u16,
    /// Token bytes
    pub token: Vec<u8>,
    /// Parsed options
    pub options: Vec<CoapOption>,
    /// Payload bytes (after 0xFF marker)
    pub payload: Vec<u8>,
    /// Extracted URI path (concatenated Uri-Path options)
    pub uri_path: Option<String>,
    /// Extracted URI query (concatenated Uri-Query options)
    pub uri_query: Option<String>,
    /// Content format ID
    pub content_format: Option<u16>,
}

impl CoapMessage {
    /// Get the method name if this is a request
    pub fn method(&self) -> Option<&'static str> {
        self.code.method_name()
    }
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadVersion(u8),
    BadTokenLength(u8),
    BadOption(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadVersion(v) => write!(f, "invalid CoAP version: {}", v),
            Self::BadTokenLength(l) => write!(f, "invalid token length: {}", l),
            Self::BadOption(msg) => write!(f, "option parse error: {}", msg),
        }
    }
}

/// Probe a UDP payload for CoAP.
///
/// Checks that the version bits (upper 2 bits of first byte) are 0x01
/// and the code byte represents a valid CoAP code.
pub fn probe_coap(buf: &[u8]) -> bool {
    if buf.len() < COAP_MIN_SIZE {
        return false;
    }

    // Version is bits 6-7 of byte 0 (upper 2 bits)
    let version = (buf[0] >> 6) & 0x03;
    if version != COAP_VERSION {
        return false;
    }

    // Token length (bits 0-3) must be <= 8
    let tkl = buf[0] & 0x0F;
    if tkl > 8 {
        return false;
    }

    // Validate code byte — must be a valid class
    let code = Code::from_raw(buf[1]);
    // Valid classes: 0 (request/empty), 2 (success), 4 (client error), 5 (server error)
    // Also accept class 7 for signaling messages (RFC 7967)
    match code.class {
        0 | 2 | 4 | 5 | 7 => {}
        _ => return false,
    }

    // For class 0, detail must be 0-7 (empty, GET, POST, PUT, DELETE, FETCH, PATCH, iPATCH)
    if code.class == 0 && code.detail > 7 {
        return false;
    }

    true
}

/// Read an option extended value (RFC 7252 Section 3.1).
fn read_option_ext(buf: &[u8], offset: &mut usize, nibble: u8) -> Result<u16, ParseError> {
    match nibble {
        0..=12 => Ok(nibble as u16),
        13 => {
            if *offset >= buf.len() {
                return Err(ParseError::BadOption("extended delta overflow".into()));
            }
            let val = buf[*offset] as u16 + 13;
            *offset += 1;
            Ok(val)
        }
        14 => {
            if *offset + 1 >= buf.len() {
                return Err(ParseError::BadOption("extended delta overflow".into()));
            }
            let val = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]) + 269;
            *offset += 2;
            Ok(val)
        }
        _ => Err(ParseError::BadOption("reserved delta value 15".into())),
    }
}

/// Parse CoAP options from the buffer.
fn parse_options(buf: &[u8]) -> Result<(Vec<CoapOption>, usize), ParseError> {
    let mut options = Vec::new();
    let mut offset = 0;
    let mut current_number: u16 = 0;

    while offset < buf.len() {
        // Check for payload marker
        if buf[offset] == PAYLOAD_MARKER {
            offset += 1; // skip marker
            break;
        }

        let delta_nibble = (buf[offset] >> 4) & 0x0F;
        let length_nibble = buf[offset] & 0x0F;
        offset += 1;

        let delta = read_option_ext(buf, &mut offset, delta_nibble)?;
        let length = read_option_ext(buf, &mut offset, length_nibble)?;

        current_number += delta;

        let value_end = offset + length as usize;
        if value_end > buf.len() {
            // Truncated option — take what we have
            break;
        }

        let value = buf[offset..value_end].to_vec();

        let known = OptionNumber::from_u16(current_number);
        let name = known.as_ref().map(|o| o.name());

        let value_string = if known.as_ref().map_or(false, |o| o.is_string()) {
            std::str::from_utf8(&value).ok().map(|s| s.to_string())
        } else {
            None
        };

        let value_uint = if !value.is_empty() && value.len() <= 8 && known.is_some() {
            let mut v: u64 = 0;
            for &b in &value {
                v = (v << 8) | b as u64;
            }
            Some(v)
        } else {
            None
        };

        options.push(CoapOption {
            number: current_number,
            name,
            value,
            value_string,
            value_uint,
        });

        offset = value_end;
    }

    Ok((options, offset))
}

/// Parse a complete CoAP message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<CoapMessage, ParseError> {
    if buf.len() < COAP_MIN_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let version = (buf[0] >> 6) & 0x03;
    if version != COAP_VERSION {
        return Err(ParseError::BadVersion(version));
    }

    let msg_type_raw = (buf[0] >> 4) & 0x03;
    let msg_type = MessageType::from_u8(msg_type_raw)
        .ok_or(ParseError::BadVersion(msg_type_raw))?;

    let token_length = buf[0] & 0x0F;
    if token_length > 8 {
        return Err(ParseError::BadTokenLength(token_length));
    }

    let code = Code::from_raw(buf[1]);
    let message_id = u16::from_be_bytes([buf[2], buf[3]]);

    // Extract token
    let token_end = COAP_MIN_SIZE + token_length as usize;
    if buf.len() < token_end {
        return Err(ParseError::TooShort(buf.len()));
    }
    let token = buf[COAP_MIN_SIZE..token_end].to_vec();

    // Parse options and payload
    let (options, payload_offset) = if token_end < buf.len() {
        let (opts, off) = parse_options(&buf[token_end..])?;
        (opts, token_end + off)
    } else {
        (Vec::new(), token_end)
    };

    let payload = if payload_offset < buf.len() {
        buf[payload_offset..].to_vec()
    } else {
        Vec::new()
    };

    // Extract URI path from Uri-Path options (number 11)
    let uri_path_parts: Vec<&str> = options
        .iter()
        .filter(|o| o.number == 11)
        .filter_map(|o| o.value_string.as_deref())
        .collect();
    let uri_path = if !uri_path_parts.is_empty() {
        Some(format!("/{}", uri_path_parts.join("/")))
    } else {
        None
    };

    // Extract URI query from Uri-Query options (number 15)
    let uri_query_parts: Vec<&str> = options
        .iter()
        .filter(|o| o.number == 15)
        .filter_map(|o| o.value_string.as_deref())
        .collect();
    let uri_query = if !uri_query_parts.is_empty() {
        Some(uri_query_parts.join("&"))
    } else {
        None
    };

    // Extract content format (number 12)
    let content_format = options
        .iter()
        .find(|o| o.number == 12)
        .and_then(|o| o.value_uint.map(|v| v as u16));

    Ok(CoapMessage {
        version,
        msg_type,
        token_length,
        code,
        message_id,
        token,
        options,
        payload,
        uri_path,
        uri_query,
        content_format,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_coap_get() {
        // Version=1, Type=CON(0), TKL=0, Code=0.01(GET), MsgID=0x0001
        let buf = [0x40, 0x01, 0x00, 0x01];
        assert!(probe_coap(&buf));
    }

    #[test]
    fn test_probe_coap_negative() {
        // Wrong version
        assert!(!probe_coap(&[0x00, 0x01, 0x00, 0x01])); // version 0
        assert!(!probe_coap(&[0x80, 0x01, 0x00, 0x01])); // version 2
        // Too short
        assert!(!probe_coap(&[0x40, 0x01]));
        // Invalid code class
        assert!(!probe_coap(&[0x40, 0x61, 0x00, 0x01])); // class 3
    }

    #[test]
    fn test_parse_get_request() {
        // CON GET with 2-byte token and Uri-Path option "test"
        let buf = [
            0x42,             // Version=1, Type=CON(0), TKL=2
            0x01,             // Code=0.01 (GET)
            0x00, 0x01,       // Message ID = 1
            0xAA, 0xBB,       // Token
            0xB4,             // Option: delta=11 (Uri-Path), length=4
            b't', b'e', b's', b't',
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.version, 1);
        assert_eq!(msg.msg_type, MessageType::Con);
        assert_eq!(msg.token_length, 2);
        assert_eq!(msg.code.class, 0);
        assert_eq!(msg.code.detail, 1);
        assert_eq!(msg.code.method_name(), Some("GET"));
        assert_eq!(msg.message_id, 1);
        assert_eq!(msg.token, vec![0xAA, 0xBB]);
        assert_eq!(msg.uri_path, Some("/test".to_string()));
    }

    #[test]
    fn test_parse_response_with_payload() {
        // ACK 2.05 Content with payload
        let buf = [
            0x60,             // Version=1, Type=ACK(2), TKL=0
            0x45,             // Code=2.05 (Content)
            0x00, 0x01,       // Message ID
            0xFF,             // Payload marker
            b'H', b'e', b'l', b'l', b'o',
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.msg_type, MessageType::Ack);
        assert_eq!(msg.code.class, 2);
        assert_eq!(msg.code.detail, 5);
        assert_eq!(msg.code.response_name(), Some("Content"));
        assert_eq!(msg.payload, b"Hello");
    }

    #[test]
    fn test_code_display() {
        let get = Code::from_raw(0x01);
        assert_eq!(get.method_name(), Some("GET"));
        assert!(get.is_request());

        let not_found = Code::from_raw(0x84); // 4.04
        assert_eq!(not_found.class, 4);
        assert_eq!(not_found.detail, 4);
        assert_eq!(not_found.response_name(), Some("NotFound"));
        assert!(not_found.is_client_error());

        let empty = Code::from_raw(0x00);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_content_format() {
        assert_eq!(content_format_name(0), "text/plain");
        assert_eq!(content_format_name(50), "application/json");
        assert_eq!(content_format_name(60), "application/cbor");
    }
}
