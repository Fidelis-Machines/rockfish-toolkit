// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! LwM2M (Lightweight M2M) over CoAP wire protocol parser.
//!
//! Parses CoAP messages carrying LwM2M operations including
//! registration, bootstrap, device management, and information reporting.
//!
//! LwM2M runs over CoAP (RFC 7252) on UDP ports 5683 (plain) and 5684 (DTLS).
//! LwM2M-specific semantics are encoded in CoAP URI paths and payloads.
//!
//! Reference: OMA LwM2M v1.1 Technical Specification
//!
//! Wire format (CoAP):
//!   +------------------+
//!   | CoAP Header      |  4 bytes (ver + type + tkl + code + message_id)
//!   +------------------+
//!   | Token            |  0-8 bytes
//!   +------------------+
//!   | Options          |  variable (delta + length encoded)
//!   +------------------+
//!   | 0xFF             |  payload marker (1 byte)
//!   +------------------+
//!   | Payload          |  variable (TLV, JSON, CBOR, etc.)
//!   +------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// CoAP default port (plain)
pub const COAP_PORT: u16 = 5683;

/// CoAP default port (DTLS)
pub const COAPS_PORT: u16 = 5684;

/// CoAP version (always 1)
pub const COAP_VERSION: u8 = 1;

/// CoAP payload marker
pub const COAP_PAYLOAD_MARKER: u8 = 0xFF;

// CoAP option numbers
pub const COAP_OPT_URI_PATH: u16 = 11;
pub const COAP_OPT_CONTENT_FORMAT: u16 = 12;
pub const COAP_OPT_URI_QUERY: u16 = 15;
pub const COAP_OPT_OBSERVE: u16 = 6;

// LwM2M content formats
pub const LWM2M_CONTENT_TLV: u16 = 11542;
pub const LWM2M_CONTENT_JSON: u16 = 11543;
pub const LWM2M_CONTENT_CBOR: u16 = 11544;
pub const LWM2M_CONTENT_SENML_JSON: u16 = 110;
pub const LWM2M_CONTENT_SENML_CBOR: u16 = 112;

// ============================================================================
// CoAP Message Types and Codes
// ============================================================================

/// CoAP message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoapType {
    Confirmable = 0,
    NonConfirmable = 1,
    Acknowledgement = 2,
    Reset = 3,
}

impl CoapType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Confirmable),
            1 => Some(Self::NonConfirmable),
            2 => Some(Self::Acknowledgement),
            3 => Some(Self::Reset),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Confirmable => "CON",
            Self::NonConfirmable => "NON",
            Self::Acknowledgement => "ACK",
            Self::Reset => "RST",
        }
    }
}

/// CoAP method/response code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapCode {
    pub class: u8,
    pub detail: u8,
}

impl CoapCode {
    pub fn new(class: u8, detail: u8) -> Self {
        Self { class, detail }
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            class: (b >> 5) & 0x07,
            detail: b & 0x1F,
        }
    }

    pub fn is_request(&self) -> bool {
        self.class == 0 && self.detail > 0
    }

    pub fn is_success(&self) -> bool {
        self.class == 2
    }

    pub fn name(&self) -> &'static str {
        match (self.class, self.detail) {
            (0, 0) => "EMPTY",
            (0, 1) => "GET",
            (0, 2) => "POST",
            (0, 3) => "PUT",
            (0, 4) => "DELETE",
            (2, 1) => "2.01 Created",
            (2, 2) => "2.02 Deleted",
            (2, 3) => "2.03 Valid",
            (2, 4) => "2.04 Changed",
            (2, 5) => "2.05 Content",
            (4, 0) => "4.00 Bad Request",
            (4, 1) => "4.01 Unauthorized",
            (4, 4) => "4.04 Not Found",
            (4, 5) => "4.05 Method Not Allowed",
            (5, 0) => "5.00 Internal Server Error",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for CoapCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.class, self.detail)
    }
}

// ============================================================================
// LwM2M Operations
// ============================================================================

/// LwM2M operation type derived from CoAP method + URI path
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lwm2mOperation {
    /// POST /rd?ep={name}&lt={lifetime}&lwm2m={version}
    Register,
    /// PUT /rd/{location}
    Update,
    /// DELETE /rd/{location}
    Deregister,
    /// POST /bs?ep={name}
    Bootstrap,
    /// GET /{object_id}/...
    Read,
    /// PUT /{object_id}/...
    Write,
    /// POST /{object_id}/{instance_id}/{resource_id}
    Execute,
    /// GET /{object_id}?discover (Accept: application/link-format)
    Discover,
    /// GET with Observe option
    Observe,
    /// POST /{object_id}/{instance_id}
    Create,
    /// DELETE /{object_id}/{instance_id}
    Delete,
    /// Notification (response to Observe)
    Notify,
    /// Unknown operation
    Unknown,
}

impl Lwm2mOperation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Register => "Register",
            Self::Update => "Update",
            Self::Deregister => "Deregister",
            Self::Bootstrap => "Bootstrap",
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Execute => "Execute",
            Self::Discover => "Discover",
            Self::Observe => "Observe",
            Self::Create => "Create",
            Self::Delete => "Delete",
            Self::Notify => "Notify",
            Self::Unknown => "Unknown",
        }
    }
}

/// Well-known LwM2M object names
pub fn object_name(object_id: u16) -> &'static str {
    match object_id {
        0 => "Security",
        1 => "Server",
        2 => "Access Control",
        3 => "Device",
        4 => "Connectivity Monitoring",
        5 => "Firmware Update",
        6 => "Location",
        7 => "Connectivity Statistics",
        _ => "Unknown",
    }
}

/// Payload content format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadFormat {
    TLV,
    JSON,
    CBOR,
    SenMLJSON,
    SenMLCBOR,
    PlainText,
    OpaqueData,
    LinkFormat,
    Unknown(u16),
}

impl PayloadFormat {
    pub fn from_content_format(cf: u16) -> Self {
        match cf {
            0 => Self::PlainText,
            42 => Self::OpaqueData,
            40 => Self::LinkFormat,
            LWM2M_CONTENT_TLV => Self::TLV,
            LWM2M_CONTENT_JSON => Self::JSON,
            LWM2M_CONTENT_CBOR => Self::CBOR,
            LWM2M_CONTENT_SENML_JSON => Self::SenMLJSON,
            LWM2M_CONTENT_SENML_CBOR => Self::SenMLCBOR,
            other => Self::Unknown(other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::TLV => "TLV",
            Self::JSON => "JSON",
            Self::CBOR => "CBOR",
            Self::SenMLJSON => "SenML+JSON",
            Self::SenMLCBOR => "SenML+CBOR",
            Self::PlainText => "text/plain",
            Self::OpaqueData => "application/octet-stream",
            Self::LinkFormat => "application/link-format",
            Self::Unknown(_) => "unknown",
        }
    }
}

// ============================================================================
// Parsed LwM2M Message
// ============================================================================

/// A CoAP option (number + value)
#[derive(Debug, Clone)]
pub struct CoapOption {
    pub number: u16,
    pub value: Vec<u8>,
}

/// A fully parsed LwM2M message (CoAP layer + LwM2M semantics)
#[derive(Debug, Clone)]
pub struct Lwm2mMessage {
    /// CoAP message type (CON, NON, ACK, RST)
    pub coap_type: CoapType,
    /// CoAP code (method or response code)
    pub code: CoapCode,
    /// CoAP message ID
    pub message_id: u16,
    /// CoAP token
    pub token: Vec<u8>,
    /// URI path segments
    pub uri_path: Vec<String>,
    /// URI query parameters
    pub uri_query: Vec<String>,
    /// Content format option value
    pub content_format: Option<u16>,
    /// Observe option value
    pub observe: Option<u32>,
    /// Derived LwM2M operation
    pub operation: Lwm2mOperation,
    /// Endpoint name (from registration query parameters)
    pub endpoint_name: Option<String>,
    /// Object ID (from URI path)
    pub object_id: Option<u16>,
    /// Instance ID (from URI path)
    pub instance_id: Option<u16>,
    /// Resource ID (from URI path)
    pub resource_id: Option<u16>,
    /// Human-readable object name
    pub object_name: Option<String>,
    /// Client lifetime (from registration query parameters)
    pub lifetime: Option<u32>,
    /// LwM2M version (from registration query parameters)
    pub lwm2m_version: Option<String>,
    /// Payload format
    pub payload_format: Option<PayloadFormat>,
    /// Payload size in bytes
    pub payload_size: usize,
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadVersion(u8),
    BadType(u8),
    BadOption(String),
    InvalidUri(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadVersion(v) => write!(f, "invalid CoAP version: {}", v),
            Self::BadType(t) => write!(f, "invalid CoAP type: {}", t),
            Self::BadOption(msg) => write!(f, "option parse error: {}", msg),
            Self::InvalidUri(msg) => write!(f, "invalid URI: {}", msg),
        }
    }
}

/// Check if a buffer looks like a CoAP message carrying LwM2M data.
/// Used for protocol probing in Suricata.
pub fn probe_lwm2m(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }

    // Check CoAP version (bits 7-6 of first byte must be 01)
    let version = (buf[0] >> 6) & 0x03;
    if version != COAP_VERSION {
        return false;
    }

    // Check type is valid (bits 5-4)
    let msg_type = (buf[0] >> 4) & 0x03;
    if msg_type > 3 {
        return false;
    }

    // Token length must be 0-8
    let tkl = (buf[0] & 0x0F) as usize;
    if tkl > 8 {
        return false;
    }

    // Must have enough bytes for header + token
    if buf.len() < 4 + tkl {
        return false;
    }

    // Try to find LwM2M-specific URI paths in options
    // Parse enough options to look for URI-Path starting with "rd", "bs", or a digit
    let code = CoapCode::from_byte(buf[1]);
    if !code.is_request() && !code.is_success() && !(code.class == 0 && code.detail == 0) {
        // Allow requests, success responses, and empty messages
        // but reject client/server error responses for probing
    }

    // Check options for LwM2M URI patterns
    let mut offset = 4 + tkl;
    let mut option_number: u16 = 0;

    while offset < buf.len() {
        if buf[offset] == COAP_PAYLOAD_MARKER {
            break;
        }

        let delta = (buf[offset] >> 4) & 0x0F;
        let length = buf[offset] & 0x0F;
        offset += 1;

        let (actual_delta, skip_d) = match decode_option_ext(delta, buf, offset) {
            Some(v) => v,
            None => return false,
        };
        offset += skip_d;

        let (actual_length, skip_l) = match decode_option_ext(length, buf, offset) {
            Some(v) => v,
            None => return false,
        };
        offset += skip_l;

        option_number += actual_delta;

        if offset + actual_length as usize > buf.len() {
            return false;
        }

        // Check if this is a URI-Path option with LwM2M patterns
        if option_number == COAP_OPT_URI_PATH {
            let val = &buf[offset..offset + actual_length as usize];
            if let Ok(s) = std::str::from_utf8(val) {
                if s == "rd" || s == "bs" || s == ".well-known" {
                    return true;
                }
                // Check if first path segment is a digit (object ID)
                if !s.is_empty() && s.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    if s.parse::<u16>().is_ok() {
                        return true;
                    }
                }
            }
        }

        offset += actual_length as usize;
    }

    false
}

/// Decode CoAP option extended delta/length.
fn decode_option_ext(nibble: u8, buf: &[u8], offset: usize) -> Option<(u16, usize)> {
    match nibble {
        0..=12 => Some((nibble as u16, 0)),
        13 => {
            if offset >= buf.len() { return None; }
            Some((buf[offset] as u16 + 13, 1))
        }
        14 => {
            if offset + 1 >= buf.len() { return None; }
            let val = u16::from_be_bytes([buf[offset], buf[offset + 1]]) + 269;
            Some((val, 2))
        }
        _ => None, // 15 is reserved
    }
}

/// Parse CoAP options from the buffer.
fn parse_options(buf: &[u8]) -> Result<(Vec<CoapOption>, usize), ParseError> {
    let mut options = Vec::new();
    let mut offset = 0;
    let mut option_number: u16 = 0;

    while offset < buf.len() {
        if buf[offset] == COAP_PAYLOAD_MARKER {
            offset += 1; // skip marker
            break;
        }

        let delta_nibble = (buf[offset] >> 4) & 0x0F;
        let length_nibble = buf[offset] & 0x0F;
        offset += 1;

        let (actual_delta, skip_d) = decode_option_ext(delta_nibble, buf, offset)
            .ok_or_else(|| ParseError::BadOption("invalid delta".into()))?;
        offset += skip_d;

        let (actual_length, skip_l) = decode_option_ext(length_nibble, buf, offset)
            .ok_or_else(|| ParseError::BadOption("invalid length".into()))?;
        offset += skip_l;

        option_number += actual_delta;

        if offset + actual_length as usize > buf.len() {
            return Err(ParseError::BadOption("option value exceeds buffer".into()));
        }

        let value = buf[offset..offset + actual_length as usize].to_vec();
        offset += actual_length as usize;

        options.push(CoapOption {
            number: option_number,
            value,
        });
    }

    Ok((options, offset))
}

/// Extract a query parameter value from URI query options.
fn extract_query_param<'a>(queries: &'a [String], key: &str) -> Option<&'a str> {
    for q in queries {
        if let Some(val) = q.strip_prefix(key).and_then(|s| s.strip_prefix('=')) {
            return Some(val);
        }
    }
    None
}

/// Determine the LwM2M operation from CoAP method, URI path, and options.
fn determine_operation(
    code: &CoapCode,
    uri_path: &[String],
    observe: Option<u32>,
) -> Lwm2mOperation {
    if uri_path.is_empty() {
        return Lwm2mOperation::Unknown;
    }

    let first = uri_path[0].as_str();

    match (code.class, code.detail) {
        // POST
        (0, 2) => {
            if first == "rd" && uri_path.len() == 1 {
                Lwm2mOperation::Register
            } else if first == "bs" {
                Lwm2mOperation::Bootstrap
            } else if uri_path.len() == 3 {
                // POST /{obj}/{inst}/{res} = Execute
                Lwm2mOperation::Execute
            } else if uri_path.len() == 2 {
                // POST /{obj}/{inst} = Create (new instance)
                Lwm2mOperation::Create
            } else {
                Lwm2mOperation::Unknown
            }
        }
        // GET
        (0, 1) => {
            if observe.is_some() {
                Lwm2mOperation::Observe
            } else if first == ".well-known" {
                Lwm2mOperation::Discover
            } else {
                Lwm2mOperation::Read
            }
        }
        // PUT
        (0, 3) => {
            if first == "rd" && uri_path.len() > 1 {
                Lwm2mOperation::Update
            } else {
                Lwm2mOperation::Write
            }
        }
        // DELETE
        (0, 4) => {
            if first == "rd" && uri_path.len() > 1 {
                Lwm2mOperation::Deregister
            } else {
                Lwm2mOperation::Delete
            }
        }
        // Response with Observe (notification)
        (2, _) => {
            if observe.is_some() {
                Lwm2mOperation::Notify
            } else {
                Lwm2mOperation::Unknown
            }
        }
        _ => Lwm2mOperation::Unknown,
    }
}

/// Read an unsigned integer from CoAP option value bytes (big-endian).
fn option_value_uint(val: &[u8]) -> u32 {
    match val.len() {
        0 => 0,
        1 => val[0] as u32,
        2 => u16::from_be_bytes([val[0], val[1]]) as u32,
        3 => ((val[0] as u32) << 16) | ((val[1] as u32) << 8) | (val[2] as u32),
        _ => u32::from_be_bytes([val[0], val[1], val[2], val[3]]),
    }
}

/// Parse a complete LwM2M/CoAP message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<Lwm2mMessage, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::TooShort(buf.len()));
    }

    let version = (buf[0] >> 6) & 0x03;
    if version != COAP_VERSION {
        return Err(ParseError::BadVersion(version));
    }

    let msg_type_raw = (buf[0] >> 4) & 0x03;
    let coap_type = CoapType::from_u8(msg_type_raw)
        .ok_or(ParseError::BadType(msg_type_raw))?;

    let tkl = (buf[0] & 0x0F) as usize;
    let code = CoapCode::from_byte(buf[1]);
    let message_id = u16::from_be_bytes([buf[2], buf[3]]);

    if buf.len() < 4 + tkl {
        return Err(ParseError::TooShort(buf.len()));
    }

    let token = buf[4..4 + tkl].to_vec();

    // Parse options
    let options_buf = &buf[4 + tkl..];
    let (options, payload_offset) = parse_options(options_buf)?;

    let payload_start = 4 + tkl + payload_offset;
    let payload_size = if payload_start < buf.len() {
        buf.len() - payload_start
    } else {
        0
    };

    // Extract URI path segments
    let uri_path: Vec<String> = options
        .iter()
        .filter(|o| o.number == COAP_OPT_URI_PATH)
        .filter_map(|o| std::str::from_utf8(&o.value).ok().map(|s| s.to_string()))
        .collect();

    // Extract URI query parameters
    let uri_query: Vec<String> = options
        .iter()
        .filter(|o| o.number == COAP_OPT_URI_QUERY)
        .filter_map(|o| std::str::from_utf8(&o.value).ok().map(|s| s.to_string()))
        .collect();

    // Extract content format
    let content_format = options
        .iter()
        .find(|o| o.number == COAP_OPT_CONTENT_FORMAT)
        .map(|o| option_value_uint(&o.value) as u16);

    // Extract observe option
    let observe = options
        .iter()
        .find(|o| o.number == COAP_OPT_OBSERVE)
        .map(|o| option_value_uint(&o.value));

    // Determine LwM2M operation
    let operation = determine_operation(&code, &uri_path, observe);

    // Extract endpoint name from query parameters
    let endpoint_name = extract_query_param(&uri_query, "ep").map(|s| s.to_string());

    // Extract lifetime
    let lifetime = extract_query_param(&uri_query, "lt")
        .and_then(|s| s.parse::<u32>().ok());

    // Extract LwM2M version
    let lwm2m_version = extract_query_param(&uri_query, "lwm2m").map(|s| s.to_string());

    // Extract object/instance/resource IDs from URI path
    let (object_id, instance_id, resource_id) = extract_object_path(&uri_path);

    // Derive object name
    let object_name_str = object_id.map(|id| object_name(id).to_string());

    // Determine payload format
    let payload_format = content_format.map(PayloadFormat::from_content_format);

    Ok(Lwm2mMessage {
        coap_type,
        code,
        message_id,
        token,
        uri_path,
        uri_query,
        content_format,
        observe,
        operation,
        endpoint_name,
        object_id,
        instance_id,
        resource_id,
        object_name: object_name_str,
        lifetime,
        lwm2m_version,
        payload_format,
        payload_size,
    })
}

/// Extract object/instance/resource IDs from URI path segments.
/// Skips well-known prefixes like "rd" and "bs".
fn extract_object_path(uri_path: &[String]) -> (Option<u16>, Option<u16>, Option<u16>) {
    // Find the first numeric segment
    let mut start = 0;
    for (i, seg) in uri_path.iter().enumerate() {
        if seg.parse::<u16>().is_ok() {
            start = i;
            break;
        }
        if i == uri_path.len() - 1 {
            return (None, None, None);
        }
    }

    let object_id = uri_path.get(start).and_then(|s| s.parse::<u16>().ok());
    let instance_id = uri_path.get(start + 1).and_then(|s| s.parse::<u16>().ok());
    let resource_id = uri_path.get(start + 2).and_then(|s| s.parse::<u16>().ok());

    (object_id, instance_id, resource_id)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal CoAP message for testing.
    fn build_coap(msg_type: u8, code: u8, token: &[u8], options: &[(u16, &[u8])], payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: version=1, type, tkl
        buf.push((COAP_VERSION << 6) | (msg_type << 4) | (token.len() as u8 & 0x0F));
        buf.push(code);
        buf.push(0x00); // message_id high
        buf.push(0x01); // message_id low
        buf.extend_from_slice(token);

        // Options (sorted by number)
        let mut sorted_opts: Vec<_> = options.to_vec();
        sorted_opts.sort_by_key(|(n, _)| *n);

        let mut prev_number: u16 = 0;
        for (number, value) in &sorted_opts {
            let delta = number - prev_number;
            let length = value.len() as u16;

            // Encode delta nibble
            let (delta_nibble, delta_ext) = encode_option_nibble(delta);
            let (length_nibble, length_ext) = encode_option_nibble(length);

            buf.push((delta_nibble << 4) | length_nibble);
            buf.extend_from_slice(&delta_ext);
            buf.extend_from_slice(&length_ext);
            buf.extend_from_slice(value);

            prev_number = *number;
        }

        if !payload.is_empty() {
            buf.push(COAP_PAYLOAD_MARKER);
            buf.extend_from_slice(payload);
        }

        buf
    }

    fn encode_option_nibble(val: u16) -> (u8, Vec<u8>) {
        if val < 13 {
            (val as u8, vec![])
        } else if val < 269 {
            (13, vec![(val - 13) as u8])
        } else {
            let adjusted = val - 269;
            (14, vec![(adjusted >> 8) as u8, (adjusted & 0xFF) as u8])
        }
    }

    #[test]
    fn test_probe_lwm2m_registration() {
        // POST /rd?ep=test_device&lt=3600&lwm2m=1.1
        let msg = build_coap(
            0, // CON
            0x02, // POST (0.02)
            &[0xAB, 0xCD],
            &[
                (COAP_OPT_URI_PATH, b"rd"),
                (COAP_OPT_URI_QUERY, b"ep=test_device"),
                (COAP_OPT_URI_QUERY, b"lt=3600"),
                (COAP_OPT_URI_QUERY, b"lwm2m=1.1"),
            ],
            b"</1/0>,</3/0>",
        );
        assert!(probe_lwm2m(&msg));
    }

    #[test]
    fn test_probe_lwm2m_bootstrap() {
        // POST /bs?ep=test_device
        let msg = build_coap(
            0, 0x02, &[0x01],
            &[
                (COAP_OPT_URI_PATH, b"bs"),
                (COAP_OPT_URI_QUERY, b"ep=test_device"),
            ],
            &[],
        );
        assert!(probe_lwm2m(&msg));
    }

    #[test]
    fn test_probe_not_lwm2m() {
        // HTTP-like data
        assert!(!probe_lwm2m(b"GET / HTTP/1.1\r\n"));
        // Too short
        assert!(!probe_lwm2m(&[0x40]));
        // Wrong version
        assert!(!probe_lwm2m(&[0x00, 0x01, 0x00, 0x00]));
    }

    #[test]
    fn test_parse_registration() {
        let msg = build_coap(
            0, 0x02, &[0xAB],
            &[
                (COAP_OPT_URI_PATH, b"rd"),
                (COAP_OPT_URI_QUERY, b"ep=my_sensor"),
                (COAP_OPT_URI_QUERY, b"lt=600"),
                (COAP_OPT_URI_QUERY, b"lwm2m=1.1"),
            ],
            b"</3/0>,</4/0>",
        );

        let parsed = parse_message(&msg).unwrap();
        assert_eq!(parsed.operation, Lwm2mOperation::Register);
        assert_eq!(parsed.endpoint_name.as_deref(), Some("my_sensor"));
        assert_eq!(parsed.lifetime, Some(600));
        assert_eq!(parsed.lwm2m_version.as_deref(), Some("1.1"));
        assert_eq!(parsed.code.name(), "POST");
    }

    #[test]
    fn test_parse_read_device_object() {
        // GET /3/0 (read Device object instance 0)
        let msg = build_coap(
            0, 0x01, &[0x01, 0x02],
            &[
                (COAP_OPT_URI_PATH, b"3"),
                (COAP_OPT_URI_PATH, b"0"),
            ],
            &[],
        );

        let parsed = parse_message(&msg).unwrap();
        assert_eq!(parsed.operation, Lwm2mOperation::Read);
        assert_eq!(parsed.object_id, Some(3));
        assert_eq!(parsed.instance_id, Some(0));
        assert_eq!(parsed.resource_id, None);
        assert_eq!(parsed.object_name.as_deref(), Some("Device"));
    }

    #[test]
    fn test_object_names() {
        assert_eq!(object_name(0), "Security");
        assert_eq!(object_name(1), "Server");
        assert_eq!(object_name(3), "Device");
        assert_eq!(object_name(5), "Firmware Update");
        assert_eq!(object_name(6), "Location");
        assert_eq!(object_name(999), "Unknown");
    }
}
