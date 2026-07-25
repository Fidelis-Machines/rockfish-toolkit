// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! IEC 61850 MMS (Manufacturing Message Specification) wire protocol parser.
//!
//! Parses MMS over TPKT/COTP on TCP port 102, used by IEC 61850 for
//! substation automation and power grid SCADA communication.
//!
//! Wire format:
//!   +------------------+
//!   | TPKT Header      |  4 bytes (0x03, 0x00, length_hi, length_lo)
//!   +------------------+
//!   | COTP Header      |  variable (length byte + PDU type + ...)
//!   +------------------+
//!   | MMS PDU          |  ASN.1 BER-encoded MMS message
//!   |  (context tag)   |  Identifies PDU type
//!   |  (length)        |  BER length encoding
//!   |  (contents)      |  PDU-specific fields
//!   +------------------+
//!
//! IEC 61850 object model mapped to MMS:
//!   - Logical Device  → MMS Domain
//!   - Logical Node    → MMS Named Variable
//!   - Data Object     → MMS Variable
//!   - Naming: LDName/LNName$FC$DOName$DAName
//!
//! References:
//!   - IEC 61850-8-1: Communication mapping to MMS
//!   - ISO 9506 (MMS)
//!   - RFC 1006 (TPKT)

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// TPKT version (always 3)
pub const TPKT_VERSION: u8 = 0x03;

/// TPKT reserved byte (always 0)
pub const TPKT_RESERVED: u8 = 0x00;

/// Minimum TPKT header size
pub const TPKT_HEADER_SIZE: usize = 4;

/// MMS over TCP port
pub const MMS_PORT: u16 = 102;

/// S7comm magic byte (used to distinguish from MMS)
pub const S7COMM_MAGIC: u8 = 0x32;

// COTP PDU types
pub const COTP_CR: u8 = 0xE0; // Connection Request
pub const COTP_CC: u8 = 0xD0; // Connection Confirm
pub const COTP_DT: u8 = 0xF0; // Data Transfer
pub const COTP_DR: u8 = 0x80; // Disconnect Request
pub const COTP_DC: u8 = 0xC0; // Disconnect Confirm

// MMS PDU context tags (ASN.1 BER)
pub const MMS_CONFIRMED_REQUEST: u8 = 0xA0;
pub const MMS_CONFIRMED_RESPONSE: u8 = 0xA1;
pub const MMS_CONFIRMED_ERROR: u8 = 0xA2;
pub const MMS_UNCONFIRMED: u8 = 0xA3;
pub const MMS_REJECT: u8 = 0xA4;
pub const MMS_CANCEL_REQUEST: u8 = 0xA5;
pub const MMS_CANCEL_RESPONSE: u8 = 0xA6;
pub const MMS_CANCEL_ERROR: u8 = 0xA7;
pub const MMS_INITIATE_REQUEST: u8 = 0xA8;
pub const MMS_INITIATE_RESPONSE: u8 = 0xA9;
pub const MMS_INITIATE_ERROR: u8 = 0xAA;
pub const MMS_CONCLUDE_REQUEST: u8 = 0xAB;
pub const MMS_CONCLUDE_RESPONSE: u8 = 0xAC;
pub const MMS_CONCLUDE_ERROR: u8 = 0xAD;

// MMS Confirmed Service request tags (within Confirmed-Request PDU)
pub const MMS_SVC_GET_NAME_LIST: u8 = 0xA1;
pub const MMS_SVC_READ: u8 = 0xA4;
pub const MMS_SVC_WRITE: u8 = 0xA5;
pub const MMS_SVC_GET_VAR_ACCESS_ATTR: u8 = 0xA6;
pub const MMS_SVC_DEFINE_NAMED_VAR_LIST: u8 = 0xAB;
pub const MMS_SVC_DELETE_NAMED_VAR_LIST: u8 = 0xAC;

// ============================================================================
// MMS PDU Types
// ============================================================================

/// MMS PDU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmsPduType {
    ConfirmedRequest,
    ConfirmedResponse,
    ConfirmedError,
    Unconfirmed,
    Reject,
    InitiateRequest,
    InitiateResponse,
    InitiateError,
    ConcludeRequest,
    ConcludeResponse,
    ConcludeError,
    CancelRequest,
    CancelResponse,
    CancelError,
}

impl MmsPduType {
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            MMS_CONFIRMED_REQUEST => Some(Self::ConfirmedRequest),
            MMS_CONFIRMED_RESPONSE => Some(Self::ConfirmedResponse),
            MMS_CONFIRMED_ERROR => Some(Self::ConfirmedError),
            MMS_UNCONFIRMED => Some(Self::Unconfirmed),
            MMS_REJECT => Some(Self::Reject),
            MMS_INITIATE_REQUEST => Some(Self::InitiateRequest),
            MMS_INITIATE_RESPONSE => Some(Self::InitiateResponse),
            MMS_INITIATE_ERROR => Some(Self::InitiateError),
            MMS_CONCLUDE_REQUEST => Some(Self::ConcludeRequest),
            MMS_CONCLUDE_RESPONSE => Some(Self::ConcludeResponse),
            MMS_CONCLUDE_ERROR => Some(Self::ConcludeError),
            MMS_CANCEL_REQUEST => Some(Self::CancelRequest),
            MMS_CANCEL_RESPONSE => Some(Self::CancelResponse),
            MMS_CANCEL_ERROR => Some(Self::CancelError),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ConfirmedRequest => "confirmed-request",
            Self::ConfirmedResponse => "confirmed-response",
            Self::ConfirmedError => "confirmed-error",
            Self::Unconfirmed => "unconfirmed",
            Self::Reject => "reject",
            Self::InitiateRequest => "initiate-request",
            Self::InitiateResponse => "initiate-response",
            Self::InitiateError => "initiate-error",
            Self::ConcludeRequest => "conclude-request",
            Self::ConcludeResponse => "conclude-response",
            Self::ConcludeError => "conclude-error",
            Self::CancelRequest => "cancel-request",
            Self::CancelResponse => "cancel-response",
            Self::CancelError => "cancel-error",
        }
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            Self::ConfirmedRequest | Self::ConfirmedResponse | Self::ConfirmedError
        )
    }
}

/// MMS service type (within Confirmed-Request/Response)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmsService {
    Read,
    Write,
    GetNameList,
    GetVariableAccessAttributes,
    DefineNamedVariableList,
    DeleteNamedVariableList,
    InformationReport,
    Unknown(u8),
}

impl MmsService {
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            MMS_SVC_READ => Self::Read,
            MMS_SVC_WRITE => Self::Write,
            MMS_SVC_GET_NAME_LIST => Self::GetNameList,
            MMS_SVC_GET_VAR_ACCESS_ATTR => Self::GetVariableAccessAttributes,
            MMS_SVC_DEFINE_NAMED_VAR_LIST => Self::DefineNamedVariableList,
            MMS_SVC_DELETE_NAMED_VAR_LIST => Self::DeleteNamedVariableList,
            _ => Self::Unknown(tag),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::GetNameList => "getnamelist",
            Self::GetVariableAccessAttributes => "getVariableAccessAttributes",
            Self::DefineNamedVariableList => "defineNamedVariableList",
            Self::DeleteNamedVariableList => "deleteNamedVariableList",
            Self::InformationReport => "informationReport",
            Self::Unknown(_) => "unknown",
        }
    }
}

// ============================================================================
// COTP PDU
// ============================================================================

/// COTP PDU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CotpPduType {
    ConnectionRequest,
    ConnectionConfirm,
    DataTransfer,
    DisconnectRequest,
    DisconnectConfirm,
    Unknown(u8),
}

impl CotpPduType {
    pub fn from_byte(b: u8) -> Self {
        match b & 0xF0 {
            0xE0 => Self::ConnectionRequest,
            0xD0 => Self::ConnectionConfirm,
            0xF0 => Self::DataTransfer,
            0x80 => Self::DisconnectRequest,
            0xC0 => Self::DisconnectConfirm,
            _ => Self::Unknown(b),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ConnectionRequest => "CR",
            Self::ConnectionConfirm => "CC",
            Self::DataTransfer => "DT",
            Self::DisconnectRequest => "DR",
            Self::DisconnectConfirm => "DC",
            Self::Unknown(_) => "Unknown",
        }
    }
}

// ============================================================================
// Parsed IEC 61850 Message
// ============================================================================

/// A fully parsed IEC 61850 MMS message
#[derive(Debug, Clone)]
pub struct Iec61850Message {
    /// TPKT packet length
    pub tpkt_length: u16,
    /// COTP PDU type
    pub cotp_type: CotpPduType,
    /// MMS PDU type (if this is a DT with MMS payload)
    pub pdu_type: Option<MmsPduType>,
    /// MMS service type (for confirmed request/response)
    pub service: Option<MmsService>,
    /// Invoke ID (for confirmed request/response)
    pub invoke_id: Option<u32>,
    /// MMS domain name (IEC 61850 Logical Device)
    pub mms_domain: Option<String>,
    /// MMS variable name
    pub variable_name: Option<String>,
    /// IEC 61850 object path (LDName/LNName$FC$DOName$DAName)
    pub iec61850_path: Option<String>,
    /// Whether this is a confirmed service
    pub confirmed: bool,
    /// Raw MMS payload size
    pub mms_payload_size: usize,
}

// ============================================================================
// ASN.1 BER Helpers
// ============================================================================

/// Decode ASN.1 BER tag at the given offset.
/// Returns (tag_byte, bytes_consumed).
fn ber_read_tag(buf: &[u8], offset: usize) -> Option<(u8, usize)> {
    if offset >= buf.len() {
        return None;
    }
    // For our purposes, MMS uses single-byte tags (context-specific constructed)
    Some((buf[offset], 1))
}

/// Decode ASN.1 BER length at the given offset.
/// Returns (length_value, bytes_consumed).
fn ber_read_length(buf: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= buf.len() {
        return None;
    }

    let first = buf[offset];
    if first < 0x80 {
        // Short form: length is the byte itself
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite form — not fully supported, return 0
        Some((0, 1))
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = (first & 0x7F) as usize;
        if offset + 1 + num_bytes > buf.len() || num_bytes > 4 {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | buf[offset + 1 + i] as usize;
        }
        Some((length, 1 + num_bytes))
    }
}

/// Decode an ASN.1 BER integer value.
fn ber_read_integer(buf: &[u8]) -> Option<u32> {
    if buf.is_empty() || buf.len() > 4 {
        return None;
    }
    let mut val: u32 = 0;
    for &b in buf {
        val = (val << 8) | b as u32;
    }
    Some(val)
}

/// Try to extract a visible string from BER-encoded data at offset.
fn ber_read_visible_string(buf: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset >= buf.len() {
        return None;
    }
    let tag = buf[offset];
    // VisibleString tag = 0x1A, or context-specific with primitive
    if tag != 0x1A && (tag & 0xC0) != 0x80 {
        return None;
    }
    let (len, len_size) = ber_read_length(buf, offset + 1)?;
    let str_start = offset + 1 + len_size;
    if str_start + len > buf.len() {
        return None;
    }
    let s = std::str::from_utf8(&buf[str_start..str_start + len]).ok()?;
    Some((s.to_string(), 1 + len_size + len))
}

/// Try to extract an MMS object name (domain + item) from the payload.
/// MMS ObjectName is typically: domain-specific [1] { domainId [0] VisibleString, itemId [1] VisibleString }
fn extract_mms_object_name(buf: &[u8]) -> (Option<String>, Option<String>) {
    let mut domain = None;
    let mut item = None;

    // Simple scan for visible strings in the buffer
    let mut offset = 0;
    while offset + 2 < buf.len() {
        let tag = buf[offset];
        // Look for context-specific tags [0] and [1] that contain strings
        if tag == 0x1A {
            // VisibleString
            if let Some((s, consumed)) = ber_read_visible_string(buf, offset) {
                if domain.is_none() {
                    domain = Some(s);
                } else if item.is_none() {
                    item = Some(s);
                    break;
                }
                offset += consumed;
                continue;
            }
        }
        offset += 1;
    }

    (domain, item)
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadTpkt(String),
    BadCotp(String),
    BadMms(String),
    NotMms,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadTpkt(msg) => write!(f, "TPKT error: {}", msg),
            Self::BadCotp(msg) => write!(f, "COTP error: {}", msg),
            Self::BadMms(msg) => write!(f, "MMS error: {}", msg),
            Self::NotMms => write!(f, "not MMS (possibly S7comm)"),
        }
    }
}

/// Check if a buffer looks like a TPKT/COTP/MMS message.
/// Used for protocol probing in Suricata.
pub fn probe_iec61850(buf: &[u8]) -> bool {
    if buf.len() < TPKT_HEADER_SIZE + 3 {
        return false;
    }

    // Check TPKT header
    if buf[0] != TPKT_VERSION || buf[1] != TPKT_RESERVED {
        return false;
    }

    let tpkt_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if tpkt_length < TPKT_HEADER_SIZE + 3 {
        return false;
    }

    // Parse COTP header
    let cotp_length = buf[4] as usize;
    if cotp_length == 0 || TPKT_HEADER_SIZE + 1 + cotp_length > buf.len() {
        return false;
    }

    let cotp_pdu_type = buf[5] & 0xF0;

    // For COTP DT (Data Transfer), check if payload looks like MMS (not S7comm)
    if cotp_pdu_type == 0xF0 {
        let mms_offset = TPKT_HEADER_SIZE + 1 + cotp_length;
        if mms_offset >= buf.len() {
            // COTP CR/CC without MMS payload is still valid
            return true;
        }

        let first_mms_byte = buf[mms_offset];

        // S7comm starts with 0x32 — reject
        if first_mms_byte == S7COMM_MAGIC {
            return false;
        }

        // MMS PDU tags are in the range 0xA0-0xAD
        if first_mms_byte >= MMS_CONFIRMED_REQUEST && first_mms_byte <= MMS_CONCLUDE_ERROR {
            return true;
        }

        return false;
    }

    // COTP CR/CC/DR/DC are valid IEC 61850 transport
    matches!(cotp_pdu_type, 0xE0 | 0xD0 | 0x80 | 0xC0)
}

/// Parse the COTP header. Returns (CotpPduType, offset to payload after COTP).
fn parse_cotp(buf: &[u8]) -> Result<(CotpPduType, usize), ParseError> {
    if buf.is_empty() {
        return Err(ParseError::BadCotp("empty".into()));
    }

    let cotp_length = buf[0] as usize;
    if cotp_length == 0 || 1 + cotp_length > buf.len() {
        return Err(ParseError::BadCotp("length out of range".into()));
    }

    let pdu_type = CotpPduType::from_byte(buf[1]);
    Ok((pdu_type, 1 + cotp_length))
}

/// Parse an MMS PDU from the buffer.
fn parse_mms_pdu(buf: &[u8]) -> Result<(MmsPduType, Option<MmsService>, Option<u32>, usize), ParseError> {
    if buf.is_empty() {
        return Err(ParseError::BadMms("empty".into()));
    }

    let (tag, tag_size) = ber_read_tag(buf, 0)
        .ok_or_else(|| ParseError::BadMms("cannot read tag".into()))?;

    let pdu_type = MmsPduType::from_tag(tag)
        .ok_or_else(|| ParseError::BadMms(format!("unknown PDU tag: 0x{:02X}", tag)))?;

    let (pdu_length, len_size) = ber_read_length(buf, tag_size)
        .ok_or_else(|| ParseError::BadMms("cannot read length".into()))?;

    let content_offset = tag_size + len_size;
    let content_end = (content_offset + pdu_length).min(buf.len());
    let content = &buf[content_offset..content_end];

    let mut service = None;
    let mut invoke_id = None;

    // For Confirmed-Request: InvokeID (integer) + service tag
    if pdu_type == MmsPduType::ConfirmedRequest && content.len() >= 3 {
        // InvokeID is typically [0x02 len value...]
        let mut offset = 0;
        if offset < content.len() && content[offset] == 0x02 {
            // Integer tag
            offset += 1;
            if let Some((len, ls)) = ber_read_length(content, offset) {
                offset += ls;
                if offset + len <= content.len() {
                    invoke_id = ber_read_integer(&content[offset..offset + len]);
                    offset += len;
                }
            }
        }

        // Next should be the service tag
        if offset < content.len() {
            let svc_tag = content[offset];
            service = Some(MmsService::from_tag(svc_tag));
        }
    }

    // For Confirmed-Response: InvokeID + service tag
    if pdu_type == MmsPduType::ConfirmedResponse && content.len() >= 3 {
        let mut offset = 0;
        if offset < content.len() && content[offset] == 0x02 {
            offset += 1;
            if let Some((len, ls)) = ber_read_length(content, offset) {
                offset += ls;
                if offset + len <= content.len() {
                    invoke_id = ber_read_integer(&content[offset..offset + len]);
                    offset += len;
                }
            }
        }
        if offset < content.len() {
            let svc_tag = content[offset];
            service = Some(MmsService::from_tag(svc_tag));
        }
    }

    // For Unconfirmed: check for InformationReport
    if pdu_type == MmsPduType::Unconfirmed {
        service = Some(MmsService::InformationReport);
    }

    Ok((pdu_type, service, invoke_id, pdu_length))
}

/// Parse a complete IEC 61850 MMS message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<Iec61850Message, ParseError> {
    if buf.len() < TPKT_HEADER_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    // TPKT header
    if buf[0] != TPKT_VERSION || buf[1] != TPKT_RESERVED {
        return Err(ParseError::BadTpkt("invalid version/reserved bytes".into()));
    }

    let tpkt_length = u16::from_be_bytes([buf[2], buf[3]]);
    if (tpkt_length as usize) < TPKT_HEADER_SIZE {
        return Err(ParseError::BadTpkt("length too small".into()));
    }

    // COTP header (starts after TPKT)
    let cotp_buf = &buf[TPKT_HEADER_SIZE..];
    let (cotp_type, cotp_payload_offset) = parse_cotp(cotp_buf)?;

    let mut pdu_type = None;
    let mut service = None;
    let mut invoke_id = None;
    let mut mms_domain = None;
    let mut variable_name = None;
    let mut iec61850_path = None;
    let mut confirmed = false;
    let mut mms_payload_size = 0;

    // If COTP DT, parse MMS payload
    if cotp_type == CotpPduType::DataTransfer {
        let mms_buf = &cotp_buf[cotp_payload_offset..];
        if !mms_buf.is_empty() {
            // Check for S7comm
            if mms_buf[0] == S7COMM_MAGIC {
                return Err(ParseError::NotMms);
            }

            let (pt, svc, inv_id, payload_len) = parse_mms_pdu(mms_buf)?;
            pdu_type = Some(pt);
            service = svc;
            invoke_id = inv_id;
            confirmed = pt.is_confirmed();
            mms_payload_size = payload_len;

            // Try to extract MMS object names from the payload
            let (dom, item) = extract_mms_object_name(mms_buf);
            mms_domain = dom;
            variable_name = item.clone();

            // Construct IEC 61850 path
            if let (Some(ref d), Some(ref v)) = (&mms_domain, &variable_name) {
                iec61850_path = Some(format!("{}/{}", d, v));
            }
        }
    }

    Ok(Iec61850Message {
        tpkt_length,
        cotp_type,
        pdu_type,
        service,
        invoke_id,
        mms_domain,
        variable_name,
        iec61850_path,
        confirmed,
        mms_payload_size,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TPKT/COTP/MMS message for testing.
    fn build_tpkt_cotp_mms(cotp_type: u8, mms_payload: &[u8]) -> Vec<u8> {
        let cotp_header = if cotp_type == 0xF0 {
            // COTP DT: length=2, PDU type=0xF0, TPDU number=0x80
            vec![0x02, 0xF0, 0x80]
        } else {
            // COTP CR/CC: length=6, PDU type, dst_ref, src_ref, class
            vec![0x06, cotp_type, 0x00, 0x00, 0x00, 0x00, 0x00]
        };

        let total_len = (TPKT_HEADER_SIZE + cotp_header.len() + mms_payload.len()) as u16;
        let mut buf = Vec::new();
        buf.push(TPKT_VERSION);
        buf.push(TPKT_RESERVED);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&cotp_header);
        buf.extend_from_slice(mms_payload);
        buf
    }

    #[test]
    fn test_probe_iec61850_mms() {
        // TPKT + COTP DT + MMS Confirmed-Request
        let mms = vec![MMS_CONFIRMED_REQUEST, 0x05, 0x02, 0x01, 0x01, 0xA4, 0x00];
        let pkt = build_tpkt_cotp_mms(0xF0, &mms);
        assert!(probe_iec61850(&pkt));
    }

    #[test]
    fn test_probe_iec61850_cotp_cr() {
        // TPKT + COTP CR (no MMS payload)
        let pkt = build_tpkt_cotp_mms(0xE0, &[]);
        assert!(probe_iec61850(&pkt));
    }

    #[test]
    fn test_probe_not_iec61850() {
        // Wrong TPKT version
        assert!(!probe_iec61850(&[0x01, 0x00, 0x00, 0x10, 0x02, 0xF0, 0x80]));
        // S7comm magic
        let s7 = build_tpkt_cotp_mms(0xF0, &[S7COMM_MAGIC, 0x01, 0x00]);
        assert!(!probe_iec61850(&s7));
        // Too short
        assert!(!probe_iec61850(&[0x03, 0x00]));
    }

    #[test]
    fn test_parse_initiate_request() {
        // Build MMS Initiate-Request
        let mms = vec![MMS_INITIATE_REQUEST, 0x03, 0x01, 0x02, 0x03];
        let pkt = build_tpkt_cotp_mms(0xF0, &mms);
        let msg = parse_message(&pkt).unwrap();

        assert_eq!(msg.cotp_type, CotpPduType::DataTransfer);
        assert_eq!(msg.pdu_type, Some(MmsPduType::InitiateRequest));
    }

    #[test]
    fn test_parse_confirmed_request_read() {
        // MMS Confirmed-Request with InvokeID=1, service=Read (0xA4)
        let mms = vec![
            MMS_CONFIRMED_REQUEST, 0x07,
            0x02, 0x01, 0x01, // Integer: InvokeID = 1
            MMS_SVC_READ, 0x02, 0x00, 0x00, // Read service (empty)
        ];
        let pkt = build_tpkt_cotp_mms(0xF0, &mms);
        let msg = parse_message(&pkt).unwrap();

        assert_eq!(msg.pdu_type, Some(MmsPduType::ConfirmedRequest));
        assert_eq!(msg.service, Some(MmsService::Read));
        assert_eq!(msg.invoke_id, Some(1));
        assert!(msg.confirmed);
    }

    #[test]
    fn test_mms_pdu_type_names() {
        assert_eq!(MmsPduType::ConfirmedRequest.name(), "confirmed-request");
        assert_eq!(MmsPduType::InitiateRequest.name(), "initiate-request");
        assert_eq!(MmsPduType::Unconfirmed.name(), "unconfirmed");
        assert_eq!(MmsPduType::ConcludeRequest.name(), "conclude-request");
    }

    #[test]
    fn test_ber_read_length() {
        // Short form
        assert_eq!(ber_read_length(&[0x05], 0), Some((5, 1)));
        // Long form, 1 byte
        assert_eq!(ber_read_length(&[0x81, 0x80], 0), Some((128, 2)));
        // Long form, 2 bytes
        assert_eq!(ber_read_length(&[0x82, 0x01, 0x00], 0), Some((256, 3)));
    }
}
