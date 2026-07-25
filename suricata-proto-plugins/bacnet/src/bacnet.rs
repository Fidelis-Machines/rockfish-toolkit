// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! BACnet (Building Automation and Control Networks) wire protocol parser.
//!
//! Parses the BACnet/IP protocol over UDP (port 47808 / 0xBAC0).
//!
//! Reference: ASHRAE Standard 135 — BACnet
//!
//! Wire format:
//!   +------------------+
//!   | BVLC Header      |  4 bytes (type + function + length)
//!   +------------------+
//!   | NPDU Header      |  2+ bytes (version + control + routing)
//!   +------------------+
//!   | APDU             |  Variable (type + service + data)
//!   +------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// BACnet/IP default UDP port (0xBAC0)
pub const BACNET_PORT: u16 = 47808;

/// BVLC type for BACnet/IP
pub const BVLC_TYPE_BACNET_IP: u8 = 0x81;

/// Minimum BVLC header size
pub const BVLC_HEADER_SIZE: usize = 4;

/// NPDU version (always 0x01)
pub const NPDU_VERSION: u8 = 0x01;

// ============================================================================
// BVLC Functions
// ============================================================================

/// BVLC function codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BvlcFunction {
    Result,
    WriteBroadcastDistributionTable,
    ReadBroadcastDistributionTable,
    ReadBroadcastDistributionTableAck,
    ForwardedNpdu,
    RegisterForeignDevice,
    ReadForeignDeviceTable,
    ReadForeignDeviceTableAck,
    DeleteForeignDeviceTableEntry,
    DistributeBroadcastToNetwork,
    OriginalUnicastNpdu,
    OriginalBroadcastNpdu,
    SecureBvll,
    Unknown(u8),
}

impl BvlcFunction {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Result,
            0x01 => Self::WriteBroadcastDistributionTable,
            0x02 => Self::ReadBroadcastDistributionTable,
            0x03 => Self::ReadBroadcastDistributionTableAck,
            0x04 => Self::ForwardedNpdu,
            0x05 => Self::RegisterForeignDevice,
            0x06 => Self::ReadForeignDeviceTable,
            0x07 => Self::ReadForeignDeviceTableAck,
            0x08 => Self::DeleteForeignDeviceTableEntry,
            0x09 => Self::DistributeBroadcastToNetwork,
            0x0a => Self::OriginalUnicastNpdu,
            0x0b => Self::OriginalBroadcastNpdu,
            0x0c => Self::SecureBvll,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Result => "Result",
            Self::WriteBroadcastDistributionTable => "Write-BDT",
            Self::ReadBroadcastDistributionTable => "Read-BDT",
            Self::ReadBroadcastDistributionTableAck => "Read-BDT-Ack",
            Self::ForwardedNpdu => "Forwarded-NPDU",
            Self::RegisterForeignDevice => "Register-Foreign-Device",
            Self::ReadForeignDeviceTable => "Read-FDT",
            Self::ReadForeignDeviceTableAck => "Read-FDT-Ack",
            Self::DeleteForeignDeviceTableEntry => "Delete-FDT-Entry",
            Self::DistributeBroadcastToNetwork => "Distribute-Broadcast-To-Network",
            Self::OriginalUnicastNpdu => "Original-Unicast-NPDU",
            Self::OriginalBroadcastNpdu => "Original-Broadcast-NPDU",
            Self::SecureBvll => "Secure-BVLL",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Whether this function carries an NPDU
    pub fn has_npdu(&self) -> bool {
        matches!(
            self,
            Self::ForwardedNpdu | Self::OriginalUnicastNpdu | Self::OriginalBroadcastNpdu
        )
    }
}

impl fmt::Display for BvlcFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// APDU Types
// ============================================================================

/// BACnet APDU type (upper nibble of APDU type byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduType {
    ConfirmedRequest,
    UnconfirmedRequest,
    SimpleAck,
    ComplexAck,
    SegmentAck,
    Error,
    Reject,
    Abort,
    Unknown(u8),
}

impl ApduType {
    pub fn from_u8(v: u8) -> Self {
        match v & 0xF0 {
            0x00 => Self::ConfirmedRequest,
            0x10 => Self::UnconfirmedRequest,
            0x20 => Self::SimpleAck,
            0x30 => Self::ComplexAck,
            0x40 => Self::SegmentAck,
            0x50 => Self::Error,
            0x60 => Self::Reject,
            0x70 => Self::Abort,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ConfirmedRequest => "Confirmed-REQ",
            Self::UnconfirmedRequest => "Unconfirmed-REQ",
            Self::SimpleAck => "Simple-ACK",
            Self::ComplexAck => "Complex-ACK",
            Self::SegmentAck => "Segment-ACK",
            Self::Error => "Error",
            Self::Reject => "Reject",
            Self::Abort => "Abort",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for ApduType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown(0x{:02x})", v),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// BACnet Services
// ============================================================================

/// BACnet confirmed service choices
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceChoice {
    // Confirmed services
    AcknowledgeAlarm,
    ConfirmedCovNotification,
    ConfirmedEventNotification,
    GetAlarmSummary,
    GetEnrollmentSummary,
    SubscribeCov,
    AtomicReadFile,
    AtomicWriteFile,
    AddListElement,
    RemoveListElement,
    CreateObject,
    DeleteObject,
    ReadProperty,
    ReadPropertyConditional,
    ReadPropertyMultiple,
    WriteProperty,
    WritePropertyMultiple,
    DeviceCommunicationControl,
    ConfirmedPrivateTransfer,
    ConfirmedTextMessage,
    ReinitializeDevice,
    // Unconfirmed services
    IAm,
    IHave,
    UnconfirmedCovNotification,
    UnconfirmedEventNotification,
    UnconfirmedPrivateTransfer,
    UnconfirmedTextMessage,
    TimeSynchronization,
    WhoHas,
    WhoIs,
    UtcTimeSynchronization,
    WriteGroup,
    Unknown(u8),
}

impl ServiceChoice {
    /// Decode from confirmed service choice byte
    pub fn from_confirmed(v: u8) -> Self {
        match v {
            0 => Self::AcknowledgeAlarm,
            1 => Self::ConfirmedCovNotification,
            2 => Self::ConfirmedEventNotification,
            3 => Self::GetAlarmSummary,
            4 => Self::GetEnrollmentSummary,
            5 => Self::SubscribeCov,
            6 => Self::AtomicReadFile,
            7 => Self::AtomicWriteFile,
            8 => Self::AddListElement,
            9 => Self::RemoveListElement,
            10 => Self::CreateObject,
            11 => Self::DeleteObject,
            12 => Self::ReadProperty,
            13 => Self::ReadPropertyConditional,
            14 => Self::ReadPropertyMultiple,
            15 => Self::WriteProperty,
            16 => Self::WritePropertyMultiple,
            17 => Self::DeviceCommunicationControl,
            18 => Self::ConfirmedPrivateTransfer,
            19 => Self::ConfirmedTextMessage,
            20 => Self::ReinitializeDevice,
            _ => Self::Unknown(v),
        }
    }

    /// Decode from unconfirmed service choice byte
    pub fn from_unconfirmed(v: u8) -> Self {
        match v {
            0 => Self::IAm,
            1 => Self::IHave,
            2 => Self::UnconfirmedCovNotification,
            3 => Self::UnconfirmedEventNotification,
            4 => Self::UnconfirmedPrivateTransfer,
            5 => Self::UnconfirmedTextMessage,
            6 => Self::TimeSynchronization,
            7 => Self::WhoHas,
            8 => Self::WhoIs,
            9 => Self::UtcTimeSynchronization,
            10 => Self::WriteGroup,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AcknowledgeAlarm => "AcknowledgeAlarm",
            Self::ConfirmedCovNotification => "ConfirmedCOVNotification",
            Self::ConfirmedEventNotification => "ConfirmedEventNotification",
            Self::GetAlarmSummary => "GetAlarmSummary",
            Self::GetEnrollmentSummary => "GetEnrollmentSummary",
            Self::SubscribeCov => "SubscribeCOV",
            Self::AtomicReadFile => "AtomicReadFile",
            Self::AtomicWriteFile => "AtomicWriteFile",
            Self::AddListElement => "AddListElement",
            Self::RemoveListElement => "RemoveListElement",
            Self::CreateObject => "CreateObject",
            Self::DeleteObject => "DeleteObject",
            Self::ReadProperty => "ReadProperty",
            Self::ReadPropertyConditional => "ReadPropertyConditional",
            Self::ReadPropertyMultiple => "ReadPropertyMultiple",
            Self::WriteProperty => "WriteProperty",
            Self::WritePropertyMultiple => "WritePropertyMultiple",
            Self::DeviceCommunicationControl => "DeviceCommunicationControl",
            Self::ConfirmedPrivateTransfer => "ConfirmedPrivateTransfer",
            Self::ConfirmedTextMessage => "ConfirmedTextMessage",
            Self::ReinitializeDevice => "ReinitializeDevice",
            Self::IAm => "I-Am",
            Self::IHave => "I-Have",
            Self::UnconfirmedCovNotification => "UnconfirmedCOVNotification",
            Self::UnconfirmedEventNotification => "UnconfirmedEventNotification",
            Self::UnconfirmedPrivateTransfer => "UnconfirmedPrivateTransfer",
            Self::UnconfirmedTextMessage => "UnconfirmedTextMessage",
            Self::TimeSynchronization => "TimeSynchronization",
            Self::WhoHas => "Who-Has",
            Self::WhoIs => "Who-Is",
            Self::UtcTimeSynchronization => "UtcTimeSynchronization",
            Self::WriteGroup => "WriteGroup",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for ServiceChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown({})", v),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// BACnet Object Types
// ============================================================================

/// BACnet object types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    AnalogInput,
    AnalogOutput,
    AnalogValue,
    BinaryInput,
    BinaryOutput,
    BinaryValue,
    Calendar,
    Command,
    Device,
    EventEnrollment,
    File,
    Group,
    Loop,
    MultiStateInput,
    MultiStateOutput,
    NotificationClass,
    Program,
    Schedule,
    Averaging,
    MultiStateValue,
    TrendLog,
    Unknown(u16),
}

impl ObjectType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::AnalogInput,
            1 => Self::AnalogOutput,
            2 => Self::AnalogValue,
            3 => Self::BinaryInput,
            4 => Self::BinaryOutput,
            5 => Self::BinaryValue,
            6 => Self::Calendar,
            7 => Self::Command,
            8 => Self::Device,
            9 => Self::EventEnrollment,
            10 => Self::File,
            11 => Self::Group,
            12 => Self::Loop,
            13 => Self::MultiStateInput,
            14 => Self::MultiStateOutput,
            15 => Self::NotificationClass,
            16 => Self::Program,
            17 => Self::Schedule,
            18 => Self::Averaging,
            19 => Self::MultiStateValue,
            20 => Self::TrendLog,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AnalogInput => "Analog-Input",
            Self::AnalogOutput => "Analog-Output",
            Self::AnalogValue => "Analog-Value",
            Self::BinaryInput => "Binary-Input",
            Self::BinaryOutput => "Binary-Output",
            Self::BinaryValue => "Binary-Value",
            Self::Calendar => "Calendar",
            Self::Command => "Command",
            Self::Device => "Device",
            Self::EventEnrollment => "Event-Enrollment",
            Self::File => "File",
            Self::Group => "Group",
            Self::Loop => "Loop",
            Self::MultiStateInput => "Multi-State-Input",
            Self::MultiStateOutput => "Multi-State-Output",
            Self::NotificationClass => "Notification-Class",
            Self::Program => "Program",
            Self::Schedule => "Schedule",
            Self::Averaging => "Averaging",
            Self::MultiStateValue => "Multi-State-Value",
            Self::TrendLog => "Trend-Log",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown({})", v),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// BVLC header (4 bytes)
#[derive(Debug, Clone)]
pub struct BvlcHeader {
    pub bvlc_type: u8,
    pub function: BvlcFunction,
    pub length: u16,
}

/// NPDU header
#[derive(Debug, Clone)]
pub struct NpduHeader {
    pub version: u8,
    pub control: u8,
    /// Destination network (if present)
    pub dnet: Option<u16>,
    /// Source network (if present)
    pub snet: Option<u16>,
    /// Whether this NPDU expects a reply
    pub expecting_reply: bool,
    /// Network priority (0-3)
    pub priority: u8,
}

/// APDU content
#[derive(Debug, Clone)]
pub struct Apdu {
    pub apdu_type: ApduType,
    pub service_choice: Option<ServiceChoice>,
    pub invoke_id: Option<u8>,
    pub segmented: bool,
    pub max_segments: u8,
    pub max_apdu_size: u16,
}

/// BACnet object identifier (type + instance)
#[derive(Debug, Clone)]
pub struct ObjectIdentifier {
    pub object_type: ObjectType,
    pub instance: u32,
}

impl ObjectIdentifier {
    /// Decode from a 4-byte BACnet object identifier
    pub fn from_u32(val: u32) -> Self {
        let object_type = ObjectType::from_u16(((val >> 22) & 0x3FF) as u16);
        let instance = val & 0x003F_FFFF;
        Self {
            object_type,
            instance,
        }
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.object_type, self.instance)
    }
}

/// A fully parsed BACnet message
#[derive(Debug, Clone)]
pub struct BacnetMessage {
    pub bvlc: BvlcHeader,
    pub npdu: Option<NpduHeader>,
    pub apdu: Option<Apdu>,
    pub object_id: Option<ObjectIdentifier>,
    pub property_id: Option<u8>,
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadBvlcType(u8),
    BadNpduVersion(u8),
    InvalidApdu(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadBvlcType(t) => write!(f, "invalid BVLC type 0x{:02x}", t),
            Self::BadNpduVersion(v) => write!(f, "invalid NPDU version 0x{:02x}", v),
            Self::InvalidApdu(msg) => write!(f, "APDU parse error: {}", msg),
        }
    }
}

/// Check if a buffer looks like a BACnet/IP BVLC header.
/// Used for protocol probing in Suricata.
pub fn probe_bacnet(buf: &[u8]) -> bool {
    if buf.len() < BVLC_HEADER_SIZE {
        return false;
    }
    // BVLC type must be 0x81 (BACnet/IP)
    if buf[0] != BVLC_TYPE_BACNET_IP {
        return false;
    }
    // Function must be valid
    let func = buf[1];
    if func > 0x0c {
        return false;
    }
    // Length must be reasonable
    let length = u16::from_be_bytes([buf[2], buf[3]]);
    if (length as usize) < BVLC_HEADER_SIZE || length > 1500 {
        return false;
    }
    true
}

/// Parse the BVLC header (4 bytes, big-endian).
pub fn parse_bvlc(buf: &[u8]) -> Result<BvlcHeader, ParseError> {
    if buf.len() < BVLC_HEADER_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }
    if buf[0] != BVLC_TYPE_BACNET_IP {
        return Err(ParseError::BadBvlcType(buf[0]));
    }

    Ok(BvlcHeader {
        bvlc_type: buf[0],
        function: BvlcFunction::from_u8(buf[1]),
        length: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// Parse the NPDU header. Returns (NpduHeader, bytes_consumed).
fn parse_npdu(buf: &[u8]) -> Result<(NpduHeader, usize), ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::TooShort(buf.len()));
    }
    if buf[0] != NPDU_VERSION {
        return Err(ParseError::BadNpduVersion(buf[0]));
    }

    let control = buf[1];
    let expecting_reply = (control & 0x04) != 0;
    let priority = control & 0x03;
    let has_dnet = (control & 0x20) != 0;
    let has_snet = (control & 0x08) != 0;

    let mut offset = 2;
    let mut dnet = None;
    let mut snet = None;

    // Destination network + DLEN + DADR
    if has_dnet {
        if offset + 3 > buf.len() {
            return Err(ParseError::TooShort(buf.len()));
        }
        dnet = Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
        let dlen = buf[offset + 2] as usize;
        offset += 3 + dlen;
    }

    // Source network + SLEN + SADR
    if has_snet {
        if offset + 3 > buf.len() {
            return Err(ParseError::TooShort(buf.len()));
        }
        snet = Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
        let slen = buf[offset + 2] as usize;
        offset += 3 + slen;
    }

    // Hop count (present if DNET is present)
    if has_dnet && offset < buf.len() {
        offset += 1;
    }

    Ok((
        NpduHeader {
            version: buf[0],
            control,
            dnet,
            snet,
            expecting_reply,
            priority,
        },
        offset,
    ))
}

/// Decode a BACnet tagged value (context tag with length).
/// Returns (tag_number, value, bytes_consumed).
fn decode_tag(buf: &[u8], offset: usize) -> Option<(u8, u32, usize)> {
    if offset >= buf.len() {
        return None;
    }
    let tag_byte = buf[offset];
    let tag_number = (tag_byte >> 4) & 0x0F;
    let _tag_class = (tag_byte >> 3) & 0x01; // 0=application, 1=context
    let len_value = tag_byte & 0x07;

    if len_value <= 4 {
        let mut value = 0u32;
        let data_len = len_value as usize;
        if offset + 1 + data_len > buf.len() {
            return None;
        }
        for i in 0..data_len {
            value = (value << 8) | buf[offset + 1 + i] as u32;
        }
        Some((tag_number, value, 1 + data_len))
    } else if len_value == 5 {
        // Extended length
        if offset + 2 > buf.len() {
            return None;
        }
        let ext_len = buf[offset + 1] as usize;
        Some((tag_number, 0, 2 + ext_len))
    } else {
        Some((tag_number, 0, 1))
    }
}

/// Parse the APDU and extract service information.
fn parse_apdu(buf: &[u8]) -> Result<(Apdu, Option<ObjectIdentifier>, Option<u8>), ParseError> {
    if buf.is_empty() {
        return Err(ParseError::InvalidApdu("empty APDU".into()));
    }

    let type_byte = buf[0];
    let apdu_type = ApduType::from_u8(type_byte);

    let mut invoke_id = None;
    let mut service_choice = None;
    let mut segmented = false;
    let mut max_segments = 0u8;
    let mut max_apdu_size = 0u16;
    let mut object_id = None;
    let mut property_id = None;
    let mut service_offset = 1;

    match apdu_type {
        ApduType::ConfirmedRequest => {
            // Byte 0: type + segmentation flags
            segmented = (type_byte & 0x08) != 0;
            // Byte 1: max segments + max APDU size
            if buf.len() >= 2 {
                max_segments = (buf[1] >> 4) & 0x07;
                max_apdu_size = match buf[1] & 0x0F {
                    0 => 50,
                    1 => 128,
                    2 => 206,
                    3 => 480,
                    4 => 1024,
                    5 => 1476,
                    _ => 0,
                };
            }
            // Byte 2: invoke ID
            if buf.len() >= 3 {
                invoke_id = Some(buf[2]);
            }
            // Byte 3: service choice (if not segmented)
            if !segmented && buf.len() >= 4 {
                service_choice = Some(ServiceChoice::from_confirmed(buf[3]));
                service_offset = 4;
            } else if segmented && buf.len() >= 5 {
                // Segmented: sequence number at byte 3, proposed window at byte 4
                if buf.len() >= 6 {
                    service_choice = Some(ServiceChoice::from_confirmed(buf[5]));
                    service_offset = 6;
                }
            }
        }
        ApduType::UnconfirmedRequest => {
            // Byte 1: service choice
            if buf.len() >= 2 {
                service_choice = Some(ServiceChoice::from_unconfirmed(buf[1]));
                service_offset = 2;
            }
        }
        ApduType::SimpleAck => {
            if buf.len() >= 2 {
                invoke_id = Some(buf[1]);
            }
            if buf.len() >= 3 {
                service_choice = Some(ServiceChoice::from_confirmed(buf[2]));
                service_offset = 3;
            }
        }
        ApduType::ComplexAck => {
            if buf.len() >= 2 {
                invoke_id = Some(buf[1]);
            }
            if buf.len() >= 3 {
                service_choice = Some(ServiceChoice::from_confirmed(buf[2]));
                service_offset = 3;
            }
        }
        ApduType::Error => {
            if buf.len() >= 2 {
                invoke_id = Some(buf[1]);
            }
            if buf.len() >= 3 {
                service_choice = Some(ServiceChoice::from_confirmed(buf[2]));
                service_offset = 3;
            }
        }
        ApduType::Reject => {
            if buf.len() >= 2 {
                invoke_id = Some(buf[1]);
            }
        }
        ApduType::Abort => {
            if buf.len() >= 2 {
                invoke_id = Some(buf[1]);
            }
        }
        _ => {}
    }

    // Try to extract object identifier and property ID from service data
    // For ReadProperty/WriteProperty: context tag 0 = object ID, context tag 1 = property ID
    if matches!(
        service_choice,
        Some(ServiceChoice::ReadProperty)
            | Some(ServiceChoice::WriteProperty)
            | Some(ServiceChoice::ReadPropertyMultiple)
    ) {
        let svc_data = &buf[service_offset..];
        if let Some((tag_num, value, consumed)) = decode_tag(svc_data, 0) {
            if tag_num == 0 && value != 0 {
                // Context tag 0 = object identifier (4 bytes)
                object_id = Some(ObjectIdentifier::from_u32(value));
            }
            // Next tag should be property identifier
            if let Some((tag_num2, value2, _)) = decode_tag(svc_data, consumed) {
                if tag_num2 == 1 {
                    property_id = Some(value2 as u8);
                }
            }
        }
    }

    // For I-Am, extract the object identifier from the service data
    if matches!(service_choice, Some(ServiceChoice::IAm)) {
        let svc_data = &buf[service_offset..];
        if svc_data.len() >= 5 {
            // Application tag for object identifier
            let tag_byte = svc_data[0];
            if (tag_byte & 0xF0) == 0xC0 {
                // BACnet Object Identifier application tag
                let len = (tag_byte & 0x07) as usize;
                if len == 4 && svc_data.len() >= 5 {
                    let val = u32::from_be_bytes([
                        svc_data[1],
                        svc_data[2],
                        svc_data[3],
                        svc_data[4],
                    ]);
                    object_id = Some(ObjectIdentifier::from_u32(val));
                }
            }
        }
    }

    Ok((
        Apdu {
            apdu_type,
            service_choice,
            invoke_id,
            segmented,
            max_segments,
            max_apdu_size,
        },
        object_id,
        property_id,
    ))
}

/// Parse a complete BACnet/IP message from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<BacnetMessage, ParseError> {
    let bvlc = parse_bvlc(buf)?;

    let mut npdu = None;
    let mut apdu = None;
    let mut object_id = None;
    let mut property_id = None;

    if bvlc.function.has_npdu() {
        let npdu_start = if bvlc.function == BvlcFunction::ForwardedNpdu {
            // Forwarded NPDU has 6 extra bytes (IP address + port)
            BVLC_HEADER_SIZE + 6
        } else {
            BVLC_HEADER_SIZE
        };

        if npdu_start < buf.len() {
            let npdu_buf = &buf[npdu_start..];
            if let Ok((npdu_hdr, npdu_consumed)) = parse_npdu(npdu_buf) {
                // Check if there's an APDU (network layer message flag not set)
                let is_network_msg = (npdu_hdr.control & 0x80) != 0;
                npdu = Some(npdu_hdr);

                if !is_network_msg {
                    let apdu_start = npdu_start + npdu_consumed;
                    if apdu_start < buf.len() {
                        let apdu_buf = &buf[apdu_start..];
                        if let Ok((apdu_parsed, oid, pid)) = parse_apdu(apdu_buf) {
                            apdu = Some(apdu_parsed);
                            object_id = oid;
                            property_id = pid;
                        }
                    }
                }
            }
        }
    }

    Ok(BacnetMessage {
        bvlc,
        npdu,
        apdu,
        object_id,
        property_id,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_bacnet() {
        // Valid BVLC header: type=0x81, function=0x0a (Original-Unicast-NPDU), length=20
        let buf = [0x81, 0x0a, 0x00, 0x14, 0x01, 0x00];
        assert!(probe_bacnet(&buf));
    }

    #[test]
    fn test_probe_bacnet_broadcast() {
        let buf = [0x81, 0x0b, 0x00, 0x10, 0x01, 0x00];
        assert!(probe_bacnet(&buf));
    }

    #[test]
    fn test_probe_bacnet_invalid() {
        // Wrong BVLC type
        assert!(!probe_bacnet(&[0x82, 0x0a, 0x00, 0x10]));
        // Too short
        assert!(!probe_bacnet(&[0x81, 0x0a]));
        // Invalid function
        assert!(!probe_bacnet(&[0x81, 0xFF, 0x00, 0x10]));
    }

    #[test]
    fn test_parse_bvlc() {
        let buf = [0x81, 0x0a, 0x00, 0x18];
        let bvlc = parse_bvlc(&buf).unwrap();
        assert_eq!(bvlc.bvlc_type, 0x81);
        assert_eq!(bvlc.function, BvlcFunction::OriginalUnicastNpdu);
        assert_eq!(bvlc.length, 24);
    }

    #[test]
    fn test_parse_whois() {
        // BACnet Who-Is: BVLC(0x81, 0x0b, len=12) + NPDU(0x01, 0x20, dnet=0xFFFF, dlen=0, hop=255) + APDU(Unconfirmed, WhoIs)
        let buf = [
            0x81, 0x0b, 0x00, 0x0c, // BVLC
            0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, // NPDU with broadcast DNET
            0x10, 0x08, // Unconfirmed WhoIs
        ];
        let msg = parse_message(&buf).unwrap();
        assert_eq!(msg.bvlc.function, BvlcFunction::OriginalBroadcastNpdu);
        assert!(msg.npdu.is_some());
        let npdu = msg.npdu.unwrap();
        assert_eq!(npdu.dnet, Some(0xFFFF));

        assert!(msg.apdu.is_some());
        let apdu = msg.apdu.unwrap();
        assert_eq!(apdu.apdu_type, ApduType::UnconfirmedRequest);
        assert_eq!(apdu.service_choice, Some(ServiceChoice::WhoIs));
    }

    #[test]
    fn test_object_identifier() {
        // Device:1234 = (8 << 22) | 1234 = 0x02000000 | 0x4D2 = 0x020004D2
        let oid = ObjectIdentifier::from_u32(0x020004D2);
        assert_eq!(oid.object_type, ObjectType::Device);
        assert_eq!(oid.instance, 1234);
    }

    #[test]
    fn test_bvlc_function_names() {
        assert_eq!(BvlcFunction::OriginalUnicastNpdu.name(), "Original-Unicast-NPDU");
        assert_eq!(BvlcFunction::OriginalBroadcastNpdu.name(), "Original-Broadcast-NPDU");
        assert_eq!(BvlcFunction::ForwardedNpdu.name(), "Forwarded-NPDU");
    }

    #[test]
    fn test_service_choice_names() {
        assert_eq!(ServiceChoice::ReadProperty.name(), "ReadProperty");
        assert_eq!(ServiceChoice::WriteProperty.name(), "WriteProperty");
        assert_eq!(ServiceChoice::WhoIs.name(), "Who-Is");
        assert_eq!(ServiceChoice::IAm.name(), "I-Am");
    }
}
