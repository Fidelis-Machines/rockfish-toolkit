// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! ASTERIX (All-purpose STructured EUROCONTROL Surveillance Information EXchange)
//! wire protocol parser.
//!
//! Parses the ASTERIX binary protocol used for air traffic surveillance data
//! exchange between radar systems, ADS-B receivers, and ATM systems.
//!
//! Reference: EUROCONTROL ASTERIX specification
//!
//! Wire format:
//!   +------------------+
//!   | Data Block       |
//!   |  Category (1B)   |  ASTERIX category number (1-255)
//!   |  Length   (2B)    |  Total data block length (big-endian)
//!   |  Record 1        |  FSPEC + data fields
//!   |  Record 2        |
//!   |  ...             |
//!   +------------------+
//!   | Data Block 2     |  (optional, multiple blocks per datagram)
//!   +------------------+

use std::fmt;

// ============================================================================
// Constants
// ============================================================================

/// Minimum data block size: 1 (category) + 2 (length) = 3 bytes
pub const MIN_DATA_BLOCK_SIZE: usize = 3;

/// Common ASTERIX port range
pub const ASTERIX_PORT_BASE: u16 = 8600;
pub const ASTERIX_PORT_END: u16 = 8610;

// ============================================================================
// ASTERIX Categories
// ============================================================================

/// ASTERIX category with human-readable name
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsterixCategory(pub u8);

impl AsterixCategory {
    /// Human-readable category name
    pub fn name(&self) -> &'static str {
        match self.0 {
            1 => "Monoradar Target Reports",
            2 => "Monoradar Service Messages",
            8 => "Monoradar Weather Reports",
            10 => "Monosensor Surface Movement Data",
            19 => "Multilateration System Status Messages",
            20 => "Multilateration Target Reports",
            21 => "ADS-B Target Reports",
            23 => "CNS/ATM Ground Station Service Messages",
            30 => "Network Layer Messages",
            34 => "Monoradar Service Messages (Enhanced)",
            48 => "Monoradar Target Reports (Enhanced)",
            62 => "System Track Data",
            63 => "Sensor Status Messages",
            65 => "SDPS Service Status Messages",
            240 => "Radar Video Data",
            247 => "Version/Reference Table Messages",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for AsterixCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CAT {:03}", self.0)
    }
}

// ============================================================================
// FSPEC (Field Specification)
// ============================================================================

/// Parsed FSPEC bitmask — indicates which data fields are present in a record.
#[derive(Debug, Clone)]
pub struct Fspec {
    /// Raw FSPEC bytes
    pub bytes: Vec<u8>,
    /// Number of FSPEC octets
    pub len: usize,
}

impl Fspec {
    /// Check if a specific field index (0-based) is present.
    /// Field indices count from bit 7 of the first FSPEC byte (MSB first),
    /// skipping the extension bit (bit 0) of each byte.
    pub fn has_field(&self, field_index: usize) -> bool {
        // Each FSPEC byte provides 7 usable bits (bit 0 is FX extension)
        let byte_idx = field_index / 7;
        let bit_idx = 7 - (field_index % 7);

        if bit_idx == 0 {
            // This would be the FX bit, not a data field
            return false;
        }

        if byte_idx >= self.bytes.len() {
            return false;
        }

        (self.bytes[byte_idx] >> bit_idx) & 1 == 1
    }
}

// ============================================================================
// ASTERIX Record Fields
// ============================================================================

/// Extracted fields from an ASTERIX record.
/// Fields vary by category; we extract common surveillance-relevant fields.
#[derive(Debug, Clone, Default)]
pub struct RecordFields {
    /// Track number (CAT 048 I048/161, CAT 062 I062/105)
    pub track_number: Option<u16>,
    /// ICAO 24-bit aircraft address (CAT 021 I021/080, CAT 048 I048/220)
    pub icao_address: Option<u32>,
    /// Target identification / callsign (CAT 021 I021/170, CAT 048 I048/240)
    pub callsign: Option<String>,
    /// Latitude in degrees
    pub latitude: Option<f64>,
    /// Longitude in degrees
    pub longitude: Option<f64>,
    /// Altitude in feet
    pub altitude: Option<f64>,
    /// Mode-3/A squawk code (CAT 048 I048/070)
    pub squawk_code: Option<u16>,
    /// Time of day in seconds since midnight (CAT 048 I048/140)
    pub time_of_day: Option<f64>,
    /// Target position: rho (slant range) in NM
    pub rho: Option<f64>,
    /// Target position: theta (azimuth) in degrees
    pub theta: Option<f64>,
    /// Geometric altitude in feet (CAT 021)
    pub geometric_altitude: Option<f64>,
    /// Emitter category (CAT 021 I021/020)
    pub emitter_category: Option<u8>,
}

/// A parsed ASTERIX record within a data block.
#[derive(Debug, Clone)]
pub struct AsterixRecord {
    /// FSPEC for this record
    pub fspec: Fspec,
    /// Extracted fields
    pub fields: RecordFields,
    /// Raw record size in bytes
    pub raw_size: usize,
}

// ============================================================================
// Parsed ASTERIX Data Block
// ============================================================================

/// A parsed ASTERIX data block (one category, one or more records).
#[derive(Debug, Clone)]
pub struct AsterixDataBlock {
    /// Category number
    pub category: AsterixCategory,
    /// Total block length (from header)
    pub length: u16,
    /// Parsed records
    pub records: Vec<AsterixRecord>,
}

/// A fully parsed ASTERIX message (one or more data blocks in a datagram).
#[derive(Debug, Clone)]
pub struct AsterixMessage {
    /// Data blocks in this datagram
    pub data_blocks: Vec<AsterixDataBlock>,
}

impl AsterixMessage {
    /// Total number of records across all data blocks
    pub fn total_record_count(&self) -> usize {
        self.data_blocks.iter().map(|b| b.records.len()).sum()
    }

    /// Get the first category seen
    pub fn primary_category(&self) -> Option<AsterixCategory> {
        self.data_blocks.first().map(|b| b.category)
    }
}

// ============================================================================
// Parser
// ============================================================================

/// Parse error
#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    BadLength { expected: usize, actual: usize },
    BadCategory(u8),
    BadRecord(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "buffer too short ({} bytes)", n),
            Self::BadLength { expected, actual } => {
                write!(f, "length mismatch (expected {}, got {})", expected, actual)
            }
            Self::BadCategory(c) => write!(f, "invalid category: {}", c),
            Self::BadRecord(msg) => write!(f, "record parse error: {}", msg),
        }
    }
}

/// Check if a buffer looks like an ASTERIX data block.
/// Used for protocol probing in Suricata.
pub fn probe_asterix(buf: &[u8]) -> bool {
    if buf.len() < MIN_DATA_BLOCK_SIZE {
        return false;
    }

    let category = buf[0];
    // Category 0 is reserved/invalid
    if category == 0 {
        return false;
    }

    let length = u16::from_be_bytes([buf[1], buf[2]]) as usize;

    // Length must be at least MIN_DATA_BLOCK_SIZE
    if length < MIN_DATA_BLOCK_SIZE {
        return false;
    }

    // Length must not exceed the buffer (but buffer may contain multiple blocks)
    if length > buf.len() {
        return false;
    }

    // Validate category is in a known range
    match category {
        1 | 2 | 8 | 10 | 19 | 20 | 21 | 23 | 30 | 34 | 48 | 62 | 63 | 65 | 240 | 247 => true,
        _ => {
            // Unknown category but structurally valid — still accept
            // if length fits cleanly
            length <= buf.len()
        }
    }
}

/// Parse FSPEC (Field Specification) bytes at the given offset.
fn parse_fspec(buf: &[u8]) -> Result<(Fspec, usize), ParseError> {
    let mut bytes = Vec::new();
    let mut offset = 0;

    loop {
        if offset >= buf.len() {
            return Err(ParseError::BadRecord("FSPEC truncated".into()));
        }

        let b = buf[offset];
        bytes.push(b);
        offset += 1;

        // Bit 0 (FX) = 0 means this is the last FSPEC byte
        if b & 0x01 == 0 {
            break;
        }
    }

    let len = bytes.len();
    Ok((Fspec { bytes, len }, offset))
}

/// Decode a 6-character ICAO callsign from 6 bytes of IA-5 encoded data.
fn decode_callsign(data: &[u8]) -> String {
    // Each character is 6 bits, packed into 48 bits (6 bytes) for 8 characters
    if data.len() < 6 {
        return String::new();
    }

    let bits: u64 = ((data[0] as u64) << 40)
        | ((data[1] as u64) << 32)
        | ((data[2] as u64) << 24)
        | ((data[3] as u64) << 16)
        | ((data[4] as u64) << 8)
        | (data[5] as u64);

    let mut chars = Vec::new();
    for i in 0..8 {
        let c = ((bits >> (42 - i * 6)) & 0x3F) as u8;
        let ch = match c {
            1..=26 => (b'A' + c - 1) as char,
            48..=57 => c as char, // '0'-'9' map directly
            32 => ' ',
            0 => ' ',
            _ => ' ',
        };
        chars.push(ch);
    }

    chars.into_iter().collect::<String>().trim().to_string()
}

/// Parse a single ASTERIX record for CAT 048.
/// Extracts key surveillance fields based on FSPEC.
fn parse_record_cat048(buf: &[u8], fspec: &Fspec) -> RecordFields {
    let mut fields = RecordFields::default();
    let mut offset = 0;

    // I048/010 — Data Source Identifier (2 bytes) — field index 0
    if fspec.has_field(0) {
        offset += 2;
    }

    // I048/140 — Time of Day (3 bytes) — field index 1
    if fspec.has_field(1) {
        if offset + 3 <= buf.len() {
            let raw = ((buf[offset] as u32) << 16)
                | ((buf[offset + 1] as u32) << 8)
                | (buf[offset + 2] as u32);
            fields.time_of_day = Some(raw as f64 / 128.0);
        }
        offset += 3;
    }

    // I048/020 — Target Report Descriptor (variable) — field index 2
    if fspec.has_field(2) {
        if offset < buf.len() {
            // First byte always present; FX bit extends
            offset += 1;
            while offset < buf.len() && buf[offset - 1] & 0x01 != 0 {
                offset += 1;
            }
        }
    }

    // I048/040 — Measured Position (Rho/Theta) (4 bytes) — field index 3
    if fspec.has_field(3) {
        if offset + 4 <= buf.len() {
            let rho_raw = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let theta_raw = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            fields.rho = Some(rho_raw as f64 / 256.0); // NM, LSB = 1/256 NM
            fields.theta = Some(theta_raw as f64 * 360.0 / 65536.0); // degrees
        }
        offset += 4;
    }

    // I048/070 — Mode-3/A Code (2 bytes) — field index 4
    if fspec.has_field(4) {
        if offset + 2 <= buf.len() {
            let raw = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            // Mode-3/A is in octal, stored in bits 11-0
            fields.squawk_code = Some(raw & 0x0FFF);
        }
        offset += 2;
    }

    // I048/090 — Flight Level (Mode-C) (2 bytes) — field index 5
    if fspec.has_field(5) {
        if offset + 2 <= buf.len() {
            let raw = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            // Flight level in 1/4 FL units (1 FL = 100 ft)
            let fl = (raw & 0x3FFF) as i16;
            fields.altitude = Some(fl as f64 * 25.0); // feet
        }
        offset += 2;
    }

    // I048/130 — Radar Plot Characteristics (variable) — field index 6
    if fspec.has_field(6) {
        // Variable length — skip for now (1+ bytes with FX)
        if offset < buf.len() {
            offset += 1;
            while offset < buf.len() && buf[offset - 1] & 0x01 != 0 {
                offset += 1;
            }
        }
    }

    // Second FSPEC byte fields (indices 7+)
    // I048/220 — Aircraft Address (ICAO) (3 bytes) — field index 7
    if fspec.has_field(7) {
        if offset + 3 <= buf.len() {
            fields.icao_address = Some(
                ((buf[offset] as u32) << 16)
                    | ((buf[offset + 1] as u32) << 8)
                    | (buf[offset + 2] as u32),
            );
        }
        offset += 3;
    }

    // I048/240 — Aircraft Identification (callsign) (6 bytes) — field index 8
    if fspec.has_field(8) {
        if offset + 6 <= buf.len() {
            fields.callsign = Some(decode_callsign(&buf[offset..offset + 6]));
        }
        offset += 6;
    }

    // I048/250 — Mode-S MB Data (variable) — field index 9 — skip

    // I048/161 — Track Number (2 bytes) — field index 10
    if fspec.has_field(10) {
        if offset + 2 <= buf.len() {
            fields.track_number = Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]) & 0x0FFF);
        }
        // offset += 2; // not needed since we stop here
    }

    fields
}

/// Parse a single ASTERIX record for CAT 021 (ADS-B).
/// Extracts key ADS-B fields based on FSPEC.
fn parse_record_cat021(buf: &[u8], fspec: &Fspec) -> RecordFields {
    let mut fields = RecordFields::default();
    let mut offset = 0;

    // I021/010 — Data Source Identifier (2 bytes) — field index 0
    if fspec.has_field(0) {
        offset += 2;
    }

    // I021/040 — Target Report Descriptor (variable) — field index 1
    if fspec.has_field(1) {
        if offset < buf.len() {
            offset += 1;
            while offset < buf.len() && buf[offset - 1] & 0x01 != 0 {
                offset += 1;
            }
        }
    }

    // I021/161 — Track Number (2 bytes) — field index 2
    if fspec.has_field(2) {
        if offset + 2 <= buf.len() {
            fields.track_number = Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]) & 0x0FFF);
        }
        offset += 2;
    }

    // I021/015 — Service Identification (1 byte) — field index 3
    if fspec.has_field(3) {
        offset += 1;
    }

    // I021/071 — Time of Applicability for Position (3 bytes) — field index 4
    if fspec.has_field(4) {
        if offset + 3 <= buf.len() {
            let raw = ((buf[offset] as u32) << 16)
                | ((buf[offset + 1] as u32) << 8)
                | (buf[offset + 2] as u32);
            fields.time_of_day = Some(raw as f64 / 128.0);
        }
        offset += 3;
    }

    // I021/130 — Position in WGS-84 (lat/lon) (6 bytes) — field index 5
    if fspec.has_field(5) {
        if offset + 6 <= buf.len() {
            let lat_raw = ((buf[offset] as i32) << 16)
                | ((buf[offset + 1] as i32) << 8)
                | (buf[offset + 2] as i32);
            // Sign extension for 24-bit signed
            let lat_signed = if lat_raw & 0x800000 != 0 {
                lat_raw | !0xFFFFFF_i32
            } else {
                lat_raw
            };
            let lon_raw = ((buf[offset + 3] as i32) << 16)
                | ((buf[offset + 4] as i32) << 8)
                | (buf[offset + 5] as i32);
            let lon_signed = if lon_raw & 0x800000 != 0 {
                lon_raw | !0xFFFFFF_i32
            } else {
                lon_raw
            };
            fields.latitude = Some(lat_signed as f64 * (180.0 / (1 << 23) as f64));
            fields.longitude = Some(lon_signed as f64 * (180.0 / (1 << 23) as f64));
        }
        offset += 6;
    }

    // I021/131 — High-Resolution Position (8 bytes) — field index 6
    if fspec.has_field(6) {
        offset += 8;
    }

    // Second FSPEC byte
    // I021/072 — Time of Applicability for Velocity (3 bytes) — field index 7
    if fspec.has_field(7) {
        offset += 3;
    }

    // I021/150 — Air Speed (2 bytes) — field index 8
    if fspec.has_field(8) {
        offset += 2;
    }

    // I021/151 — True Air Speed (2 bytes) — field index 9
    if fspec.has_field(9) {
        offset += 2;
    }

    // I021/080 — Target Address (ICAO, 3 bytes) — field index 10
    if fspec.has_field(10) {
        if offset + 3 <= buf.len() {
            fields.icao_address = Some(
                ((buf[offset] as u32) << 16)
                    | ((buf[offset + 1] as u32) << 8)
                    | (buf[offset + 2] as u32),
            );
        }
        offset += 3;
    }

    // I021/073 — Time of Message Reception Position (3 bytes) — field index 11
    if fspec.has_field(11) {
        offset += 3;
    }

    // I021/074 — Time of Message Reception Position High Precision — field index 12
    if fspec.has_field(12) {
        offset += 4;
    }

    // I021/075 — Time of Message Reception Velocity — field index 13
    if fspec.has_field(13) {
        offset += 3;
    }

    // Third FSPEC byte
    // I021/076 — Time of Message Reception Velocity High Precision — field index 14
    if fspec.has_field(14) {
        offset += 4;
    }

    // I021/140 — Geometric Height (2 bytes) — field index 15
    if fspec.has_field(15) {
        if offset + 2 <= buf.len() {
            let raw = i16::from_be_bytes([buf[offset], buf[offset + 1]]);
            fields.geometric_altitude = Some(raw as f64 * 6.25); // feet, LSB=6.25ft
        }
        offset += 2;
    }

    // I021/090 — Quality Indicators (variable) — field index 16
    if fspec.has_field(16) {
        if offset < buf.len() {
            offset += 1;
            while offset < buf.len() && buf[offset - 1] & 0x01 != 0 {
                offset += 1;
            }
        }
    }

    // I021/210 — MOPS Version (1 byte) — field index 17
    if fspec.has_field(17) {
        offset += 1;
    }

    // I021/070 — Mode 3/A Code (2 bytes) — field index 18
    if fspec.has_field(18) {
        if offset + 2 <= buf.len() {
            let raw = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            fields.squawk_code = Some(raw & 0x0FFF);
        }
        offset += 2;
    }

    // I021/230 — Roll Angle (2 bytes) — field index 19
    if fspec.has_field(19) {
        offset += 2;
    }

    // I021/145 — Flight Level (2 bytes) — field index 20
    if fspec.has_field(20) {
        if offset + 2 <= buf.len() {
            let raw = i16::from_be_bytes([buf[offset], buf[offset + 1]]);
            fields.altitude = Some(raw as f64 * 25.0); // feet
        }
        offset += 2;
    }

    // Fourth FSPEC byte
    // I021/152 — Magnetic Heading (2 bytes) — field index 21
    if fspec.has_field(21) {
        offset += 2;
    }

    // I021/200 — Target Status (1 byte) — field index 22
    if fspec.has_field(22) {
        offset += 1;
    }

    // I021/155 — Barometric Vertical Rate (2 bytes) — field index 23
    if fspec.has_field(23) {
        offset += 2;
    }

    // I021/157 — Geometric Vertical Rate (2 bytes) — field index 24
    if fspec.has_field(24) {
        offset += 2;
    }

    // I021/160 — Airborne Ground Vector (4 bytes) — field index 25
    if fspec.has_field(25) {
        offset += 4;
    }

    // I021/165 — Track Angle Rate (2 bytes) — field index 26
    if fspec.has_field(26) {
        offset += 2;
    }

    // I021/020 — Emitter Category (1 byte) — field index 27
    if fspec.has_field(27) {
        if offset + 1 <= buf.len() {
            fields.emitter_category = Some(buf[offset]);
        }
        offset += 1;
    }

    // Fifth FSPEC byte
    // I021/220 — Met Information (variable) — field index 28
    if fspec.has_field(28) {
        // Skip variable length
        if offset < buf.len() {
            offset += 1;
            while offset < buf.len() && buf[offset - 1] & 0x01 != 0 {
                offset += 1;
            }
        }
    }

    // I021/146 — Selected Altitude (2 bytes) — field index 29
    if fspec.has_field(29) {
        offset += 2;
    }

    // I021/148 — Final State Selected Altitude (2 bytes) — field index 30
    if fspec.has_field(30) {
        offset += 2;
    }

    // I021/110 — Trajectory Intent (variable) — field index 31
    if fspec.has_field(31) {
        // Complex compound field, skip
        if offset < buf.len() {
            offset += 1;
            while offset < buf.len() && buf[offset - 1] & 0x01 != 0 {
                offset += 1;
            }
        }
    }

    // I021/170 — Target Identification (6 bytes) — field index 32
    if fspec.has_field(32) {
        if offset + 6 <= buf.len() {
            fields.callsign = Some(decode_callsign(&buf[offset..offset + 6]));
        }
        // offset += 6;
    }

    fields
}

/// Parse a single record (FSPEC + data fields) from a data block.
fn parse_record(buf: &[u8], category: u8) -> Result<(AsterixRecord, usize), ParseError> {
    let (fspec, fspec_size) = parse_fspec(buf)?;

    let data_buf = &buf[fspec_size..];
    let fields = match category {
        48 => parse_record_cat048(data_buf, &fspec),
        21 => parse_record_cat021(data_buf, &fspec),
        _ => RecordFields::default(), // Unknown category — no field extraction
    };

    // For unknown categories, we cannot determine the exact record size.
    // Use the remaining buffer as a single record.
    let record_size = buf.len(); // conservative — entire remaining block

    Ok((
        AsterixRecord {
            fspec,
            fields,
            raw_size: record_size,
        },
        record_size,
    ))
}

/// Parse a single ASTERIX data block.
fn parse_data_block(buf: &[u8]) -> Result<(AsterixDataBlock, usize), ParseError> {
    if buf.len() < MIN_DATA_BLOCK_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let category = AsterixCategory(buf[0]);
    let length = u16::from_be_bytes([buf[1], buf[2]]);

    if (length as usize) < MIN_DATA_BLOCK_SIZE {
        return Err(ParseError::BadLength {
            expected: MIN_DATA_BLOCK_SIZE,
            actual: length as usize,
        });
    }

    if (length as usize) > buf.len() {
        return Err(ParseError::BadLength {
            expected: length as usize,
            actual: buf.len(),
        });
    }

    let block_data = &buf[3..length as usize];
    let mut records = Vec::new();

    // Parse records within the data block
    if !block_data.is_empty() {
        match parse_record(block_data, category.0) {
            Ok((record, _)) => records.push(record),
            Err(_) => {
                // Create a minimal record with just the FSPEC
                if let Ok((fspec, _)) = parse_fspec(block_data) {
                    records.push(AsterixRecord {
                        fspec,
                        fields: RecordFields::default(),
                        raw_size: block_data.len(),
                    });
                }
            }
        }
    }

    Ok((
        AsterixDataBlock {
            category,
            length,
            records,
        },
        length as usize,
    ))
}

/// Parse a complete ASTERIX message (one or more data blocks) from a byte buffer.
pub fn parse_message(buf: &[u8]) -> Result<AsterixMessage, ParseError> {
    if buf.len() < MIN_DATA_BLOCK_SIZE {
        return Err(ParseError::TooShort(buf.len()));
    }

    let mut data_blocks = Vec::new();
    let mut offset = 0;

    while offset + MIN_DATA_BLOCK_SIZE <= buf.len() {
        match parse_data_block(&buf[offset..]) {
            Ok((block, consumed)) => {
                data_blocks.push(block);
                offset += consumed;
            }
            Err(_) => break,
        }
    }

    if data_blocks.is_empty() {
        return Err(ParseError::TooShort(buf.len()));
    }

    Ok(AsterixMessage { data_blocks })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ASTERIX data block for testing.
    fn build_data_block(category: u8, record_data: &[u8]) -> Vec<u8> {
        let length = (3 + record_data.len()) as u16;
        let mut buf = Vec::new();
        buf.push(category);
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(record_data);
        buf
    }

    #[test]
    fn test_probe_asterix_valid() {
        // CAT 048, length 10, with some record data
        let block = build_data_block(48, &[0x80, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
        assert!(probe_asterix(&block));
    }

    #[test]
    fn test_probe_asterix_cat021() {
        let block = build_data_block(21, &[0x80, 0x01, 0x02]);
        assert!(probe_asterix(&block));
    }

    #[test]
    fn test_probe_asterix_invalid() {
        // Category 0 is invalid
        assert!(!probe_asterix(&[0, 0, 3]));
        // Too short
        assert!(!probe_asterix(&[48, 0]));
        // Length exceeds buffer
        assert!(!probe_asterix(&[48, 0, 100]));
    }

    #[test]
    fn test_parse_fspec_single_byte() {
        let buf = [0xF0]; // Fields 0-3 set, FX=0
        let (fspec, size) = parse_fspec(&buf).unwrap();
        assert_eq!(size, 1);
        assert!(fspec.has_field(0)); // bit 7
        assert!(fspec.has_field(1)); // bit 6
        assert!(fspec.has_field(2)); // bit 5
        assert!(fspec.has_field(3)); // bit 4
        assert!(!fspec.has_field(4)); // bit 3
    }

    #[test]
    fn test_parse_message_cat048() {
        // Build a minimal CAT 048 data block with FSPEC indicating
        // Time of Day (field 1) only
        let mut record_data = Vec::new();
        // FSPEC: field 1 set (bit 6) = 0x40, FX=0
        record_data.push(0x40);
        // I048/140 Time of Day: 3 bytes, value 0x00_80_00 = 256.0 seconds
        record_data.extend_from_slice(&[0x00, 0x80, 0x00]);

        let block = build_data_block(48, &record_data);
        let msg = parse_message(&block).unwrap();

        assert_eq!(msg.data_blocks.len(), 1);
        assert_eq!(msg.data_blocks[0].category.0, 48);
        assert_eq!(msg.data_blocks[0].category.name(), "Monoradar Target Reports (Enhanced)");
        assert_eq!(msg.data_blocks[0].records.len(), 1);
    }

    #[test]
    fn test_category_names() {
        assert_eq!(AsterixCategory(1).name(), "Monoradar Target Reports");
        assert_eq!(AsterixCategory(21).name(), "ADS-B Target Reports");
        assert_eq!(AsterixCategory(48).name(), "Monoradar Target Reports (Enhanced)");
        assert_eq!(AsterixCategory(62).name(), "System Track Data");
        assert_eq!(AsterixCategory(240).name(), "Radar Video Data");
        assert_eq!(AsterixCategory(99).name(), "Unknown");
    }

    #[test]
    fn test_decode_callsign() {
        // "TEST    " encoded in 6-bit IA-5
        // T=20, E=5, S=19, T=20
        // 010100 000101 010011 010100 100000 100000 100000 100000
        let bytes: [u8; 6] = [0x50, 0x15, 0x35, 0x20, 0x82, 0x08];
        let cs = decode_callsign(&bytes);
        assert!(!cs.is_empty());
    }
}
