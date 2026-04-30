// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for S7comm.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::s7comm::{self, S7commMessage};

// ============================================================================
// Transaction
// ============================================================================

/// A single S7comm transaction (one parsed TPKT/COTP/S7comm PDU).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each S7comm PDU produces one transaction.
#[derive(Debug)]
pub struct S7commTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed S7comm message
    pub message: S7commMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Message type name
    pub msg_type: Option<String>,
    /// Message type raw value
    pub msg_type_raw: Option<u8>,
    /// Function code name
    pub function_code: Option<String>,
    /// Function code raw value
    pub function_code_raw: Option<u8>,
    /// Area name
    pub area: Option<String>,
    /// DB number
    pub db_number: Option<u16>,
    /// COTP PDU type
    pub cotp_pdu_type: String,
    /// Is a security-relevant operation (write, download, control, stop)
    pub is_security_relevant: bool,
    /// Is S7comm+ (extended protocol)
    pub is_s7comm_plus: bool,
}

impl S7commTransaction {
    pub fn new(tx_id: u64, message: S7commMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.cotp_pdu_type = message.cotp.pdu_type.name().to_string();
        detect_flags.is_s7comm_plus = message.is_s7comm_plus;

        if let Some(ref hdr) = message.s7_header {
            detect_flags.msg_type = Some(hdr.msg_type.name().to_string());
            detect_flags.msg_type_raw = Some(hdr.msg_type_raw);
        }

        if let Some(fc) = &message.function_code {
            detect_flags.function_code = Some(fc.name().to_string());
            detect_flags.is_security_relevant = fc.is_security_relevant();
        }
        detect_flags.function_code_raw = message.function_code_raw;

        if let Some(area) = &message.area {
            detect_flags.area = Some(area.name().to_string());
        }
        detect_flags.db_number = message.db_number;

        Self {
            tx_id,
            message,
            logged: false,
            detect_flags,
        }
    }
}

// ============================================================================
// Flow State
// ============================================================================

/// Per-flow S7comm parser state.
#[derive(Debug)]
pub struct S7commState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<S7commTransaction>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl S7commState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an S7comm message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, s7comm::ParseError> {
        let message = s7comm::parse_message(buf)?;

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = S7commTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&S7commTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut S7commTransaction> {
        self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id)
    }

    /// Free completed transactions (already logged)
    pub fn free_logged_transactions(&mut self) {
        self.transactions.retain(|tx| !tx.logged);
    }

    /// Mark a transaction as logged
    pub fn set_logged(&mut self, tx_id: u64) {
        if let Some(tx) = self.get_tx_mut(tx_id) {
            tx.logged = true;
        }
    }

    /// Number of active (unlogged) transactions
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

impl Default for S7commState {
    fn default() -> Self {
        Self::new()
    }
}
