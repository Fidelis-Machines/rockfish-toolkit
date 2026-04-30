// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for IEC 104.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::iec104::{self, Iec104Message};

// ============================================================================
// Transaction
// ============================================================================

/// A single IEC 104 transaction (one parsed TCP segment).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each IEC 104 TCP segment produces one transaction.
#[derive(Debug)]
pub struct Iec104Transaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed IEC 104 message
    pub message: Iec104Message,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Message contains command-direction type IDs (45-69, 100-106)
    pub is_command: bool,
    /// Message contains direct control actions (switches, set-points)
    pub is_control_action: bool,
    /// Message contains system management commands (100-106)
    pub is_system_command: bool,
    /// Message contains U-frame control functions (StartDT/StopDT)
    pub has_u_control: bool,
    /// Number of I-frames in this message
    pub i_frame_count: usize,
    /// ASDU type IDs observed in this message
    pub type_ids: Vec<u8>,
    /// Common addresses (station addresses) observed
    pub common_addresses: Vec<u16>,
}

impl Iec104Transaction {
    pub fn new(tx_id: u64, message: Iec104Message) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.is_command = message.command_count() > 0;
        detect_flags.is_control_action = message.control_action_count() > 0;
        detect_flags.has_u_control = message.has_u_control();
        detect_flags.i_frame_count = message.i_frame_count();

        for apdu in &message.apdus {
            if let Some(ref asdu) = apdu.asdu {
                if asdu.type_id.is_system_command() {
                    detect_flags.is_system_command = true;
                }
                if !detect_flags.type_ids.contains(&asdu.type_id.0) {
                    detect_flags.type_ids.push(asdu.type_id.0);
                }
                if !detect_flags.common_addresses.contains(&asdu.common_address) {
                    detect_flags.common_addresses.push(asdu.common_address);
                }
            }
        }

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

/// Per-flow IEC 104 parser state.
///
/// Tracks all transactions and accumulated state for a flow.
#[derive(Debug)]
pub struct Iec104State {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<Iec104Transaction>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl Iec104State {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an IEC 104 message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, iec104::ParseError> {
        let message = iec104::parse_message(buf)?;

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = Iec104Transaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&Iec104Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut Iec104Transaction> {
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

impl Default for Iec104State {
    fn default() -> Self {
        Self::new()
    }
}
