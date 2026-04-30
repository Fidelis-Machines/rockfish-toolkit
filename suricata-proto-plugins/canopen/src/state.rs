// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for CANopen.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::canopen::{self, CanopenMessage};

// ============================================================================
// Transaction
// ============================================================================

/// A single CANopen transaction (one parsed CAN-over-UDP message).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each CAN-over-UDP datagram produces one transaction.
#[derive(Debug)]
pub struct CanopenTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed CANopen message
    pub message: CanopenMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Message contains NMT commands
    pub has_nmt: bool,
    /// Message contains SDO transfers
    pub has_sdo: bool,
    /// Message contains PDO data
    pub has_pdo: bool,
    /// Message contains emergency frames
    pub has_emergency: bool,
    /// Number of CAN frames in the message
    pub frame_count: usize,
    /// Function names seen
    pub function_names: Vec<String>,
    /// Node IDs seen
    pub node_ids: Vec<u8>,
}

impl CanopenTransaction {
    pub fn new(tx_id: u64, message: CanopenMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.has_nmt = message.has_nmt();
        detect_flags.has_sdo = message.has_sdo();
        detect_flags.has_pdo = message.has_pdo();
        detect_flags.has_emergency = message.has_emergency();
        detect_flags.frame_count = message.frames.len();

        for frame in &message.frames {
            detect_flags.function_names.push(frame.function_code.name().to_string());
            if !detect_flags.node_ids.contains(&frame.node_id) {
                detect_flags.node_ids.push(frame.node_id);
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

/// Per-flow CANopen parser state.
///
/// Tracks all transactions and accumulated state for a flow.
#[derive(Debug)]
pub struct CanopenState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<CanopenTransaction>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl CanopenState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse a CANopen message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, canopen::ParseError> {
        let message = canopen::parse_message(buf)?;

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = CanopenTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&CanopenTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut CanopenTransaction> {
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

impl Default for CanopenState {
    fn default() -> Self {
        Self::new()
    }
}
