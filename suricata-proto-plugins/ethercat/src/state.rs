// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for EtherCAT.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::ethercat::{self, EthercatMessage};

// ============================================================================
// Transaction
// ============================================================================

/// A single EtherCAT transaction (one parsed message).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each EtherCAT frame produces one transaction.
#[derive(Debug)]
pub struct EthercatTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed EtherCAT message
    pub message: EthercatMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Message contains cyclic (process data) commands
    pub is_cyclic: bool,
    /// Message contains mailbox data
    pub has_mailbox: bool,
    /// Number of datagrams in the message
    pub datagram_count: usize,
    /// Total data length across all datagrams
    pub total_data_length: usize,
    /// Command names seen in this message
    pub commands: Vec<String>,
    /// Mailbox types seen
    pub mailbox_types: Vec<String>,
    /// Slave addresses accessed
    pub slave_addresses: Vec<u32>,
    /// Working counters
    pub working_counters: Vec<u16>,
}

impl EthercatTransaction {
    pub fn new(tx_id: u64, message: EthercatMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.is_cyclic = message.has_cyclic_data();
        detect_flags.has_mailbox = message.has_mailbox();
        detect_flags.datagram_count = message.datagrams.len();
        detect_flags.total_data_length = message.total_data_length();

        for dg in &message.datagrams {
            if let Some(cmd) = ethercat::Command::from_u8(dg.command) {
                detect_flags.commands.push(cmd.name().to_string());
            }
            if let Some(ref mbt) = dg.mailbox_type {
                detect_flags.mailbox_types.push(mbt.name().to_string());
            }
            detect_flags.slave_addresses.push(dg.slave_address);
            detect_flags.working_counters.push(dg.working_counter);
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

/// Per-flow EtherCAT parser state.
///
/// Tracks all transactions and accumulated state for a flow.
#[derive(Debug)]
pub struct EthercatState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<EthercatTransaction>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl EthercatState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an EtherCAT message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, ethercat::ParseError> {
        let message = ethercat::parse_message(buf)?;

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = EthercatTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&EthercatTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut EthercatTransaction> {
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

impl Default for EthercatState {
    fn default() -> Self {
        Self::new()
    }
}
