// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for EtherNet/IP (CIP).
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::enip::{self, EnipMessage};

// ============================================================================
// Transaction
// ============================================================================

/// A single EtherNet/IP transaction (one parsed message).
#[derive(Debug)]
pub struct EnipTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed EtherNet/IP message
    pub message: EnipMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Encapsulation command name
    pub command: String,
    /// Session handle
    pub session_handle: u32,
    /// CIP service name (if applicable)
    pub cip_service: Option<String>,
    /// CIP class ID
    pub cip_class: u16,
    /// CIP instance ID
    pub cip_instance: u16,
    /// CIP attribute ID
    pub cip_attribute: u16,
    /// Encapsulation status
    pub status: u32,
    /// Product name from identity
    pub product_name: Option<String>,
    /// Whether CIP request is a response
    pub is_response: bool,
}

impl EnipTransaction {
    pub fn new(tx_id: u64, message: EnipMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.command = message.header.command.name().to_string();
        detect_flags.session_handle = message.header.session_handle;
        detect_flags.status = message.header.status;

        if let Some(ref cip) = message.cip {
            detect_flags.cip_service = Some(cip.service.name().to_string());
            detect_flags.cip_class = cip.class_id;
            detect_flags.cip_instance = cip.instance_id;
            detect_flags.cip_attribute = cip.attribute_id;
            detect_flags.is_response = cip.is_response;
        }

        if let Some(ref identity) = message.identity {
            detect_flags.product_name = Some(identity.product_name.clone());
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

/// Per-flow EtherNet/IP parser state.
#[derive(Debug)]
pub struct EnipState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<EnipTransaction>,

    /// Session handle for this flow
    pub session_handle: Option<u32>,

    /// Product name from ListIdentity
    pub product_name: Option<String>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl EnipState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            session_handle: None,
            product_name: None,
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an EtherNet/IP message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, enip::ParseError> {
        let message = enip::parse_message(buf)?;

        // Update flow-level state
        if message.header.session_handle != 0 {
            self.session_handle = Some(message.header.session_handle);
        }
        if let Some(ref identity) = message.identity {
            self.product_name = Some(identity.product_name.clone());
        }

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = EnipTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&EnipTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut EnipTransaction> {
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

impl Default for EnipState {
    fn default() -> Self {
        Self::new()
    }
}
