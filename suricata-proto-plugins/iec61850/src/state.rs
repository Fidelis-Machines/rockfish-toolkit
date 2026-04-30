// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for IEC 61850 MMS.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::iec61850::{Iec61850Message, MmsPduType};
use std::collections::HashSet;

// ============================================================================
// Transaction
// ============================================================================

/// A single IEC 61850 transaction (one parsed TPKT/COTP/MMS PDU).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each MMS PDU produces one transaction.
#[derive(Debug)]
pub struct Iec61850Transaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed IEC 61850 message
    pub message: Iec61850Message,

    /// Whether this transaction has been logged
    pub logged: bool,
}

impl Iec61850Transaction {
    pub fn new(tx_id: u64, message: Iec61850Message) -> Self {
        Self {
            tx_id,
            message,
            logged: false,
        }
    }
}

// ============================================================================
// Flow State
// ============================================================================

/// Per-flow IEC 61850 parser state.
///
/// Tracks all transactions and accumulated state for a flow.
#[derive(Debug)]
pub struct Iec61850State {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<Iec61850Transaction>,

    /// MMS domains (IEC 61850 Logical Devices) seen on this flow
    pub known_domains: HashSet<String>,

    /// Variable names accessed on this flow
    pub known_variables: HashSet<String>,

    /// Whether the MMS session has been initiated
    pub session_initiated: bool,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl Iec61850State {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            known_domains: HashSet::new(),
            known_variables: HashSet::new(),
            session_initiated: false,
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an IEC 61850 message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, crate::iec61850::ParseError> {
        let message = crate::iec61850::parse_message(buf)?;

        // Update flow-level state
        if let Some(ref pdu_type) = message.pdu_type {
            if matches!(pdu_type, MmsPduType::InitiateRequest | MmsPduType::InitiateResponse) {
                self.session_initiated = true;
            }
        }

        if let Some(ref domain) = message.mms_domain {
            self.known_domains.insert(domain.clone());
        }
        if let Some(ref var) = message.variable_name {
            self.known_variables.insert(var.clone());
        }

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = Iec61850Transaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&Iec61850Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut Iec61850Transaction> {
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

impl Default for Iec61850State {
    fn default() -> Self {
        Self::new()
    }
}
