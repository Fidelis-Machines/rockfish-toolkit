// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for LwM2M.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::lwm2m::{Lwm2mMessage, Lwm2mOperation};

// ============================================================================
// Transaction
// ============================================================================

/// A single LwM2M transaction (one parsed CoAP message).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each LwM2M/CoAP UDP datagram produces one transaction.
#[derive(Debug)]
pub struct Lwm2mTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed LwM2M message
    pub message: Lwm2mMessage,

    /// Whether this transaction has been logged
    pub logged: bool,
}

impl Lwm2mTransaction {
    pub fn new(tx_id: u64, message: Lwm2mMessage) -> Self {
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

/// Per-flow LwM2M parser state.
///
/// Tracks all transactions and accumulated state for a flow.
#[derive(Debug)]
pub struct Lwm2mState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<Lwm2mTransaction>,

    /// Endpoint name from registration (if seen)
    pub endpoint_name: Option<String>,

    /// LwM2M version from registration (if seen)
    pub lwm2m_version: Option<String>,

    /// Whether this flow has seen a registration
    pub registered: bool,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl Lwm2mState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            endpoint_name: None,
            lwm2m_version: None,
            registered: false,
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an LwM2M message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, crate::lwm2m::ParseError> {
        let message = crate::lwm2m::parse_message(buf)?;

        // Update flow-level state
        if message.operation == Lwm2mOperation::Register {
            self.registered = true;
            if let Some(ref ep) = message.endpoint_name {
                self.endpoint_name = Some(ep.clone());
            }
            if let Some(ref ver) = message.lwm2m_version {
                self.lwm2m_version = Some(ver.clone());
            }
        }

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = Lwm2mTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&Lwm2mTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut Lwm2mTransaction> {
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

impl Default for Lwm2mState {
    fn default() -> Self {
        Self::new()
    }
}
