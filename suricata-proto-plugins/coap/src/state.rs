// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for CoAP.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::coap::{self, CoapMessage};

// ============================================================================
// Transaction
// ============================================================================

/// A single CoAP transaction (one parsed message).
#[derive(Debug)]
pub struct CoapTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed CoAP message
    pub message: CoapMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Message type name (CON/NON/ACK/RST)
    pub msg_type: String,
    /// Code class
    pub code_class: u8,
    /// Code detail
    pub code_detail: u8,
    /// Method name (GET/POST/PUT/DELETE) or response name
    pub method: Option<String>,
    /// URI path
    pub uri_path: Option<String>,
    /// URI query
    pub uri_query: Option<String>,
    /// Content format name
    pub content_format: Option<String>,
    /// Payload size
    pub payload_size: usize,
    /// Token as hex string
    pub token_hex: String,
    /// Whether this is a request
    pub is_request: bool,
}

impl CoapTransaction {
    pub fn new(tx_id: u64, message: CoapMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.msg_type = message.msg_type.name().to_string();
        detect_flags.code_class = message.code.class;
        detect_flags.code_detail = message.code.detail;
        detect_flags.is_request = message.code.is_request();

        if let Some(method) = message.code.method_name() {
            detect_flags.method = Some(method.to_string());
        } else if let Some(resp) = message.code.response_name() {
            detect_flags.method = Some(resp.to_string());
        }

        detect_flags.uri_path = message.uri_path.clone();
        detect_flags.uri_query = message.uri_query.clone();
        detect_flags.payload_size = message.payload.len();

        if let Some(cf) = message.content_format {
            detect_flags.content_format = Some(coap::content_format_name(cf).to_string());
        }

        detect_flags.token_hex = message
            .token
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

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

/// Per-flow CoAP parser state.
#[derive(Debug)]
pub struct CoapState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<CoapTransaction>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl CoapState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse a CoAP message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, coap::ParseError> {
        let message = coap::parse_message(buf)?;

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = CoapTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&CoapTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut CoapTransaction> {
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

impl Default for CoapState {
    fn default() -> Self {
        Self::new()
    }
}
