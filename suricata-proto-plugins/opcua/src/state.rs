// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for OPC UA.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::opcua::{self, OpcuaMessage, SecurityMode, MessageContent};

// ============================================================================
// Transaction
// ============================================================================

/// A single OPC UA transaction (one parsed message).
///
/// Suricata's app-layer model expects a list of transactions per flow.
/// Each OPC UA message produces one transaction.
#[derive(Debug)]
pub struct OpcuaTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed OPC UA message
    pub message: OpcuaMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Message type name
    pub message_type: String,
    /// Service type if applicable
    pub service_type: Option<String>,
    /// Security mode
    pub security_mode: String,
    /// Security policy URI
    pub security_policy: Option<String>,
    /// Endpoint URL (from Hello or CreateSession)
    pub endpoint_url: Option<String>,
    /// Node IDs referenced in this message
    pub node_ids: Vec<String>,
    /// Status code
    pub status_code: u32,
}

impl OpcuaTransaction {
    pub fn new(tx_id: u64, message: OpcuaMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.message_type = message.header.message_type.name().to_string();

        match &message.content {
            MessageContent::Hello(hello) => {
                detect_flags.endpoint_url = Some(hello.endpoint_url.clone());
                detect_flags.security_mode = "None".to_string();
            }
            MessageContent::Acknowledge(_) => {
                detect_flags.security_mode = "None".to_string();
            }
            MessageContent::Error(_) => {
                detect_flags.security_mode = "None".to_string();
            }
            MessageContent::Secure(sec) => {
                detect_flags.security_mode = sec.security_mode.name().to_string();
                detect_flags.security_policy = sec.security_policy.clone();
                detect_flags.endpoint_url = sec.endpoint_url.clone();
                detect_flags.status_code = sec.status_code;
                detect_flags.node_ids = sec.node_ids.clone();
                if let Some(ref svc) = sec.service_type {
                    detect_flags.service_type = Some(svc.to_string());
                }
            }
            MessageContent::Raw(_) => {
                detect_flags.security_mode = "None".to_string();
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

/// Per-flow OPC UA parser state.
///
/// Tracks all transactions and accumulated session state for a flow.
#[derive(Debug)]
pub struct OpcuaState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<OpcuaTransaction>,

    /// Endpoint URL from the Hello message
    pub endpoint_url: Option<String>,

    /// Security policy negotiated on this flow
    pub security_policy: Option<String>,

    /// Security mode negotiated on this flow
    pub security_mode: SecurityMode,

    /// Secure channel ID for this flow
    pub secure_channel_id: Option<u32>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl OpcuaState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            endpoint_url: None,
            security_policy: None,
            security_mode: SecurityMode::None,
            secure_channel_id: None,
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse an OPC UA message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, opcua::ParseError> {
        let message = opcua::parse_message(buf)?;

        // Update flow-level state
        match &message.content {
            MessageContent::Hello(hello) => {
                self.endpoint_url = Some(hello.endpoint_url.clone());
            }
            MessageContent::Secure(sec) => {
                self.secure_channel_id = Some(sec.channel_header.secure_channel_id);
                if let Some(ref policy) = sec.security_policy {
                    self.security_policy = Some(policy.clone());
                }
                if sec.security_mode != SecurityMode::None {
                    self.security_mode = sec.security_mode;
                }
            }
            _ => {}
        }

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = OpcuaTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&OpcuaTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut OpcuaTransaction> {
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

impl Default for OpcuaState {
    fn default() -> Self {
        Self::new()
    }
}
