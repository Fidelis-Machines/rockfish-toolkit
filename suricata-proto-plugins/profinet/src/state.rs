// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for PROFINET DCP.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::profinet::{self, ProfinetMessage};
use std::collections::HashSet;

// ============================================================================
// Transaction
// ============================================================================

/// A single PROFINET transaction (one parsed DCP frame).
#[derive(Debug)]
pub struct ProfinetTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed PROFINET message
    pub message: ProfinetMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// Frame ID
    pub frame_id: u16,
    /// Frame type name
    pub frame_type: String,
    /// Service type name
    pub service_type: Option<String>,
    /// Service ID name
    pub service_id: Option<String>,
    /// Station name
    pub station_name: Option<String>,
    /// Device ID
    pub device_id: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// Whether this is a Set operation (security relevant)
    pub is_security_relevant: bool,
}

impl ProfinetTransaction {
    pub fn new(tx_id: u64, message: ProfinetMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.frame_id = message.frame_id;
        detect_flags.frame_type = message.frame_type.name().to_string();

        if let Some(ref sid) = message.service_id {
            detect_flags.service_id = Some(sid.name().to_string());
            detect_flags.is_security_relevant = sid.is_security_relevant();
        }
        if let Some(ref st) = message.service_type {
            detect_flags.service_type = Some(st.name().to_string());
        }

        detect_flags.station_name = message.station_name.clone();
        detect_flags.device_id = message.device_id.clone();
        detect_flags.ip_address = message.ip_address.clone();

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

/// Per-flow PROFINET parser state.
#[derive(Debug)]
pub struct ProfinetState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<ProfinetTransaction>,

    /// All station names discovered on this flow
    pub known_stations: HashSet<String>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl ProfinetState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            known_stations: HashSet::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse a PROFINET message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, profinet::ParseError> {
        let message = profinet::parse_message(buf)?;

        // Track station names
        if let Some(ref name) = message.station_name {
            self.known_stations.insert(name.clone());
        }

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = ProfinetTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&ProfinetTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut ProfinetTransaction> {
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

impl Default for ProfinetState {
    fn default() -> Self {
        Self::new()
    }
}
