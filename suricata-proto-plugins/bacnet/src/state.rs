// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata app-layer parser state for BACnet.
//!
//! Maintains per-flow state and transactions that Suricata uses for
//! detection, logging, and flow lifecycle management.

use crate::bacnet::{self, BacnetMessage};
use std::collections::HashSet;

// ============================================================================
// Transaction
// ============================================================================

/// A single BACnet transaction (one parsed message).
#[derive(Debug)]
pub struct BacnetTransaction {
    /// Transaction ID (monotonically increasing per flow)
    pub tx_id: u64,

    /// Parsed BACnet message
    pub message: BacnetMessage,

    /// Whether this transaction has been logged
    pub logged: bool,

    /// Detection flags set during parsing
    pub detect_flags: DetectFlags,
}

/// Flags for Suricata detection keywords
#[derive(Debug, Default)]
pub struct DetectFlags {
    /// BVLC function name
    pub bvlc_function: String,
    /// APDU type name
    pub apdu_type: Option<String>,
    /// Service choice name
    pub service_choice: Option<String>,
    /// Object type name
    pub object_type: Option<String>,
    /// Object instance number
    pub object_instance: Option<u32>,
    /// Property ID
    pub property_id: Option<u8>,
    /// Whether this is a broadcast
    pub is_broadcast: bool,
    /// Whether this is a network layer message
    pub is_network_message: bool,
}

impl BacnetTransaction {
    pub fn new(tx_id: u64, message: BacnetMessage) -> Self {
        let mut detect_flags = DetectFlags::default();

        detect_flags.bvlc_function = message.bvlc.function.name().to_string();
        detect_flags.is_broadcast =
            message.bvlc.function == bacnet::BvlcFunction::OriginalBroadcastNpdu;

        if let Some(ref npdu) = message.npdu {
            detect_flags.is_network_message = (npdu.control & 0x80) != 0;
        }

        if let Some(ref apdu) = message.apdu {
            detect_flags.apdu_type = Some(apdu.apdu_type.name().to_string());
            if let Some(ref svc) = apdu.service_choice {
                detect_flags.service_choice = Some(svc.name().to_string());
            }
        }

        if let Some(ref oid) = message.object_id {
            detect_flags.object_type = Some(oid.object_type.name().to_string());
            detect_flags.object_instance = Some(oid.instance);
        }

        detect_flags.property_id = message.property_id;

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

/// Per-flow BACnet parser state.
#[derive(Debug)]
pub struct BacnetState {
    /// Transaction counter
    tx_id_counter: u64,

    /// Active transactions (not yet logged/freed)
    pub transactions: Vec<BacnetTransaction>,

    /// Device instances discovered on this flow
    pub known_devices: HashSet<u32>,

    /// Total messages parsed on this flow
    pub message_count: u64,

    /// Total bytes parsed
    pub bytes_parsed: u64,

    /// Parse errors encountered
    pub parse_errors: u64,
}

impl BacnetState {
    pub fn new() -> Self {
        Self {
            tx_id_counter: 0,
            transactions: Vec::new(),
            known_devices: HashSet::new(),
            message_count: 0,
            bytes_parsed: 0,
            parse_errors: 0,
        }
    }

    /// Parse a BACnet message and create a new transaction.
    pub fn parse(&mut self, buf: &[u8]) -> Result<u64, bacnet::ParseError> {
        let message = bacnet::parse_message(buf)?;

        // Track device instances from I-Am responses
        if let Some(ref oid) = message.object_id {
            if oid.object_type == bacnet::ObjectType::Device {
                self.known_devices.insert(oid.instance);
            }
        }

        // Create transaction
        let tx_id = self.tx_id_counter;
        self.tx_id_counter += 1;
        self.message_count += 1;
        self.bytes_parsed += buf.len() as u64;

        let tx = BacnetTransaction::new(tx_id, message);
        self.transactions.push(tx);

        Ok(tx_id)
    }

    /// Get a transaction by ID
    pub fn get_tx(&self, tx_id: u64) -> Option<&BacnetTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id)
    }

    /// Get a mutable transaction by ID
    pub fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut BacnetTransaction> {
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

impl Default for BacnetState {
    fn default() -> Self {
        Self::new()
    }
}
