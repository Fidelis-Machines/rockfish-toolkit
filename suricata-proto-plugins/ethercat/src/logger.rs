// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for EtherCAT transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "ethercat": {
//!     "frame_type": 1,
//!     "frame_type_name": "Command",
//!     "datagram_count": 2,
//!     "is_cyclic": true,
//!     "datagrams": [
//!       {
//!         "command": 12,
//!         "command_name": "LRW",
//!         "slave_address": 4096,
//!         "data_length": 32,
//!         "working_counter": 2,
//!         "is_cyclic": true
//!       }
//!     ]
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::ethercat::{Command, FrameType};
use crate::state::EthercatTransaction;

/// Generate EVE JSON for an EtherCAT transaction.
pub fn log_transaction(tx: &EthercatTransaction) -> Value {
    let msg = &tx.message;
    let header = &msg.header;

    let frame_type_name = FrameType::from_u8(header.frame_type)
        .map(|ft| ft.name())
        .unwrap_or("Unknown");

    let mut datagrams = Vec::new();
    for dg in &msg.datagrams {
        let command_name = Command::from_u8(dg.command)
            .map(|c| c.name())
            .unwrap_or("Unknown");

        let mut entry = json!({
            "command": dg.command,
            "command_name": command_name,
            "slave_address": dg.slave_address,
            "data_length": dg.data_length,
            "working_counter": dg.working_counter,
            "is_cyclic": dg.is_cyclic,
        });

        if let Some(ref mbt) = dg.mailbox_type {
            entry["mailbox_type"] = json!(mbt.name());
        }

        datagrams.push(entry);
    }

    json!({
        "frame_type": header.frame_type,
        "frame_type_name": frame_type_name,
        "frame_length": header.length,
        "datagram_count": msg.datagrams.len(),
        "is_cyclic": tx.detect_flags.is_cyclic,
        "has_mailbox": tx.detect_flags.has_mailbox,
        "datagrams": datagrams,
    })
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &EthercatTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethercat;

    #[test]
    fn test_log_empty_message() {
        let msg = ethercat::EthercatMessage {
            header: ethercat::EthercatFrameHeader {
                length: 0,
                reserved: false,
                frame_type: 0x01,
            },
            datagrams: vec![],
        };
        let tx = crate::state::EthercatTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["frame_type"], 1);
        assert_eq!(json["frame_type_name"], "Command");
        assert_eq!(json["datagram_count"], 0);
    }
}
