// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for CANopen transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "canopen": {
//!     "sequence": 1,
//!     "frame_count": 2,
//!     "has_nmt": false,
//!     "has_sdo": true,
//!     "has_pdo": false,
//!     "frames": [
//!       {
//!         "cob_id": 1537,
//!         "node_id": 1,
//!         "function_code": "RSDO",
//!         "function_name": "RSDO",
//!         "dlc": 8,
//!         "data_hex": "2340600006000000",
//!         "sdo_command": "InitiateDownloadReq",
//!         "sdo_index": 24640,
//!         "sdo_subindex": 0
//!       }
//!     ]
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::CanopenTransaction;

/// Generate EVE JSON for a CANopen transaction.
pub fn log_transaction(tx: &CanopenTransaction) -> Value {
    let msg = &tx.message;

    let mut frames = Vec::new();
    for frame in &msg.frames {
        let mut entry = json!({
            "cob_id": frame.cob_id,
            "node_id": frame.node_id,
            "function_code": frame.function_code.name(),
            "function_name": frame.function_code.name(),
            "dlc": frame.dlc,
            "data_hex": frame.data_hex,
        });

        if let Some(ref nmt_cmd) = frame.nmt_command {
            entry["nmt_command"] = json!(nmt_cmd.name());
        }

        if let Some(ref sdo_cmd) = frame.sdo_command {
            entry["sdo_command"] = json!(sdo_cmd.name());
        }

        if let Some(idx) = frame.sdo_index {
            entry["sdo_index"] = json!(idx);
        }

        if let Some(sub) = frame.sdo_subindex {
            entry["sdo_subindex"] = json!(sub);
        }

        frames.push(entry);
    }

    json!({
        "sequence": msg.sequence,
        "frame_count": msg.frames.len(),
        "has_nmt": tx.detect_flags.has_nmt,
        "has_sdo": tx.detect_flags.has_sdo,
        "has_pdo": tx.detect_flags.has_pdo,
        "has_emergency": tx.detect_flags.has_emergency,
        "frames": frames,
    })
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &CanopenTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canopen;

    #[test]
    fn test_log_empty_message() {
        let msg = canopen::CanopenMessage {
            sequence: 0,
            flags: 0,
            frames: vec![],
        };
        let tx = crate::state::CanopenTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["sequence"], 0);
        assert_eq!(json["frame_count"], 0);
        assert_eq!(json["has_nmt"], false);
        assert_eq!(json["has_sdo"], false);
    }
}
