// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for PROFINET transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "profinet": {
//!     "frame_id": "0xfefe",
//!     "frame_type": "dcp",
//!     "service_id": "Identify",
//!     "service_type": "Request",
//!     "xid": 66,
//!     "station_name": "plc-station-1",
//!     "device_id": "002a:0401",
//!     "ip_address": "192.168.1.100",
//!     "blocks": [
//!       { "option": "Name-of-Station", "value": "plc-station-1" }
//!     ]
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::ProfinetTransaction;

/// Generate EVE JSON for a PROFINET transaction.
pub fn log_transaction(tx: &ProfinetTransaction) -> Value {
    let msg = &tx.message;
    let flags = &tx.detect_flags;

    let mut pn = json!({
        "frame_id": format!("0x{:04x}", msg.frame_id),
        "frame_type": flags.frame_type,
        "xid": msg.xid,
        "dcp_data_length": msg.dcp_data_length,
    });

    if let Some(ref sid) = flags.service_id {
        pn["service_id"] = json!(sid);
    }
    if let Some(ref st) = flags.service_type {
        pn["service_type"] = json!(st);
    }
    if let Some(ref name) = flags.station_name {
        pn["station_name"] = json!(name);
    }
    if let Some(ref did) = flags.device_id {
        pn["device_id"] = json!(did);
    }
    if let Some(ref ip) = flags.ip_address {
        pn["ip_address"] = json!(ip);
    }

    // Log DCP blocks
    let blocks: Vec<Value> = msg
        .blocks
        .iter()
        .map(|b| {
            let mut block = json!({
                "option": b.option.name(),
                "option_raw": format!("{}.{}", b.option.option, b.option.suboption),
                "length": b.block_length,
            });
            if let Some(ref v) = b.value_string {
                block["value"] = json!(v);
            }
            block
        })
        .collect();

    if !blocks.is_empty() {
        pn["blocks"] = json!(blocks);
    }

    pn
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &ProfinetTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profinet;

    #[test]
    fn test_log_dcp_identify() {
        let buf = [
            0xFE, 0xFE,             // Frame ID
            0x05,                   // Service ID: Identify
            0x00,                   // Service Type: Request
            0x00, 0x00, 0x00, 0x42, // Xid
            0x00, 0x80,             // Response delay
            0x00, 0x04,             // DCP data length
            0xFF, 0xFF, 0x00, 0x00, // All-Selector block
        ];
        let msg = profinet::parse_message(&buf).unwrap();
        let tx = ProfinetTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["frame_id"], "0xfefe");
        assert_eq!(json["frame_type"], "dcp");
        assert_eq!(json["service_id"], "Identify");
    }
}
