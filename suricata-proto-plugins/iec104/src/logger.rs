// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for IEC 104 transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "iec104": {
//!     "apdu_count": 1,
//!     "apdus": [
//!       {
//!         "frame_type": "I",
//!         "send_seq": 0,
//!         "recv_seq": 0,
//!         "asdu": {
//!           "type_id": 100,
//!           "type_name": "C_IC_NA (Interrogation)",
//!           "is_command": true,
//!           "cot": "activation",
//!           "common_address": 1,
//!           "num_objects": 1,
//!           "ioas": [0]
//!         }
//!       }
//!     ]
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::iec104::FrameType;
use crate::state::Iec104Transaction;

/// Generate EVE JSON for an IEC 104 transaction.
pub fn log_transaction(tx: &Iec104Transaction) -> Value {
    let msg = &tx.message;

    let mut apdus = Vec::new();
    for apdu in &msg.apdus {
        let mut entry = json!({
            "frame_type": format!("{}", apdu.apci.frame_type),
        });

        // U-frame: add function name
        if apdu.apci.frame_type == FrameType::U {
            if let Some(ref uf) = apdu.apci.u_function() {
                entry["u_function"] = json!(uf.name());
            }
        }

        // I-frame: add sequence numbers
        if let Some(send_seq) = apdu.apci.send_seq() {
            entry["send_seq"] = json!(send_seq);
        }
        if let Some(recv_seq) = apdu.apci.recv_seq() {
            entry["recv_seq"] = json!(recv_seq);
        }

        // ASDU (only present in I-frames)
        if let Some(ref asdu) = apdu.asdu {
            let ioas: Vec<u32> = asdu.ioa_list.clone();
            entry["asdu"] = json!({
                "type_id": asdu.type_id.0,
                "type_name": asdu.type_id.name(),
                "is_command": asdu.type_id.is_command(),
                "cot": asdu.cot.name(),
                "common_address": asdu.common_address,
                "num_objects": asdu.num_objects,
                "ioas": ioas,
            });
        }

        apdus.push(entry);
    }

    json!({
        "apdu_count": msg.apdus.len(),
        "apdus": apdus,
    })
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &Iec104Transaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iec104;

    #[test]
    fn test_log_u_frame() {
        // STARTDT_ACT: 0x68 0x04 0x07 0x00 0x00 0x00
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let msg = iec104::parse_message(&buf).unwrap();
        let tx = crate::state::Iec104Transaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["apdu_count"], 1);
        assert_eq!(json["apdus"][0]["frame_type"], "U");
        assert_eq!(json["apdus"][0]["u_function"], "STARTDT_ACT");
    }

    #[test]
    fn test_log_i_frame_with_asdu() {
        // I-frame with ASDU: interrogation command (C_IC_NA, type 100)
        let buf = [
            0x68, 0x0E, // start, length=14
            0x00, 0x00, 0x00, 0x00, // I-frame control (seq 0/0)
            100,  // type_id = C_IC_NA
            0x01, // SQ=0, num_objects=1
            0x06, // COT=6 (activation)
            0x00, // originator=0
            0x01, 0x00, // common_address=1
            0x00, 0x00, 0x00, // IOA=0
            0x14, // QOI=20
        ];
        let msg = iec104::parse_message(&buf).unwrap();
        let tx = crate::state::Iec104Transaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["apdu_count"], 1);
        assert_eq!(json["apdus"][0]["frame_type"], "I");
        assert_eq!(json["apdus"][0]["send_seq"], 0);
        assert_eq!(json["apdus"][0]["recv_seq"], 0);
        assert_eq!(json["apdus"][0]["asdu"]["type_id"], 100);
        assert_eq!(json["apdus"][0]["asdu"]["type_name"], "C_IC_NA (Interrogation)");
        assert_eq!(json["apdus"][0]["asdu"]["is_command"], true);
        assert_eq!(json["apdus"][0]["asdu"]["cot"], "activation");
        assert_eq!(json["apdus"][0]["asdu"]["common_address"], 1);
        assert_eq!(json["apdus"][0]["asdu"]["num_objects"], 1);
        assert_eq!(json["apdus"][0]["asdu"]["ioas"][0], 0);
    }

    #[test]
    fn test_log_s_frame() {
        // S-frame: recv_seq=1
        let buf = [0x68, 0x04, 0x01, 0x00, 0x02, 0x00];
        let msg = iec104::parse_message(&buf).unwrap();
        let tx = crate::state::Iec104Transaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["apdu_count"], 1);
        assert_eq!(json["apdus"][0]["frame_type"], "S");
        assert_eq!(json["apdus"][0]["recv_seq"], 1);
    }
}
