// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for IEC 61850 MMS transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "iec61850": {
//!     "pdu_type": "confirmed-request",
//!     "service": "read",
//!     "mms_domain": "LD0",
//!     "variable_name": "XCBR1$ST$Pos$stVal",
//!     "iec61850_path": "LD0/XCBR1$ST$Pos$stVal",
//!     "confirmed": true,
//!     "invoke_id": 1
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::Iec61850Transaction;

/// Generate EVE JSON for an IEC 61850 transaction.
pub fn log_transaction(tx: &Iec61850Transaction) -> Value {
    let msg = &tx.message;

    let mut iec61850 = json!({
        "cotp_type": msg.cotp_type.name(),
        "tpkt_length": msg.tpkt_length,
    });

    if let Some(ref pdu_type) = msg.pdu_type {
        iec61850["pdu_type"] = json!(pdu_type.name());
    }
    if let Some(ref svc) = msg.service {
        iec61850["service"] = json!(svc.name());
    }
    if let Some(ref domain) = msg.mms_domain {
        iec61850["mms_domain"] = json!(domain);
    }
    if let Some(ref var) = msg.variable_name {
        iec61850["variable_name"] = json!(var);
    }
    if let Some(ref path) = msg.iec61850_path {
        iec61850["iec61850_path"] = json!(path);
    }
    if msg.confirmed {
        iec61850["confirmed"] = json!(true);
    }
    if let Some(inv_id) = msg.invoke_id {
        iec61850["invoke_id"] = json!(inv_id);
    }
    if msg.mms_payload_size > 0 {
        iec61850["mms_payload_size"] = json!(msg.mms_payload_size);
    }

    iec61850
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &Iec61850Transaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iec61850;

    #[test]
    fn test_log_initiate_request() {
        // Build a TPKT/COTP/MMS Initiate-Request
        let mut buf = Vec::new();
        // TPKT header
        buf.push(0x03); buf.push(0x00);
        let mms = vec![iec61850::MMS_INITIATE_REQUEST, 0x02, 0x01, 0x02];
        let cotp = vec![0x02, 0xF0, 0x80]; // COTP DT
        let total = (4 + cotp.len() + mms.len()) as u16;
        buf.extend_from_slice(&total.to_be_bytes());
        buf.extend_from_slice(&cotp);
        buf.extend_from_slice(&mms);

        let msg = iec61850::parse_message(&buf).unwrap();
        let tx = crate::state::Iec61850Transaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["pdu_type"], "initiate-request");
        assert_eq!(json["cotp_type"], "DT");
    }
}
