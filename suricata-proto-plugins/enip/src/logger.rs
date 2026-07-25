// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for EtherNet/IP (CIP) transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "enip": {
//!     "command": "SendRRData",
//!     "session_handle": 1,
//!     "cip_service": "Read_Tag",
//!     "cip_class": 2,
//!     "cip_instance": 1,
//!     "status": 0,
//!     "product_name": "1756-L71 Logix5571"
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::EnipTransaction;

/// Generate EVE JSON for an EtherNet/IP transaction.
pub fn log_transaction(tx: &EnipTransaction) -> Value {
    let mut enip = json!({
        "command": tx.detect_flags.command,
        "session_handle": tx.detect_flags.session_handle,
        "status": tx.detect_flags.status,
    });

    if let Some(ref svc) = tx.detect_flags.cip_service {
        enip["cip_service"] = json!(svc);
        enip["cip_class"] = json!(tx.detect_flags.cip_class);
        enip["cip_instance"] = json!(tx.detect_flags.cip_instance);
        if tx.detect_flags.cip_attribute > 0 {
            enip["cip_attribute"] = json!(tx.detect_flags.cip_attribute);
        }
        enip["is_response"] = json!(tx.detect_flags.is_response);
    }

    if let Some(ref name) = tx.detect_flags.product_name {
        enip["product_name"] = json!(name);
    }

    // Add identity details if present
    if let Some(ref identity) = tx.message.identity {
        enip["vendor_id"] = json!(identity.vendor_id);
        enip["device_type"] = json!(identity.device_type);
        enip["product_code"] = json!(identity.product_code);
        enip["revision"] = json!(format!("{}.{}", identity.revision_major, identity.revision_minor));
        enip["serial_number"] = json!(format!("0x{:08x}", identity.serial_number));
    }

    enip
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &EnipTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enip;

    #[test]
    fn test_log_register_session() {
        let msg = enip::EnipMessage {
            header: enip::EnipHeader {
                command: enip::EnipCommand::RegisterSession,
                length: 4,
                session_handle: 0x00000001,
                status: 0,
                sender_context: [0u8; 8],
                options: 0,
            },
            cip: None,
            identity: None,
        };
        let tx = crate::state::EnipTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["command"], "RegisterSession");
        assert_eq!(json["session_handle"], 1);
        assert_eq!(json["status"], 0);
    }
}
