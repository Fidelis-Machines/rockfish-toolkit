// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for S7comm transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "s7comm": {
//!     "cotp_pdu_type": "DT_DATA",
//!     "msg_type": "Job",
//!     "function_code": "ReadVar",
//!     "area": "DB",
//!     "db_number": 1,
//!     "is_s7comm_plus": false,
//!     "is_security_relevant": false,
//!     "pdu_ref": 1,
//!     "param_length": 14,
//!     "data_length": 0
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::S7commTransaction;

/// Generate EVE JSON for an S7comm transaction.
pub fn log_transaction(tx: &S7commTransaction) -> Value {
    let msg = &tx.message;
    let flags = &tx.detect_flags;

    let mut s7 = json!({
        "cotp_pdu_type": flags.cotp_pdu_type,
        "is_s7comm_plus": flags.is_s7comm_plus,
        "is_security_relevant": flags.is_security_relevant,
    });

    if let Some(ref hdr) = msg.s7_header {
        s7["msg_type"] = json!(hdr.msg_type.name());
        s7["msg_type_raw"] = json!(hdr.msg_type_raw);
        s7["pdu_ref"] = json!(hdr.pdu_ref);
        s7["param_length"] = json!(hdr.param_length);
        s7["data_length"] = json!(hdr.data_length);

        if let Some(ec) = hdr.error_class {
            s7["error_class"] = json!(ec);
        }
        if let Some(ec) = hdr.error_code {
            s7["error_code"] = json!(ec);
        }
    }

    if let Some(ref fc) = flags.function_code {
        s7["function_code"] = json!(fc);
    }
    if let Some(raw) = flags.function_code_raw {
        s7["function_code_raw"] = json!(format!("0x{:02x}", raw));
    }

    if let Some(ref area) = flags.area {
        s7["area"] = json!(area);
    }
    if let Some(db) = flags.db_number {
        s7["db_number"] = json!(db);
    }

    s7
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &S7commTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s7comm;

    #[test]
    fn test_log_cotp_cr() {
        let buf = [
            0x03, 0x00, 0x00, 0x16, // TPKT
            0x11, 0xE0,             // COTP: CR
            0x00, 0x00, 0x00, 0x01, 0x00, 0xC1, 0x02, 0x01,
            0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
        ];
        let msg = s7comm::parse_message(&buf).unwrap();
        let tx = S7commTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["cotp_pdu_type"], "CR");
        assert_eq!(json["is_s7comm_plus"], false);
    }
}
