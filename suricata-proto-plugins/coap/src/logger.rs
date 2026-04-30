// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for CoAP transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "coap": {
//!     "type": "CON",
//!     "code_class": 0,
//!     "code_detail": 1,
//!     "method": "GET",
//!     "message_id": 1,
//!     "token": "aabb",
//!     "uri_path": "/sensor/temperature",
//!     "content_format": "application/json",
//!     "payload_size": 42
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::coap;
use crate::state::CoapTransaction;

/// Generate EVE JSON for a CoAP transaction.
pub fn log_transaction(tx: &CoapTransaction) -> Value {
    let msg = &tx.message;
    let flags = &tx.detect_flags;

    let mut coap_json = json!({
        "type": flags.msg_type,
        "code_class": flags.code_class,
        "code_detail": flags.code_detail,
        "code": msg.code.display_name(),
        "message_id": msg.message_id,
        "token": flags.token_hex,
        "payload_size": flags.payload_size,
    });

    if let Some(ref method) = flags.method {
        coap_json["method"] = json!(method);
    }

    if let Some(ref path) = flags.uri_path {
        coap_json["uri_path"] = json!(path);
    }

    if let Some(ref query) = flags.uri_query {
        coap_json["uri_query"] = json!(query);
    }

    if let Some(ref cf) = flags.content_format {
        coap_json["content_format"] = json!(cf);
    }

    if let Some(cf_id) = msg.content_format {
        coap_json["content_format_id"] = json!(cf_id);
    }

    // Include options summary
    let option_names: Vec<&str> = msg
        .options
        .iter()
        .filter_map(|o| o.name)
        .collect();
    if !option_names.is_empty() {
        coap_json["options"] = json!(option_names);
    }

    // Block transfer info
    for opt in &msg.options {
        match opt.number {
            23 => {
                // Block2
                if let Some(v) = opt.value_uint {
                    coap_json["block2_num"] = json!(v >> 4);
                    coap_json["block2_more"] = json!((v & 0x08) != 0);
                    coap_json["block2_szx"] = json!(v & 0x07);
                }
            }
            27 => {
                // Block1
                if let Some(v) = opt.value_uint {
                    coap_json["block1_num"] = json!(v >> 4);
                    coap_json["block1_more"] = json!((v & 0x08) != 0);
                    coap_json["block1_szx"] = json!(v & 0x07);
                }
            }
            6 => {
                // Observe
                if let Some(v) = opt.value_uint {
                    coap_json["observe"] = json!(v);
                }
            }
            _ => {}
        }
    }

    coap_json
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &CoapTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_get_request() {
        let buf = [
            0x42, 0x01, 0x00, 0x01, // CON GET, MsgID=1, TKL=2
            0xAA, 0xBB,             // Token
            0xB4,                   // Option: Uri-Path, length=4
            b't', b'e', b's', b't',
        ];
        let msg = coap::parse_message(&buf).unwrap();
        let tx = CoapTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["type"], "CON");
        assert_eq!(json["method"], "GET");
        assert_eq!(json["uri_path"], "/test");
        assert_eq!(json["token"], "aabb");
        assert_eq!(json["code_class"], 0);
        assert_eq!(json["code_detail"], 1);
    }
}
