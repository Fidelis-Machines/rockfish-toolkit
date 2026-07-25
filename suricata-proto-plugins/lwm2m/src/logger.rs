// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for LwM2M transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "lwm2m": {
//!     "operation": "Register",
//!     "endpoint_name": "my_sensor",
//!     "object_id": 3,
//!     "instance_id": 0,
//!     "object_name": "Device",
//!     "lifetime": 3600,
//!     "lwm2m_version": "1.1",
//!     "payload_format": "TLV",
//!     "coap_type": "CON",
//!     "coap_code": "0.02"
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::Lwm2mTransaction;

/// Generate EVE JSON for an LwM2M transaction.
pub fn log_transaction(tx: &Lwm2mTransaction) -> Value {
    let msg = &tx.message;

    let mut lwm2m = json!({
        "operation": msg.operation.name(),
        "coap_type": msg.coap_type.name(),
        "coap_code": format!("{}", msg.code),
        "message_id": msg.message_id,
    });

    if let Some(ref ep) = msg.endpoint_name {
        lwm2m["endpoint_name"] = json!(ep);
    }
    if let Some(obj_id) = msg.object_id {
        lwm2m["object_id"] = json!(obj_id);
    }
    if let Some(inst_id) = msg.instance_id {
        lwm2m["instance_id"] = json!(inst_id);
    }
    if let Some(res_id) = msg.resource_id {
        lwm2m["resource_id"] = json!(res_id);
    }
    if let Some(ref name) = msg.object_name {
        lwm2m["object_name"] = json!(name);
    }
    if let Some(lt) = msg.lifetime {
        lwm2m["lifetime"] = json!(lt);
    }
    if let Some(ref ver) = msg.lwm2m_version {
        lwm2m["lwm2m_version"] = json!(ver);
    }
    if let Some(ref fmt) = msg.payload_format {
        lwm2m["payload_format"] = json!(fmt.name());
    }
    if msg.payload_size > 0 {
        lwm2m["payload_size"] = json!(msg.payload_size);
    }
    if !msg.uri_path.is_empty() {
        lwm2m["uri_path"] = json!(format!("/{}", msg.uri_path.join("/")));
    }

    lwm2m
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &Lwm2mTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lwm2m;

    #[test]
    fn test_log_registration() {
        // Build a registration CoAP message
        let buf = build_test_registration();
        let msg = lwm2m::parse_message(&buf).unwrap();
        let tx = crate::state::Lwm2mTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["operation"], "Register");
        assert_eq!(json["endpoint_name"], "test_ep");
    }

    fn build_test_registration() -> Vec<u8> {
        // Manually build a CoAP POST /rd?ep=test_ep
        let mut buf = Vec::new();
        // Header: ver=1, type=CON(0), tkl=1
        buf.push(0x41);
        // Code: POST (0.02)
        buf.push(0x02);
        // Message ID
        buf.push(0x00);
        buf.push(0x01);
        // Token
        buf.push(0xAA);
        // Option: URI-Path "rd" (delta=11, len=2)
        buf.push(0xB2); // delta=11 (URI-Path), length=2
        buf.extend_from_slice(b"rd");
        // Option: URI-Query "ep=test_ep" (delta=4, len=10)
        buf.push(0x4A); // delta=4 (15-11), length=10
        buf.extend_from_slice(b"ep=test_ep");
        buf
    }
}
