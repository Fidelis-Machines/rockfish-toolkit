// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for OPC UA transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "opcua": {
//!     "message_type": "Message",
//!     "security_mode": "SignAndEncrypt",
//!     "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
//!     "endpoint_url": "opc.tcp://plc01.factory:4840",
//!     "service_type": "Read",
//!     "node_ids": ["ns=0; i=631"],
//!     "status_code": 0
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::opcua::MessageContent;
use crate::state::OpcuaTransaction;

/// Generate EVE JSON for an OPC UA transaction.
pub fn log_transaction(tx: &OpcuaTransaction) -> Value {
    let mut opcua = json!({
        "message_type": tx.detect_flags.message_type,
        "security_mode": tx.detect_flags.security_mode,
    });

    if let Some(ref policy) = tx.detect_flags.security_policy {
        opcua["security_policy"] = json!(policy);
    }

    if let Some(ref url) = tx.detect_flags.endpoint_url {
        opcua["endpoint_url"] = json!(url);
    }

    if let Some(ref svc) = tx.detect_flags.service_type {
        opcua["service_type"] = json!(svc);
    }

    if !tx.detect_flags.node_ids.is_empty() {
        opcua["node_ids"] = json!(tx.detect_flags.node_ids);
    }

    opcua["status_code"] = json!(tx.detect_flags.status_code);

    // Add message-specific details
    match &tx.message.content {
        MessageContent::Hello(hello) => {
            opcua["protocol_version"] = json!(hello.protocol_version);
            opcua["receive_buffer_size"] = json!(hello.receive_buffer_size);
            opcua["send_buffer_size"] = json!(hello.send_buffer_size);
        }
        MessageContent::Acknowledge(ack) => {
            opcua["protocol_version"] = json!(ack.protocol_version);
            opcua["receive_buffer_size"] = json!(ack.receive_buffer_size);
            opcua["send_buffer_size"] = json!(ack.send_buffer_size);
        }
        MessageContent::Error(err) => {
            opcua["error_code"] = json!(format!("0x{:08x}", err.error_code));
            opcua["reason"] = json!(err.reason);
        }
        MessageContent::Secure(sec) => {
            opcua["secure_channel_id"] = json!(sec.channel_header.secure_channel_id);
            opcua["sequence_number"] = json!(sec.channel_header.sequence_number);
            opcua["request_id"] = json!(sec.channel_header.request_id);
        }
        MessageContent::Raw(_) => {}
    }

    opcua
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &OpcuaTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcua;

    #[test]
    fn test_log_hello_message() {
        let msg = opcua::OpcuaMessage {
            header: opcua::MessageHeader {
                message_type: opcua::MessageType::Hello,
                chunk_type: opcua::ChunkType::Final,
                message_size: 64,
            },
            content: opcua::MessageContent::Hello(opcua::HelloMessage {
                protocol_version: 0,
                receive_buffer_size: 65535,
                send_buffer_size: 65535,
                max_message_size: 0,
                max_chunk_count: 0,
                endpoint_url: "opc.tcp://localhost:4840".to_string(),
            }),
        };
        let tx = crate::state::OpcuaTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["message_type"], "Hello");
        assert_eq!(json["endpoint_url"], "opc.tcp://localhost:4840");
        assert_eq!(json["security_mode"], "None");
    }
}
