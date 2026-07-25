// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for BACnet transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "bacnet": {
//!     "bvlc_function": "Original-Unicast-NPDU",
//!     "apdu_type": "Confirmed-REQ",
//!     "service_choice": "ReadProperty",
//!     "object_type": "Analog-Input",
//!     "object_instance": 1,
//!     "property_id": 85
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::BacnetTransaction;

/// Generate EVE JSON for a BACnet transaction.
pub fn log_transaction(tx: &BacnetTransaction) -> Value {
    let mut bacnet = json!({
        "bvlc_function": tx.detect_flags.bvlc_function,
    });

    if let Some(ref apdu_type) = tx.detect_flags.apdu_type {
        bacnet["apdu_type"] = json!(apdu_type);
    }

    if let Some(ref svc) = tx.detect_flags.service_choice {
        bacnet["service_choice"] = json!(svc);
    }

    if let Some(ref obj_type) = tx.detect_flags.object_type {
        bacnet["object_type"] = json!(obj_type);
    }

    if let Some(instance) = tx.detect_flags.object_instance {
        bacnet["object_instance"] = json!(instance);
    }

    if let Some(pid) = tx.detect_flags.property_id {
        bacnet["property_id"] = json!(pid);
    }

    if tx.detect_flags.is_broadcast {
        bacnet["is_broadcast"] = json!(true);
    }

    // Add NPDU details if present
    if let Some(ref npdu) = tx.message.npdu {
        if let Some(dnet) = npdu.dnet {
            bacnet["destination_network"] = json!(dnet);
        }
        if let Some(snet) = npdu.snet {
            bacnet["source_network"] = json!(snet);
        }
        bacnet["priority"] = json!(npdu.priority);
    }

    // Add APDU details if present
    if let Some(ref apdu) = tx.message.apdu {
        if let Some(invoke_id) = apdu.invoke_id {
            bacnet["invoke_id"] = json!(invoke_id);
        }
        if apdu.segmented {
            bacnet["segmented"] = json!(true);
        }
    }

    bacnet
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &BacnetTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bacnet;

    #[test]
    fn test_log_bvlc_only() {
        let msg = bacnet::BacnetMessage {
            bvlc: bacnet::BvlcHeader {
                bvlc_type: 0x81,
                function: bacnet::BvlcFunction::OriginalBroadcastNpdu,
                length: 12,
            },
            npdu: None,
            apdu: None,
            object_id: None,
            property_id: None,
        };
        let tx = crate::state::BacnetTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["bvlc_function"], "Original-Broadcast-NPDU");
        assert_eq!(json["is_broadcast"], true);
    }
}
