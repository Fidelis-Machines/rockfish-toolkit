// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! EVE JSON logger for ASTERIX transactions.
//!
//! Produces structured JSON output for Suricata's EVE logging framework.
//!
//! Example output:
//! ```json
//! {
//!   "asterix": {
//!     "category": 48,
//!     "category_name": "Monoradar Target Reports (Enhanced)",
//!     "record_count": 1,
//!     "track_number": 1234,
//!     "icao_address": "A1B2C3",
//!     "callsign": "UAL123",
//!     "latitude": 51.4775,
//!     "longitude": -0.4614,
//!     "altitude": 35000,
//!     "squawk_code": "7700",
//!     "time_of_day": 43200.5
//!   }
//! }
//! ```

use serde_json::{json, Value};

use crate::state::AsterixTransaction;

/// Generate EVE JSON for an ASTERIX transaction.
pub fn log_transaction(tx: &AsterixTransaction) -> Value {
    let msg = &tx.message;

    let primary_cat = msg.primary_category();
    let category = primary_cat.map(|c| c.0 as u64).unwrap_or(0);
    let category_name = primary_cat
        .map(|c| c.name())
        .unwrap_or("Unknown");

    let mut asterix = json!({
        "category": category,
        "category_name": category_name,
        "record_count": msg.total_record_count(),
        "data_block_count": msg.data_blocks.len(),
    });

    // Extract fields from the first record of the first block for top-level EVE fields
    if let Some(block) = msg.data_blocks.first() {
        if let Some(record) = block.records.first() {
            let fields = &record.fields;

            if let Some(tn) = fields.track_number {
                asterix["track_number"] = json!(tn);
            }
            if let Some(icao) = fields.icao_address {
                asterix["icao_address"] = json!(format!("{:06X}", icao));
            }
            if let Some(ref cs) = fields.callsign {
                asterix["callsign"] = json!(cs);
            }
            if let Some(lat) = fields.latitude {
                asterix["latitude"] = json!(lat);
            }
            if let Some(lon) = fields.longitude {
                asterix["longitude"] = json!(lon);
            }
            if let Some(alt) = fields.altitude {
                asterix["altitude"] = json!(alt);
            }
            if let Some(ga) = fields.geometric_altitude {
                asterix["geometric_altitude"] = json!(ga);
            }
            if let Some(sq) = fields.squawk_code {
                asterix["squawk_code"] = json!(format!("{:04o}", sq));
            }
            if let Some(tod) = fields.time_of_day {
                asterix["time_of_day"] = json!(tod);
            }
            if let Some(rho) = fields.rho {
                asterix["rho"] = json!(rho);
            }
            if let Some(theta) = fields.theta {
                asterix["theta"] = json!(theta);
            }
            if let Some(ec) = fields.emitter_category {
                asterix["emitter_category"] = json!(ec);
            }
        }
    }

    asterix
}

/// Serialize a transaction to a JSON string for EVE output.
pub fn log_transaction_string(tx: &AsterixTransaction) -> String {
    let val = log_transaction(tx);
    serde_json::to_string(&val).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asterix;

    #[test]
    fn test_log_basic_message() {
        // Build a minimal CAT 048 block
        let mut data = Vec::new();
        // FSPEC: no fields set
        data.push(0x00);

        let mut block_buf = Vec::new();
        block_buf.push(48); // category
        let length = (3 + data.len()) as u16;
        block_buf.extend_from_slice(&length.to_be_bytes());
        block_buf.extend_from_slice(&data);

        let msg = asterix::parse_message(&block_buf).unwrap();
        let tx = crate::state::AsterixTransaction::new(0, msg);
        let json = log_transaction(&tx);

        assert_eq!(json["category"], 48);
        assert_eq!(json["category_name"], "Monoradar Target Reports (Enhanced)");
    }
}
