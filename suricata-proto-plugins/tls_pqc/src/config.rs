// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Plugin configuration deserialized from suricata.yaml via a JSON bridge.

use serde::Deserialize;

fn default_true() -> bool { true }
fn default_one() -> u32 { 1 }
fn default_max_flows() -> u32 { 100_000 }
fn default_max_packets_per_dir() -> u32 { 8 }

/// Plugin configuration. Events are emitted through Suricata's eve-log
/// subsystem under event_type "pqc".
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PluginConfig {
    /// Enable TCP observation (TLS over TCP — i.e. nearly all real TLS).
    /// QUIC (TLS over UDP) is out of scope for v1.
    #[serde(default = "default_true")]
    pub tcp_enabled: bool,

    /// 1-in-N flow sampling. 1 = log every flow.
    #[serde(default = "default_one")]
    pub sample_rate: u32,

    /// Per-flow state cap. New flows are dropped when this is exceeded.
    #[serde(default = "default_max_flows")]
    pub max_flows: u32,

    /// Stop inspecting payload-bearing packets after this many per
    /// direction. The TLS handshake's ClientHello + ServerHello fit in
    /// the first 1-2 packets of each side; 8 is generous headroom.
    #[serde(default = "default_max_packets_per_dir")]
    pub max_packets_per_dir: u32,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            tcp_enabled: true,
            sample_rate: 1,
            max_flows: 100_000,
            max_packets_per_dir: 8,
        }
    }
}
