// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Plugin configuration deserialized from suricata.yaml via a JSON bridge.
//!
//! This plugin emits `tcp_signals` and `udp_signals` events through
//! Suricata's own eve-log writer (no separate file/socket of its own) —
//! the user enables it under `eve-log.types:` like any other event type.

use serde::Deserialize;

fn default_true() -> bool { true }
fn default_one() -> u32 { 1 }
fn default_max_flows() -> u32 { 100_000 }
fn default_idle_secs() -> u32 { 60 }
fn default_udp_rtt_ms() -> u32 { 2000 }

/// Plugin configuration.
///
/// Note: there is no output-file / socket-type / buffer config — events
/// flow through Suricata's normal eve-log subsystem, so all eve filetypes
/// (regular, syslog, unix_dgram, unix_stream, redis, ...) are supported
/// without any plugin-side awareness.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PluginConfig {
    /// Enable per-protocol observation.
    #[serde(default = "default_true")]
    pub tcp_enabled: bool,
    #[serde(default = "default_true")]
    pub udp_enabled: bool,

    /// 1-in-N flow sampling. 1 = log every flow.
    #[serde(default = "default_one")]
    pub sample_rate: u32,

    /// Per-flow state cap. New flows are dropped when this is exceeded.
    #[serde(default = "default_max_flows")]
    pub max_flows: u32,

    /// Idle timeout (seconds) for in-progress flow state.
    #[serde(default = "default_idle_secs")]
    pub flow_idle_secs: u32,

    /// Maximum UDP request/response pairing window (ms).
    #[serde(default = "default_udp_rtt_ms")]
    pub udp_rtt_window_ms: u32,

    /// Emit toggles. Disabled metrics are omitted from the eve record.
    #[serde(default = "default_true")] pub emit_handshake_rtt: bool,
    #[serde(default = "default_true")] pub emit_retransmits: bool,
    #[serde(default = "default_true")] pub emit_zero_window: bool,
    #[serde(default = "default_true")] pub emit_window_stats: bool,
    #[serde(default = "default_true")] pub emit_udp_rtt: bool,
    #[serde(default = "default_true")] pub emit_udp_jitter: bool,
}
