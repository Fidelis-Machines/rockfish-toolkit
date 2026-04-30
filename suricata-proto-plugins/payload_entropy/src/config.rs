// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Plugin configuration deserialized from suricata.yaml via a JSON bridge.

use serde::Deserialize;

fn default_true() -> bool { true }
fn default_one() -> u32 { 1 }
fn default_max_flows() -> u32 { 100_000 }
fn default_max_packets_per_dir() -> u32 { 16 }
fn default_max_bytes_per_dir() -> u32 { 8192 }

/// Per-feature emit toggles. By default all are enabled when the plugin
/// itself is enabled.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct EmitConfig {
    /// Shannon entropy + bytes_sampled per direction.
    #[serde(default = "default_true")] pub entropy: bool,
    /// PCR (producer/consumer ratio) over the sampled byte window.
    #[serde(default = "default_true")] pub pcr: bool,
    /// SPLT — letter sequence (`splt`) + raw arrays (`splt_lengths`,
    /// `splt_iats_us`). All three are emitted/skipped together.
    #[serde(default = "default_true")] pub splt: bool,
}

impl Default for EmitConfig {
    fn default() -> Self {
        Self { entropy: true, pcr: true, splt: true }
    }
}

/// Plugin configuration. Events are emitted through Suricata's eve-log
/// subsystem — there is no plugin-side output destination.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PluginConfig {
    /// Enable per-protocol observation.
    #[serde(default = "default_true")] pub tcp_enabled: bool,
    #[serde(default = "default_true")] pub udp_enabled: bool,

    /// 1-in-N flow sampling. 1 = log every flow.
    #[serde(default = "default_one")]
    pub sample_rate: u32,

    /// Per-flow state cap. New flows are dropped when this is exceeded.
    #[serde(default = "default_max_flows")]
    pub max_flows: u32,

    /// Stop sampling after this many payload-bearing packets per direction.
    /// Caps the SPLT length to roughly `2 × max_packets_per_dir`.
    #[serde(default = "default_max_packets_per_dir")]
    pub max_packets_per_dir: u32,

    /// Hard byte cap per direction for the entropy histogram.
    #[serde(default = "default_max_bytes_per_dir")]
    pub max_bytes_per_dir: u32,

    /// Per-feature emit toggles.
    #[serde(default)]
    pub emit: EmitConfig,
}
