// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Per-flow PQC tracker.
//!
//! For each flow we maintain at most one PQC verdict — the first ClientHello
//! and ServerHello we observe. Subsequent records are ignored (handshake
//! happens once; renegotiation is rare and TLS 1.3 forbids it entirely).
//!
//! A flow is dropped from the table when we either:
//!   * have seen both halves and emitted, or
//!   * exceed `max_packets_per_dir` payload-bearing packets without finding
//!     a handshake (presumably not TLS, or handshake spans more than the
//!     plugin is willing to reassemble).

use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::groups::{any_pq, classify, group_name, GroupClass};
use crate::parser::{parse_segment, ParsedHandshake};

#[derive(Default)]
pub struct PqcFlow {
    /// Number of payload-bearing packets we've already inspected per
    /// direction. We bail out once both exceed the cap, to keep state
    /// small for long-lived flows that never produced a TLS handshake.
    pub pkts_to_server: u32,
    pub pkts_to_client: u32,

    /// ClientHello supported_groups, when found.
    pub client_supported_groups: Option<Vec<u16>>,
    /// ServerHello chosen named_group (TLS 1.3) when found.
    pub server_chosen_group: Option<u16>,
    /// Negotiated TLS version (0x0303 = 1.2, 0x0304 = 1.3) when extractable.
    pub negotiated_version: Option<u16>,
}

impl PqcFlow {
    /// True if both the client offer and the server choice have been seen
    /// (TLS 1.3) — or if only ClientHello has been seen and we've burned
    /// through enough packets that the server side likely won't surface
    /// in plaintext. The flow logger decides when to emit.
    pub fn has_verdict(&self) -> bool {
        self.client_supported_groups.is_some() && self.server_chosen_group.is_some()
    }

    /// True if we've seen a ClientHello but no ServerHello — emit as a
    /// "client-only" partial verdict at flow end if no further evidence
    /// arrives.
    pub fn client_only(&self) -> bool {
        self.client_supported_groups.is_some() && self.server_chosen_group.is_none()
    }
}

pub struct State {
    pub cfg: PluginConfig,
    flows: HashMap<u64, PqcFlow>,
    dropped: u64,
}

impl State {
    pub fn new(cfg: PluginConfig) -> Self {
        Self { cfg, flows: HashMap::new(), dropped: 0 }
    }

    pub fn shutdown(self) {
        crate::log_notice(&format!(
            "tls-pqc shutdown: tracked_flows={} dropped={}",
            self.flows.len(),
            self.dropped
        ));
    }

    /// Per-packet observation. `direction` 0 = to-server, 1 = to-client.
    /// `payload`/`payload_len` is the TCP payload (post-IP/TCP headers).
    pub fn observe(
        &mut self,
        flow_hash: u64,
        direction: u8,
        payload: *const u8,
        payload_len: u32,
    ) {
        if payload.is_null() || payload_len == 0 {
            return;
        }
        // Cap flow table size — pure backpressure.
        if !self.flows.contains_key(&flow_hash) {
            if self.flows.len() as u32 >= self.cfg.max_flows {
                self.dropped = self.dropped.saturating_add(1);
                return;
            }
        }

        let max_per_dir = self.cfg.max_packets_per_dir;
        let flow = self.flows.entry(flow_hash).or_default();

        // Bail once both sides have given up.
        let pkts = if direction == 0 { &mut flow.pkts_to_server } else { &mut flow.pkts_to_client };
        if *pkts >= max_per_dir {
            return;
        }
        *pkts = pkts.saturating_add(1);

        // Skip already-known sides.
        if direction == 0 && flow.client_supported_groups.is_some() {
            return;
        }
        if direction == 1 && flow.server_chosen_group.is_some() && flow.negotiated_version.is_some() {
            return;
        }

        let slice = unsafe { std::slice::from_raw_parts(payload, payload_len as usize) };
        let parsed: ParsedHandshake = parse_segment(slice);

        if let Some(groups) = parsed.client_supported_groups {
            if direction == 0 {
                flow.client_supported_groups = Some(groups);
            }
        }
        if let Some(group) = parsed.server_chosen_group {
            if direction == 1 {
                flow.server_chosen_group = Some(group);
            }
        }
        if let Some(v) = parsed.negotiated_version {
            if direction == 1 {
                flow.negotiated_version = Some(v);
            }
        }
    }

    /// Pop the flow's accumulated state for emission.
    pub fn take(&mut self, flow_hash: u64) -> Option<PqcFlow> {
        self.flows.remove(&flow_hash)
    }
}

// ── Emission-side helpers — used by the FFI export to compose the eve event.

/// Compact verdict suitable for embedding in the eve event.
pub struct Verdict {
    pub client_offered_pqc: bool,
    pub client_dominant_class: GroupClass,
    pub server_chosen_group: Option<u16>,
    pub server_chosen_class: GroupClass,
    pub nist_compliant: bool,
    pub exposure: ExposureClass,
    pub tls_version_be: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
pub enum ExposureClass {
    /// Server actually negotiated a PQ KEM. Safe per NIST IR 8547.
    Compliant,
    /// Client offered PQ, server chose classical. Server-side lag —
    /// silent exposure that classical clients can't detect.
    ServerLagging,
    /// Client never offered PQ. End-to-end classical — directly exposed.
    ClientLagging,
    /// Only one half of the handshake observed; treat as a soft warning.
    Partial,
    /// Couldn't classify (e.g. all-unknown groups). Don't alert.
    Unknown,
}

impl ExposureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ExposureClass::Compliant => "compliant",
            ExposureClass::ServerLagging => "server_lagging",
            ExposureClass::ClientLagging => "client_lagging",
            ExposureClass::Partial => "partial",
            ExposureClass::Unknown => "unknown",
        }
    }
}

/// Compute the verdict from a captured flow.
pub fn verdict_for(flow: &PqcFlow) -> Verdict {
    let client_offered = flow
        .client_supported_groups
        .as_deref()
        .map(any_pq)
        .unwrap_or(false);
    let client_class = flow
        .client_supported_groups
        .as_deref()
        .map(crate::groups::dominant_class)
        .unwrap_or(GroupClass::Unknown);

    let server_class = flow
        .server_chosen_group
        .map(classify)
        .unwrap_or(GroupClass::Unknown);

    let exposure = match (
        flow.client_supported_groups.as_ref(),
        flow.server_chosen_group,
    ) {
        (Some(_), Some(_)) => {
            if server_class.is_pq() {
                ExposureClass::Compliant
            } else if client_offered {
                ExposureClass::ServerLagging
            } else {
                ExposureClass::ClientLagging
            }
        }
        (Some(_), None) => {
            // ClientHello but no ServerHello observed — most common case for
            // TLS 1.2 (no key_share to extract).
            if client_offered { ExposureClass::Partial } else { ExposureClass::ClientLagging }
        }
        _ => ExposureClass::Unknown,
    };
    let nist_compliant = matches!(exposure, ExposureClass::Compliant);

    Verdict {
        client_offered_pqc: client_offered,
        client_dominant_class: client_class,
        server_chosen_group: flow.server_chosen_group,
        server_chosen_class: server_class,
        nist_compliant,
        exposure,
        tls_version_be: flow.negotiated_version,
    }
}

/// User-friendly name for a chosen group codepoint (None when not set).
pub fn server_group_name(verdict: &Verdict) -> Option<&'static str> {
    verdict.server_chosen_group.map(group_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PluginConfig {
        PluginConfig {
            tcp_enabled: true,
            sample_rate: 1,
            max_flows: 100,
            max_packets_per_dir: 8,
        }
    }

    #[test]
    fn verdict_compliant_when_server_picks_pq() {
        let flow = PqcFlow {
            client_supported_groups: Some(vec![4588, 29, 23]),
            server_chosen_group: Some(4588),
            negotiated_version: Some(0x0304),
            ..Default::default()
        };
        let v = verdict_for(&flow);
        assert!(v.client_offered_pqc);
        assert!(v.nist_compliant);
        assert!(matches!(v.exposure, ExposureClass::Compliant));
    }

    #[test]
    fn verdict_server_lagging_when_client_offered_but_server_picks_classical() {
        let flow = PqcFlow {
            client_supported_groups: Some(vec![4588, 29, 23]),
            server_chosen_group: Some(29), // X25519
            negotiated_version: Some(0x0304),
            ..Default::default()
        };
        let v = verdict_for(&flow);
        assert!(v.client_offered_pqc);
        assert!(!v.nist_compliant);
        assert!(matches!(v.exposure, ExposureClass::ServerLagging));
    }

    #[test]
    fn verdict_client_lagging_when_no_pq_offered() {
        let flow = PqcFlow {
            client_supported_groups: Some(vec![29, 23]),
            server_chosen_group: Some(29),
            negotiated_version: Some(0x0303),
            ..Default::default()
        };
        let v = verdict_for(&flow);
        assert!(!v.client_offered_pqc);
        assert!(matches!(v.exposure, ExposureClass::ClientLagging));
    }

    #[test]
    fn state_caps_per_direction() {
        let mut s = State::new(cfg());
        let buf = [0u8; 8];
        for _ in 0..16 {
            s.observe(1, 0, buf.as_ptr(), buf.len() as u32);
        }
        let flow = s.take(1).unwrap();
        assert!(flow.pkts_to_server <= 8);
    }
}
