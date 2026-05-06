// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Central per-flow state coordinator.
//!
//! Stats are exported via `take_tcp_stats` / `take_udp_stats` (which pop the
//! flow out of the in-memory map). The C side calls these from Suricata's
//! flow-end eve sub-loggers and renders the result through `OutputJsonBuilderBuffer`.

use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::tcp::TcpFlow;
use crate::udp::UdpFlow;

/// Maximum length of an address string buffer (IPv4 or IPv6).
pub const ADDR_BUF: usize = 64;

pub struct State {
    pub cfg: PluginConfig,
    tcp_flows: HashMap<u64, TcpFlow>,
    udp_flows: HashMap<u64, UdpFlow>,
    /// Number of flows dropped because the cap was reached.
    dropped_flows: u64,
}

impl State {
    pub fn new(cfg: PluginConfig) -> Self {
        Self {
            cfg,
            tcp_flows: HashMap::new(),
            udp_flows: HashMap::new(),
            dropped_flows: 0,
        }
    }

    pub fn shutdown(self) {
        crate::log_notice(&format!(
            "transport-signals shutdown: tcp_flows={} udp_flows={} dropped={}",
            self.tcp_flows.len(), self.udp_flows.len(), self.dropped_flows
        ));
    }

    /// Resolve a `[u8; ADDR_BUF]` C-style buffer back to a string.
    fn addr_str(buf: &[u8; ADDR_BUF]) -> &str {
        let n = buf.iter().position(|&b| b == 0).unwrap_or(ADDR_BUF);
        std::str::from_utf8(&buf[..n]).unwrap_or("")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_tcp(
        &mut self,
        flow_hash: u64,
        ts_us: i64,
        src_ip: [u8; ADDR_BUF],
        dst_ip: [u8; ADDR_BUF],
        src_port: u16,
        dst_port: u16,
        direction: u8,
        flags: u8,
        seq: u32,
        ack: u32,
        window: u16,
        _wscale: u8,
        payload_len: u32,
    ) {
        if !self.tcp_flows.contains_key(&flow_hash) {
            if self.tcp_flows.len() as u32 >= self.cfg.max_flows {
                self.dropped_flows += 1;
                return;
            }
        }
        let flow = self.tcp_flows.entry(flow_hash).or_default();
        let s = Self::addr_str(&src_ip);
        let d = Self::addr_str(&dst_ip);
        flow.observe(ts_us, s, d, src_port, dst_port, direction,
                     flags, seq, ack, window, payload_len);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_udp(
        &mut self,
        flow_hash: u64,
        ts_us: i64,
        src_ip: [u8; ADDR_BUF],
        dst_ip: [u8; ADDR_BUF],
        src_port: u16,
        dst_port: u16,
        direction: u8,
        payload_len: u32,
    ) {
        if !self.udp_flows.contains_key(&flow_hash) {
            if self.udp_flows.len() as u32 >= self.cfg.max_flows {
                self.dropped_flows += 1;
                return;
            }
        }
        let flow = self.udp_flows.entry(flow_hash).or_default();
        let s = Self::addr_str(&src_ip);
        let d = Self::addr_str(&dst_ip);
        let rtt_window_us = (self.cfg.udp_rtt_window_ms as i64) * 1000;
        flow.observe(ts_us, s, d, src_port, dst_port, direction,
                     payload_len, rtt_window_us);
    }

    pub fn take_tcp(&mut self, flow_hash: u64) -> Option<TcpFlow> {
        self.tcp_flows.remove(&flow_hash)
    }

    pub fn take_udp(&mut self, flow_hash: u64) -> Option<UdpFlow> {
        self.udp_flows.remove(&flow_hash)
    }
}
