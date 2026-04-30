// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Per-flow tracker for three signals (each emit-toggleable):
//!   - Shannon byte entropy (bits/byte) per direction
//!   - PCR — producer/consumer ratio over the sampled byte window
//!   - SPLT — Sequence of Packet Lengths and Times. We emit three views:
//!       * `splt_lengths`   — first N exact payload byte counts (u16)
//!       * `splt_iats_us`   — first N inter-arrival times (µs, u32)
//!       * `splt`           — same N entries encoded as ASCII letters
//!                            (case = direction; letter = log2 size bucket)

use std::collections::HashMap;

use crate::config::PluginConfig;
use crate::entropy::shannon_bits_per_byte;

/// Maximum captured SPLT length (packets). 32 covers the default
/// 16 packets/direction × 2 directions; 64 leaves headroom.
pub const SPLT_MAX_LEN: usize = 64;

/// Quantize a payload size into the SPLT letter index 0..=10 (A–K / a–k).
/// Buckets: 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048+.
fn size_bucket(payload_len: u32) -> u8 {
    if payload_len <= 2 {
        return 0;
    }
    let v = payload_len.saturating_sub(1);
    let log2_ceil = 32 - v.leading_zeros();
    log2_ceil.saturating_sub(1).min(10) as u8
}

fn size_letter(payload_len: u32, direction: u8) -> u8 {
    let idx = size_bucket(payload_len);
    let base = if direction == 0 { b'A' } else { b'a' };
    base + idx
}

/// Per-direction sample state.
pub struct DirState {
    pub histogram: [u16; 256],
    pub bytes_sampled: u32,
    pub packets_sampled: u32,
}

impl Default for DirState {
    fn default() -> Self {
        Self {
            histogram: [0u16; 256],
            bytes_sampled: 0,
            packets_sampled: 0,
        }
    }
}

impl DirState {
    /// Sample up to `byte_room` bytes from `payload` into the histogram.
    /// Always increments `packets_sampled` so per-direction packet caps
    /// stay accurate even when byte room is exhausted.
    pub fn sample(&mut self, payload: &[u8], byte_room: u32) {
        if payload.is_empty() {
            return;
        }
        self.packets_sampled = self.packets_sampled.saturating_add(1);
        if byte_room == 0 {
            return;
        }
        let take = (byte_room as usize).min(payload.len());
        for &b in &payload[..take] {
            self.histogram[b as usize] = self.histogram[b as usize].saturating_add(1);
        }
        self.bytes_sampled = self.bytes_sampled.saturating_add(take as u32);
    }

    pub fn entropy_bits_per_byte(&self) -> Option<f64> {
        if self.bytes_sampled == 0 {
            return None;
        }
        Some(shannon_bits_per_byte(&self.histogram, self.bytes_sampled as u64))
    }
}

#[derive(Default)]
pub struct EntropyFlow {
    pub started: bool,
    pub to_server: DirState,
    pub to_client: DirState,
    /// Index-aligned SPLT arrays (one entry per packet, in arrival order).
    /// `splt_letters[i]`'s case carries direction; `splt_lengths[i]` is the
    /// exact payload byte count; `splt_iats_us[i]` is the µs gap from the
    /// previous packet (entry 0 is always 0).
    pub splt_letters: Vec<u8>,
    pub splt_lengths: Vec<u16>,
    pub splt_iats_us: Vec<u32>,
    /// Wall-clock µs of the most recent observed packet — used to compute
    /// the next IAT. None until the first observation.
    pub last_pkt_ts_us: Option<i64>,
}

pub struct State {
    pub cfg: PluginConfig,
    flows: HashMap<u64, EntropyFlow>,
    dropped: u64,
}

impl State {
    pub fn new(cfg: PluginConfig) -> Self {
        Self { cfg, flows: HashMap::new(), dropped: 0 }
    }

    pub fn shutdown(self) {
        crate::log_notice(&format!(
            "payload-entropy shutdown: tracked_flows={} dropped={}",
            self.flows.len(), self.dropped
        ));
    }

    pub fn observe(
        &mut self,
        flow_hash: u64,
        ts_us: i64,
        direction: u8,
        payload: *const u8,
        payload_len: u32,
    ) {
        if payload.is_null() || payload_len == 0 {
            return;
        }
        if !self.flows.contains_key(&flow_hash) {
            if self.flows.len() as u32 >= self.cfg.max_flows {
                self.dropped += 1;
                return;
            }
        }
        let max_packets = self.cfg.max_packets_per_dir;
        let max_bytes = self.cfg.max_bytes_per_dir;
        let track_splt = self.cfg.emit.splt;
        // The entropy histogram is also what `shannon_bits_per_byte` runs on
        // — track it whenever entropy emit is enabled.
        let track_hist = self.cfg.emit.entropy;

        let flow = self.flows.entry(flow_hash).or_default();
        flow.started = true;

        // Per-direction packet cap.
        let dir = if direction == 0 { &mut flow.to_server } else { &mut flow.to_client };
        if dir.packets_sampled >= max_packets {
            return;
        }

        // SPLT capture (letter, length, IAT).
        if track_splt && flow.splt_letters.len() < SPLT_MAX_LEN {
            let iat: u32 = match flow.last_pkt_ts_us {
                Some(prev) if ts_us >= prev => (ts_us - prev).min(u32::MAX as i64) as u32,
                _ => 0,
            };
            flow.splt_letters.push(size_letter(payload_len, direction));
            flow.splt_lengths.push(payload_len.min(u16::MAX as u32) as u16);
            flow.splt_iats_us.push(iat);
        }
        flow.last_pkt_ts_us = Some(ts_us);

        // Histogram + bytes_sampled (cheap; gated on entropy emit).
        // bytes_sampled is also what producer_ratio uses, so we track it
        // whenever entropy OR producer_ratio is on. histogram itself only
        // matters for entropy.
        let dir = if direction == 0 { &mut flow.to_server } else { &mut flow.to_client };
        if track_hist {
            let room = max_bytes.saturating_sub(dir.bytes_sampled);
            let payload_slice = unsafe { std::slice::from_raw_parts(payload, payload_len as usize) };
            dir.sample(payload_slice, room);
        } else if self.cfg.emit.pcr {
            // PCR only — count bytes (capped) without the histogram update.
            let take = max_bytes
                .saturating_sub(dir.bytes_sampled)
                .min(payload_len);
            dir.bytes_sampled = dir.bytes_sampled.saturating_add(take);
            dir.packets_sampled = dir.packets_sampled.saturating_add(1);
        } else {
            // Neither entropy nor producer_ratio — still bump packet count
            // so the per-direction cap drives SPLT length too.
            dir.packets_sampled = dir.packets_sampled.saturating_add(1);
        }
    }

    /// Pop the flow's accumulated state.
    pub fn take(&mut self, flow_hash: u64) -> Option<EntropyFlow> {
        self.flows.remove(&flow_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_bucket_table() {
        assert_eq!(size_bucket(2),    0); // A
        assert_eq!(size_bucket(3),    1); // B
        assert_eq!(size_bucket(4),    1); // B
        assert_eq!(size_bucket(8),    2); // C
        assert_eq!(size_bucket(2048), 10); // K
        assert_eq!(size_bucket(65535), 10); // K (clamped)
    }

    #[test]
    fn letter_case_by_direction() {
        assert_eq!(size_letter(2, 0), b'A');
        assert_eq!(size_letter(2, 1), b'a');
        assert_eq!(size_letter(2048, 0), b'K');
        assert_eq!(size_letter(2048, 1), b'k');
    }
}
