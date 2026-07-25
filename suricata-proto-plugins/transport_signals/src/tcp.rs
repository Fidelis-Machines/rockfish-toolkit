// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Per-flow TCP performance tracker.

/// TCP flag bits, matching standard wire ordering.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
#[allow(dead_code)] pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Per-direction TCP state.
#[derive(Debug, Default, Clone)]
pub struct TcpDirState {
    /// Highest seq+payload seen (next expected). Used for retransmit detection.
    pub max_seq_end: u32,
    /// Whether we've seen any data packets (with payload) in this direction.
    pub seen_data: bool,
    /// Counters.
    pub packets: u64,
    pub bytes: u64,
    pub retransmits: u64,
    pub out_of_order: u64,
    pub zero_window: u64,
    pub rst_count: u64,
    pub fin_count: u64,
    /// Window stats (in raw packet field units; scale unknown to plugin).
    pub min_window: u32,
    pub max_window: u32,
    pub window_sum: u64,
    pub window_samples: u64,
    /// Timestamp (µs) of the first packet carrying any payload in this direction.
    /// Stays at 0 until a payload-bearing packet is observed.
    pub first_payload_ts_us: i64,
}

impl TcpDirState {
    pub fn observe(&mut self, ts_us: i64, flags: u8, seq: u32, window: u16, payload_len: u32) {
        self.packets += 1;
        self.bytes += payload_len as u64;
        if payload_len > 0 && self.first_payload_ts_us == 0 {
            self.first_payload_ts_us = ts_us;
        }

        let seq_end = seq.wrapping_add(payload_len);

        if (flags & TCP_RST) != 0 {
            self.rst_count += 1;
        }
        if (flags & TCP_FIN) != 0 {
            self.fin_count += 1;
        }

        if window == 0 && (flags & TCP_RST) == 0 {
            self.zero_window += 1;
        }
        let w32 = window as u32;
        if self.window_samples == 0 {
            self.min_window = w32;
            self.max_window = w32;
        } else {
            if w32 < self.min_window { self.min_window = w32; }
            if w32 > self.max_window { self.max_window = w32; }
        }
        self.window_sum += w32 as u64;
        self.window_samples += 1;

        if payload_len > 0 {
            if self.seen_data {
                /* seq compared modulo 2^32 — wrapping difference. */
                let diff = seq_end.wrapping_sub(self.max_seq_end) as i32;
                if diff <= 0 {
                    /* Re-sent a region we'd already covered. */
                    self.retransmits += 1;
                } else if seq.wrapping_sub(self.max_seq_end) as i32 > 0 {
                    /* Forward jump beyond current max — gap means out-of-order. */
                    self.out_of_order += 1;
                    self.max_seq_end = seq_end;
                } else {
                    self.max_seq_end = seq_end;
                }
            } else {
                self.max_seq_end = seq_end;
                self.seen_data = true;
            }
        }
    }
}

/// Per-flow TCP state.
#[derive(Debug, Default, Clone)]
pub struct TcpFlow {
    pub first_ts_us: i64,
    pub last_ts_us: i64,

    /// 5-tuple snapshot from the first packet (client side).
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,

    pub to_server: TcpDirState,
    pub to_client: TcpDirState,

    /// Handshake RTT in microseconds. None until both SYN and SYN/ACK seen.
    pub handshake_rtt_us: Option<i64>,
    syn_ts_us: Option<i64>,
    synack_ts_us: Option<i64>,

    pub flow_terminated_by_rst: bool,
    pub flow_terminated_by_fin: bool,
}

impl TcpFlow {
    pub fn observe(
        &mut self,
        ts_us: i64,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        direction: u8,
        flags: u8,
        seq: u32,
        _ack: u32,
        window: u16,
        payload_len: u32,
    ) {
        if self.first_ts_us == 0 {
            self.first_ts_us = ts_us;
            self.src_ip = src_ip.to_string();
            self.dst_ip = dst_ip.to_string();
            self.src_port = src_port;
            self.dst_port = dst_port;
        }
        self.last_ts_us = ts_us;

        // Handshake RTT: SYN (client→server) then SYN/ACK (server→client).
        if (flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0 && self.syn_ts_us.is_none() {
            self.syn_ts_us = Some(ts_us);
        }
        if (flags & TCP_SYN) != 0 && (flags & TCP_ACK) != 0 && self.synack_ts_us.is_none() {
            self.synack_ts_us = Some(ts_us);
            if let Some(syn) = self.syn_ts_us {
                let rtt = ts_us - syn;
                if rtt >= 0 {
                    self.handshake_rtt_us = Some(rtt);
                }
            }
        }

        if (flags & TCP_RST) != 0 {
            self.flow_terminated_by_rst = true;
        }
        if (flags & TCP_FIN) != 0 {
            self.flow_terminated_by_fin = true;
        }

        match direction {
            0 => self.to_server.observe(ts_us, flags, seq, window, payload_len),
            _ => self.to_client.observe(ts_us, flags, seq, window, payload_len),
        }
    }
}

