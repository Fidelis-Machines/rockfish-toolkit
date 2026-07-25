// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Per-flow UDP performance tracker.
//!
//! Pairs request/response packets within a configurable time window to
//! compute round-trip time, and tracks inter-arrival jitter using
//! Welford-style running statistics.

#[derive(Debug, Default, Clone)]
pub struct UdpDirState {
    pub packets: u64,
    pub bytes: u64,
    pub last_ts_us: i64,

    /// Inter-arrival statistics (microseconds).
    pub iat_count: u64,
    pub iat_min_us: i64,
    pub iat_max_us: i64,
    pub iat_sum_us: i64,
    /// Welford running variance components.
    pub iat_mean: f64,
    pub iat_m2: f64,
    /// Timestamp (µs) of the first packet in this direction (UDP packets
    /// always carry payload, so this is also the first-byte time). 0 until
    /// the first packet is observed.
    pub first_payload_ts_us: i64,
}

impl UdpDirState {
    pub fn observe(&mut self, ts_us: i64, payload_len: u32) {
        self.packets += 1;
        self.bytes += payload_len as u64;
        if self.first_payload_ts_us == 0 {
            self.first_payload_ts_us = ts_us;
        }

        if self.last_ts_us != 0 {
            let dt = ts_us - self.last_ts_us;
            if dt > 0 {
                if self.iat_count == 0 {
                    self.iat_min_us = dt;
                    self.iat_max_us = dt;
                } else {
                    if dt < self.iat_min_us { self.iat_min_us = dt; }
                    if dt > self.iat_max_us { self.iat_max_us = dt; }
                }
                self.iat_sum_us += dt;
                self.iat_count += 1;
                let dtf = dt as f64;
                let n = self.iat_count as f64;
                let delta = dtf - self.iat_mean;
                self.iat_mean += delta / n;
                self.iat_m2 += delta * (dtf - self.iat_mean);
            }
        }
        self.last_ts_us = ts_us;
    }

    pub fn iat_avg_us(&self) -> Option<f64> {
        if self.iat_count == 0 { None } else { Some(self.iat_mean) }
    }

    pub fn iat_stddev_us(&self) -> Option<f64> {
        if self.iat_count < 2 { None }
        else { Some((self.iat_m2 / (self.iat_count as f64 - 1.0)).sqrt()) }
    }
}

#[derive(Debug, Default, Clone)]
pub struct UdpFlow {
    pub first_ts_us: i64,
    pub last_ts_us: i64,

    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,

    pub to_server: UdpDirState,
    pub to_client: UdpDirState,

    /// Pending request timestamps (most recent only) for RTT pairing.
    pending_req_ts_us: Option<i64>,

    /// Paired RTT samples (microseconds).
    pub rtt_count: u64,
    pub rtt_min_us: i64,
    pub rtt_max_us: i64,
    pub rtt_sum_us: i64,
    /// Welford running variance for RTT.
    pub rtt_mean: f64,
    pub rtt_m2: f64,
}

impl UdpFlow {
    pub fn observe(
        &mut self,
        ts_us: i64,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        direction: u8,
        payload_len: u32,
        rtt_window_us: i64,
    ) {
        if self.first_ts_us == 0 {
            self.first_ts_us = ts_us;
            self.src_ip = src_ip.to_string();
            self.dst_ip = dst_ip.to_string();
            self.src_port = src_port;
            self.dst_port = dst_port;
        }
        self.last_ts_us = ts_us;

        match direction {
            0 => {
                self.to_server.observe(ts_us, payload_len);
                self.pending_req_ts_us = Some(ts_us);
            }
            _ => {
                self.to_client.observe(ts_us, payload_len);
                if let Some(req_ts) = self.pending_req_ts_us.take() {
                    let dt = ts_us - req_ts;
                    if dt >= 0 && dt <= rtt_window_us {
                        if self.rtt_count == 0 {
                            self.rtt_min_us = dt;
                            self.rtt_max_us = dt;
                        } else {
                            if dt < self.rtt_min_us { self.rtt_min_us = dt; }
                            if dt > self.rtt_max_us { self.rtt_max_us = dt; }
                        }
                        self.rtt_sum_us += dt;
                        self.rtt_count += 1;
                        let dtf = dt as f64;
                        let n = self.rtt_count as f64;
                        let delta = dtf - self.rtt_mean;
                        self.rtt_mean += delta / n;
                        self.rtt_m2 += delta * (dtf - self.rtt_mean);
                    }
                }
            }
        }
    }
}
