// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Rockfish Suricata Transport Performance plugin (Rust side).
//!
//! Maintains per-flow TCP/UDP state and computes derived metrics
//! (handshake RTT, retransmits, zero-windows, UDP request/response RTT,
//! jitter). Stats are popped on flow termination via `rs_tp_take_tcp_stats`
//! / `rs_tp_take_udp_stats`; the C side renders them into Suricata's eve
//! JsonBuilder so events flow through the normal eve-log pipeline.

mod config;
mod state;
mod tcp;
mod udp;

use std::ffi::{c_char, c_int, CStr};

use crate::config::PluginConfig;
use crate::state::{State, ADDR_BUF};

extern "C" {
    fn tp_log_notice(msg: *const c_char);
    fn tp_log_error(msg: *const c_char);
}

fn log_notice(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        unsafe { tp_log_notice(c.as_ptr()) }
    }
}
fn log_error(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        unsafe { tp_log_error(c.as_ptr()) }
    }
}

/// Singleton state. Initialized by `rs_tp_init`, torn down by `rs_tp_deinit`.
static STATE: parking_lot::Mutex<Option<State>> = parking_lot::Mutex::new(None);

#[no_mangle]
pub extern "C" fn rs_tp_init(config_json: *const c_char) -> c_int {
    if config_json.is_null() {
        log_error("rs_tp_init called with null config_json");
        return 1;
    }
    let cfg_str = unsafe { CStr::from_ptr(config_json) };
    let cfg_str = match cfg_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error(&format!("rs_tp_init: config not utf-8: {e}"));
            return 1;
        }
    };
    let cfg: PluginConfig = match serde_json::from_str(cfg_str) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!("rs_tp_init: config parse error: {e}"));
            return 1;
        }
    };
    *STATE.lock() = Some(State::new(cfg));
    log_notice("transport-perf state initialized");
    0
}

#[no_mangle]
pub extern "C" fn rs_tp_deinit() {
    if let Some(state) = STATE.lock().take() {
        state.shutdown();
    }
    log_notice("transport-perf state torn down");
}

fn copy_addr(src: *const u8, len: u32) -> [u8; ADDR_BUF] {
    let mut out = [0u8; ADDR_BUF];
    if src.is_null() || len == 0 {
        return out;
    }
    let n = (len as usize).min(ADDR_BUF - 1);
    unsafe { std::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), n) };
    out
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn rs_tp_observe_tcp(
    flow_hash: u64,
    ts_us: i64,
    src_ip: *const u8,
    src_ip_len: u32,
    dst_ip: *const u8,
    dst_ip_len: u32,
    src_port: u16,
    dst_port: u16,
    direction: u8,
    tcp_flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    wscale: u8,
    payload_len: u32,
) -> c_int {
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else {
        return 1;
    };
    if !s.cfg.tcp_enabled {
        return 0;
    }
    let src = copy_addr(src_ip, src_ip_len);
    let dst = copy_addr(dst_ip, dst_ip_len);
    s.observe_tcp(
        flow_hash, ts_us, src, dst, src_port, dst_port, direction,
        tcp_flags, seq, ack, window, wscale, payload_len,
    );
    0
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn rs_tp_observe_udp(
    flow_hash: u64,
    ts_us: i64,
    src_ip: *const u8,
    src_ip_len: u32,
    dst_ip: *const u8,
    dst_ip_len: u32,
    src_port: u16,
    dst_port: u16,
    direction: u8,
    payload_len: u32,
) -> c_int {
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else {
        return 1;
    };
    if !s.cfg.udp_enabled {
        return 0;
    }
    let src = copy_addr(src_ip, src_ip_len);
    let dst = copy_addr(dst_ip, dst_ip_len);
    s.observe_udp(
        flow_hash, ts_us, src, dst, src_port, dst_port, direction, payload_len,
    );
    0
}

// ─── Stats export FFI ──────────────────────────────────────────────────
//
// Each stats struct mirrors a C struct of identical layout. The C side
// (output.c) declares matching definitions and reads the populated struct
// to build the Suricata JsonBuilder. `bool` is represented as `u8`
// (0 = false, 1 = true) for portable C ABI.

const TP_BOOL_FALSE: u8 = 0;
const TP_BOOL_TRUE: u8 = 1;

#[repr(C)]
pub struct TpTcpStats {
    /// Whether to emit any field at all (false → C side skips the event).
    pub valid: u8,
    pub start_us: i64,
    pub end_us: i64,
    pub duration_us: i64,
    /// has_handshake_rtt = 1 → handshake_rtt_us is meaningful.
    pub has_handshake_rtt: u8,
    pub handshake_rtt_us: i64,
    /// Time-to-first-payload-byte per direction (µs from flow start).
    /// has_first_byte_* = 0 → field is meaningless (no payload observed).
    pub has_first_byte_ts: u8,
    pub has_first_byte_tc: u8,
    pub first_byte_toserver_us: i64,
    pub first_byte_toclient_us: i64,
    pub retransmits_toserver: u64,
    pub retransmits_toclient: u64,
    pub out_of_order_toserver: u64,
    pub out_of_order_toclient: u64,
    pub zero_window_toserver: u64,
    pub zero_window_toclient: u64,
    pub rst_count: u64,
    pub fin_count: u64,
    pub has_window_stats_ts: u8,
    pub has_window_stats_tc: u8,
    pub avg_window_toserver: u32,
    pub min_window_toserver: u32,
    pub max_window_toserver: u32,
    pub avg_window_toclient: u32,
    pub min_window_toclient: u32,
    pub max_window_toclient: u32,
    /// Null-terminated, fits "fin"/"rst"/"timeout".
    pub close_reason: [u8; 16],
    /// Emit toggles snapshotted from config so C side doesn't need to
    /// re-check (and so the toggle takes effect at flow flush, not flow
    /// start).
    pub emit_handshake_rtt: u8,
    pub emit_retransmits: u8,
    pub emit_zero_window: u8,
    pub emit_window_stats: u8,
}

#[repr(C)]
pub struct TpUdpStats {
    pub valid: u8,
    pub start_us: i64,
    pub end_us: i64,
    pub duration_us: i64,
    pub has_first_byte_ts: u8,
    pub has_first_byte_tc: u8,
    pub first_byte_toserver_us: i64,
    pub first_byte_toclient_us: i64,
    pub has_rtt: u8,
    pub rtt_count: u64,
    pub rtt_min_us: i64,
    pub rtt_max_us: i64,
    pub rtt_avg_us: f64,
    pub has_rtt_stddev: u8,
    pub rtt_stddev_us: f64,
    pub has_iat_ts: u8,
    pub iat_avg_toserver_us: f64,
    pub has_iat_tc: u8,
    pub iat_avg_toclient_us: f64,
    pub has_iat_stddev_ts: u8,
    pub iat_stddev_toserver_us: f64,
    pub has_iat_stddev_tc: u8,
    pub iat_stddev_toclient_us: f64,
    pub emit_udp_rtt: u8,
    pub emit_udp_jitter: u8,
}

fn copy_close_reason(src: &str, dst: &mut [u8; 16]) {
    let bytes = src.as_bytes();
    let n = bytes.len().min(15);
    dst[..n].copy_from_slice(&bytes[..n]);
    dst[n] = 0;
}

/// Pop the TCP flow stats by flow hash. Returns 1 if a flow existed and
/// `out` was populated, 0 if no state was tracked for this flow.
#[no_mangle]
pub extern "C" fn rs_tp_take_tcp_stats(flow_hash: u64, out: *mut TpTcpStats) -> u8 {
    if out.is_null() { return TP_BOOL_FALSE; }
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else { return TP_BOOL_FALSE; };
    let Some(flow) = s.take_tcp(flow_hash) else { return TP_BOOL_FALSE; };
    if flow.first_ts_us == 0 {
        // Flow tracked but never observed a packet — drop silently.
        return TP_BOOL_FALSE;
    }
    let cfg = &s.cfg;
    unsafe {
        let r = &mut *out;
        r.valid           = TP_BOOL_TRUE;
        r.start_us        = flow.first_ts_us;
        r.end_us          = flow.last_ts_us;
        r.duration_us     = flow.last_ts_us - flow.first_ts_us;
        r.has_handshake_rtt = flow.handshake_rtt_us.is_some() as u8;
        r.handshake_rtt_us = flow.handshake_rtt_us.unwrap_or(0);

        // Time-to-first-byte per direction, relative to flow start.
        if flow.to_server.first_payload_ts_us > 0 {
            r.has_first_byte_ts = TP_BOOL_TRUE;
            r.first_byte_toserver_us =
                flow.to_server.first_payload_ts_us - flow.first_ts_us;
        }
        if flow.to_client.first_payload_ts_us > 0 {
            r.has_first_byte_tc = TP_BOOL_TRUE;
            r.first_byte_toclient_us =
                flow.to_client.first_payload_ts_us - flow.first_ts_us;
        }

        r.retransmits_toserver = flow.to_server.retransmits;
        r.retransmits_toclient = flow.to_client.retransmits;
        r.out_of_order_toserver = flow.to_server.out_of_order;
        r.out_of_order_toclient = flow.to_client.out_of_order;
        r.zero_window_toserver = flow.to_server.zero_window;
        r.zero_window_toclient = flow.to_client.zero_window;
        r.rst_count       = flow.to_server.rst_count + flow.to_client.rst_count;
        r.fin_count       = flow.to_server.fin_count + flow.to_client.fin_count;
        r.has_window_stats_ts = (flow.to_server.window_samples > 0) as u8;
        r.has_window_stats_tc = (flow.to_client.window_samples > 0) as u8;
        if flow.to_server.window_samples > 0 {
            r.avg_window_toserver = (flow.to_server.window_sum
                / flow.to_server.window_samples) as u32;
            r.min_window_toserver = flow.to_server.min_window;
            r.max_window_toserver = flow.to_server.max_window;
        }
        if flow.to_client.window_samples > 0 {
            r.avg_window_toclient = (flow.to_client.window_sum
                / flow.to_client.window_samples) as u32;
            r.min_window_toclient = flow.to_client.min_window;
            r.max_window_toclient = flow.to_client.max_window;
        }
        let reason = if flow.flow_terminated_by_rst { "rst" }
                     else if flow.flow_terminated_by_fin { "fin" }
                     else { "timeout" };
        copy_close_reason(reason, &mut r.close_reason);
        r.emit_handshake_rtt = cfg.emit_handshake_rtt as u8;
        r.emit_retransmits   = cfg.emit_retransmits as u8;
        r.emit_zero_window   = cfg.emit_zero_window as u8;
        r.emit_window_stats  = cfg.emit_window_stats as u8;
    }
    TP_BOOL_TRUE
}

/// Pop the UDP flow stats by flow hash.
#[no_mangle]
pub extern "C" fn rs_tp_take_udp_stats(flow_hash: u64, out: *mut TpUdpStats) -> u8 {
    if out.is_null() { return TP_BOOL_FALSE; }
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else { return TP_BOOL_FALSE; };
    let Some(flow) = s.take_udp(flow_hash) else { return TP_BOOL_FALSE; };
    if flow.first_ts_us == 0 {
        return TP_BOOL_FALSE;
    }
    let cfg = &s.cfg;
    unsafe {
        let r = &mut *out;
        r.valid          = TP_BOOL_TRUE;
        r.start_us       = flow.first_ts_us;
        r.end_us         = flow.last_ts_us;
        r.duration_us    = flow.last_ts_us - flow.first_ts_us;
        if flow.to_server.first_payload_ts_us > 0 {
            r.has_first_byte_ts = TP_BOOL_TRUE;
            r.first_byte_toserver_us =
                flow.to_server.first_payload_ts_us - flow.first_ts_us;
        }
        if flow.to_client.first_payload_ts_us > 0 {
            r.has_first_byte_tc = TP_BOOL_TRUE;
            r.first_byte_toclient_us =
                flow.to_client.first_payload_ts_us - flow.first_ts_us;
        }
        r.has_rtt        = (flow.rtt_count > 0) as u8;
        if flow.rtt_count > 0 {
            r.rtt_count   = flow.rtt_count;
            r.rtt_min_us  = flow.rtt_min_us;
            r.rtt_max_us  = flow.rtt_max_us;
            r.rtt_avg_us  = flow.rtt_mean;
            if flow.rtt_count >= 2 {
                let var = flow.rtt_m2 / (flow.rtt_count as f64 - 1.0);
                r.has_rtt_stddev = TP_BOOL_TRUE;
                r.rtt_stddev_us  = var.sqrt();
            }
        }
        if let Some(v) = flow.to_server.iat_avg_us() {
            r.has_iat_ts = TP_BOOL_TRUE;
            r.iat_avg_toserver_us = v;
        }
        if let Some(v) = flow.to_client.iat_avg_us() {
            r.has_iat_tc = TP_BOOL_TRUE;
            r.iat_avg_toclient_us = v;
        }
        if let Some(v) = flow.to_server.iat_stddev_us() {
            r.has_iat_stddev_ts = TP_BOOL_TRUE;
            r.iat_stddev_toserver_us = v;
        }
        if let Some(v) = flow.to_client.iat_stddev_us() {
            r.has_iat_stddev_tc = TP_BOOL_TRUE;
            r.iat_stddev_toclient_us = v;
        }
        r.emit_udp_rtt    = cfg.emit_udp_rtt as u8;
        r.emit_udp_jitter = cfg.emit_udp_jitter as u8;
    }
    TP_BOOL_TRUE
}
