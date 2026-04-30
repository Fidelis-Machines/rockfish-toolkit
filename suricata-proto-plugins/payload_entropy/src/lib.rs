// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Rockfish Suricata Payload Entropy plugin (Rust side).
//!
//! Three signals per flow, each toggleable:
//!   1. Shannon byte entropy (bits/byte) per direction
//!   2. PCR (producer/consumer ratio) over the same sampled byte window
//!   3. SPLT (Sequence of Packet Lengths and Times) — three index-aligned
//!      views: `splt_lengths` (u16), `splt_iats_us` (u32), `splt` (letter
//!      string with case = direction).

mod config;
mod entropy;
mod state;

use std::ffi::{c_char, c_int, CStr};

use crate::config::PluginConfig;
use crate::state::{State, SPLT_MAX_LEN};

extern "C" {
    fn pe_log_notice(msg: *const c_char);
    fn pe_log_error(msg: *const c_char);
}

fn log_notice(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        unsafe { pe_log_notice(c.as_ptr()) }
    }
}
fn log_error(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        unsafe { pe_log_error(c.as_ptr()) }
    }
}

static STATE: parking_lot::Mutex<Option<State>> = parking_lot::Mutex::new(None);

#[no_mangle]
pub extern "C" fn rs_pe_init(config_json: *const c_char) -> c_int {
    if config_json.is_null() {
        log_error("rs_pe_init called with null config_json");
        return 1;
    }
    let cfg_str = unsafe { CStr::from_ptr(config_json) };
    let cfg_str = match cfg_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error(&format!("rs_pe_init: config not utf-8: {e}"));
            return 1;
        }
    };
    let cfg: PluginConfig = match serde_json::from_str(cfg_str) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!("rs_pe_init: config parse error: {e}"));
            return 1;
        }
    };
    *STATE.lock() = Some(State::new(cfg));
    log_notice("payload-entropy state initialized");
    0
}

#[no_mangle]
pub extern "C" fn rs_pe_deinit() {
    if let Some(state) = STATE.lock().take() {
        state.shutdown();
    }
    log_notice("payload-entropy state torn down");
}

/// Per-packet observation. `direction` 0 = to-server, 1 = to-client.
/// `ts_us` is the packet timestamp in microseconds since the epoch.
#[no_mangle]
pub extern "C" fn rs_pe_observe(
    flow_hash: u64,
    ts_us: i64,
    direction: u8,
    payload: *const u8,
    payload_len: u32,
) -> c_int {
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else { return 1; };
    s.observe(flow_hash, ts_us, direction, payload, payload_len);
    0
}

// ─── Stats export FFI ──────────────────────────────────────────────────

const PE_FALSE: u8 = 0;
const PE_TRUE: u8 = 1;

#[repr(C)]
pub struct PeStats {
    /// 0 if the flow had no observations; 1 otherwise.
    pub valid: u8,

    /// Snapshotted emit toggles — the C side uses these to gate the JSON
    /// fields per record (so the user can flip a knob without recompiling).
    pub emit_entropy: u8,
    pub emit_pcr: u8,
    pub emit_splt: u8,

    /// Shannon entropy + bytes_sampled per direction. `bytes_sampled` is
    /// always populated (it's needed by producer_ratio too).
    pub has_entropy_to_server: u8,
    pub has_entropy_to_client: u8,
    pub entropy_to_server: f64,
    pub entropy_to_client: f64,
    pub bytes_sampled_to_server: u32,
    pub bytes_sampled_to_client: u32,

    /// PCR (producer/consumer ratio) over sampled bytes. Same window as entropy.
    pub has_pcr: u8,
    pub pcr: f64,

    /// SPLT — index-aligned arrays. `splt_len` is the populated length of
    /// each. `splt_letters` is ASCII (A–K toserver, a–k toclient).
    pub splt_len: u8,
    pub splt_letters: [u8; SPLT_MAX_LEN],
    pub splt_lengths: [u16; SPLT_MAX_LEN],
    pub splt_iats_us: [u32; SPLT_MAX_LEN],
}

#[no_mangle]
pub extern "C" fn rs_pe_take_stats(flow_hash: u64, out: *mut PeStats) -> u8 {
    if out.is_null() { return PE_FALSE; }
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else { return PE_FALSE; };
    let cfg_emit = s.cfg.emit.clone();
    let Some(flow) = s.take(flow_hash) else { return PE_FALSE; };
    if !flow.started {
        return PE_FALSE;
    }
    let h_ts = flow.to_server.entropy_bits_per_byte();
    let h_tc = flow.to_client.entropy_bits_per_byte();
    let bs_ts = flow.to_server.bytes_sampled;
    let bs_tc = flow.to_client.bytes_sampled;
    let splt_n = flow.splt_letters.len();

    if h_ts.is_none() && h_tc.is_none() && bs_ts == 0 && bs_tc == 0 && splt_n == 0 {
        return PE_FALSE;
    }

    unsafe {
        let r = &mut *out;
        r.valid = PE_TRUE;

        r.emit_entropy = cfg_emit.entropy as u8;
        r.emit_pcr     = cfg_emit.pcr as u8;
        r.emit_splt    = cfg_emit.splt as u8;

        r.has_entropy_to_server = h_ts.is_some() as u8;
        r.has_entropy_to_client = h_tc.is_some() as u8;
        r.entropy_to_server = h_ts.unwrap_or(0.0);
        r.entropy_to_client = h_tc.unwrap_or(0.0);
        r.bytes_sampled_to_server = bs_ts;
        r.bytes_sampled_to_client = bs_tc;

        let combined = bs_ts as u64 + bs_tc as u64;
        if combined > 0 {
            r.has_pcr = PE_TRUE;
            r.pcr = bs_ts as f64 / combined as f64;
        }

        let n = splt_n.min(SPLT_MAX_LEN);
        r.splt_len = n as u8;
        r.splt_letters[..n].copy_from_slice(&flow.splt_letters[..n]);
        r.splt_lengths[..n].copy_from_slice(&flow.splt_lengths[..n]);
        r.splt_iats_us[..n].copy_from_slice(&flow.splt_iats_us[..n]);
    }
    PE_TRUE
}
