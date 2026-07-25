// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Rockfish Suricata TLS PQC plugin (Rust side).
//!
//! Detects post-quantum key-exchange usage in TLS handshakes per NIST IR
//! 8547. Emits one `pqc` eve event per TLS-bearing flow with:
//!
//!   * `client_offered_pqc`     — did ClientHello supported_groups include
//!                                a NIST-finalized or pre-standard PQ KEM?
//!   * `server_chosen_group`    — TLS 1.3 ServerHello key_share NamedGroup
//!                                (null for TLS 1.2 — see README for why)
//!   * `server_chosen_group_name` — human-readable codepoint name
//!   * `nist_compliant`         — server actually negotiated a PQ KEM
//!   * `exposure_class`         — `"compliant" | "server_lagging" |
//!                                 "client_lagging" | "partial" | "unknown"`
//!
//! The plugin extracts data Suricata's stock TLS event does not surface —
//! Suricata parses the ClientHello supported_groups only to build JA3 then
//! frees the list, and it does not parse the ServerHello key_share at all
//! (verified against `app-layer-ssl.c` as of Suricata 7.0).

mod config;
mod groups;
mod parser;
mod state;

use std::ffi::{c_char, c_int, CStr};

use crate::config::PluginConfig;
use crate::state::{server_group_name, verdict_for, State};

extern "C" {
    fn pqc_log_notice(msg: *const c_char);
    fn pqc_log_error(msg: *const c_char);
}

pub(crate) fn log_notice(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        unsafe { pqc_log_notice(c.as_ptr()) }
    }
}
pub(crate) fn log_error(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        unsafe { pqc_log_error(c.as_ptr()) }
    }
}

static STATE: parking_lot::Mutex<Option<State>> = parking_lot::Mutex::new(None);

#[no_mangle]
pub extern "C" fn rs_pqc_init(config_json: *const c_char) -> c_int {
    if config_json.is_null() {
        log_error("rs_pqc_init called with null config_json");
        return 1;
    }
    let cfg_str = unsafe { CStr::from_ptr(config_json) };
    let cfg_str = match cfg_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error(&format!("rs_pqc_init: config not utf-8: {e}"));
            return 1;
        }
    };
    let cfg: PluginConfig = match serde_json::from_str(cfg_str) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!("rs_pqc_init: config parse error: {e}"));
            return 1;
        }
    };
    *STATE.lock() = Some(State::new(cfg));
    log_notice("tls-pqc state initialized");
    0
}

#[no_mangle]
pub extern "C" fn rs_pqc_deinit() {
    if let Some(state) = STATE.lock().take() {
        state.shutdown();
    }
    log_notice("tls-pqc state torn down");
}

/// Per-packet observation. `direction` 0 = to-server, 1 = to-client.
/// `payload` is the TCP payload (post-IP/TCP headers).
#[no_mangle]
pub extern "C" fn rs_pqc_observe(
    flow_hash: u64,
    direction: u8,
    payload: *const u8,
    payload_len: u32,
) -> c_int {
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else { return 1; };
    s.observe(flow_hash, direction, payload, payload_len);
    0
}

// ─── Stats export FFI ──────────────────────────────────────────────────

const PQC_FALSE: u8 = 0;
const PQC_TRUE: u8 = 1;

/// Hardcap on how many client_supported_groups codepoints we copy out to
/// the C side. The handshake permits up to ~32K codepoints; in practice
/// clients send 4-12. 32 is more than enough for the eve log.
pub const PQC_MAX_GROUPS: usize = 32;

#[repr(C)]
pub struct PqcStats {
    /// 0 if the flow had no observations; 1 otherwise.
    pub valid: u8,

    /// Did the ClientHello offer at least one PQ codepoint?
    pub client_offered_pqc: u8,
    /// Did the server choose a PQ codepoint? (TLS 1.3 only)
    pub server_chosen_pqc: u8,
    /// NIST IR 8547 compliance verdict (server actually negotiated PQ).
    pub nist_compliant: u8,

    /// Client-side data presence flags.
    pub has_client_groups: u8,
    pub has_server_chosen: u8,
    pub has_tls_version: u8,

    /// The chosen NamedGroup codepoint when has_server_chosen=1.
    pub server_chosen_group: u16,
    /// Negotiated TLS version in network byte order (0x0303, 0x0304).
    pub tls_version_be: u16,

    /// Null-terminated 11-char exposure class label
    /// ("compliant", "server_lagging", "client_lagging", "partial", "unknown").
    pub exposure_class: [u8; 16],

    /// Null-terminated server-chosen group name (e.g. "X25519MLKEM768"),
    /// or empty when has_server_chosen=0.
    pub server_chosen_group_name: [u8; 32],

    /// Number of populated entries in client_supported_groups.
    pub client_groups_len: u16,
    /// First N codepoints from the ClientHello supported_groups list.
    pub client_supported_groups: [u16; PQC_MAX_GROUPS],
}

#[no_mangle]
pub extern "C" fn rs_pqc_take_stats(flow_hash: u64, out: *mut PqcStats) -> u8 {
    if out.is_null() {
        return PQC_FALSE;
    }
    let mut guard = STATE.lock();
    let Some(s) = guard.as_mut() else { return PQC_FALSE; };
    let Some(flow) = s.take(flow_hash) else { return PQC_FALSE; };

    if flow.client_supported_groups.is_none()
        && flow.server_chosen_group.is_none()
        && flow.negotiated_version.is_none()
    {
        return PQC_FALSE;
    }

    let v = verdict_for(&flow);

    unsafe {
        let r = &mut *out;
        r.valid = PQC_TRUE;

        r.client_offered_pqc = v.client_offered_pqc as u8;
        r.server_chosen_pqc = v.server_chosen_class.is_pq() as u8;
        r.nist_compliant = v.nist_compliant as u8;

        r.has_client_groups = flow.client_supported_groups.is_some() as u8;
        r.has_server_chosen = flow.server_chosen_group.is_some() as u8;
        r.has_tls_version = flow.negotiated_version.is_some() as u8;

        r.server_chosen_group = flow.server_chosen_group.unwrap_or(0);
        r.tls_version_be = flow.negotiated_version.unwrap_or(0);

        r.exposure_class = [0u8; 16];
        copy_cstr(&mut r.exposure_class, v.exposure.as_str());

        r.server_chosen_group_name = [0u8; 32];
        if let Some(name) = server_group_name(&v) {
            copy_cstr(&mut r.server_chosen_group_name, name);
        }

        r.client_groups_len = 0;
        r.client_supported_groups = [0u16; PQC_MAX_GROUPS];
        if let Some(ref groups) = flow.client_supported_groups {
            let n = groups.len().min(PQC_MAX_GROUPS);
            r.client_groups_len = n as u16;
            r.client_supported_groups[..n].copy_from_slice(&groups[..n]);
        }
    }
    PQC_TRUE
}

fn copy_cstr(dst: &mut [u8], src: &str) {
    let take = src.len().min(dst.len().saturating_sub(1));
    dst[..take].copy_from_slice(&src.as_bytes()[..take]);
    if take < dst.len() {
        dst[take] = 0;
    }
}
