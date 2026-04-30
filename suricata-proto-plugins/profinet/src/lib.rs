// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for PROFINET DCP.
//!
//! This plugin provides:
//! - Protocol detection (probing) for PROFINET DCP over UDP port 34964
//! - DCP frame parsing (Identify, Get, Set, Hello)
//! - Per-flow state with station discovery tracking
//! - EVE JSON logging of PROFINET DCP metadata
//! - Detection keywords: profinet.service_type, profinet.frame_type, profinet.station_name
//!
//! NOTE: PROFINET RT/IRT on Layer 2 (EtherType 0x8892/0x8893) requires
//! a separate ethertype decoder. This plugin handles the UDP DCP variant.
//!
//! ## Architecture
//!
//! ```text
//! profinet.rs  — Pure Rust PROFINET DCP protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod logger;
pub mod profinet;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::ProfinetState;

// ============================================================================
// FFI Constants
// ============================================================================

const APP_LAYER_OK: c_int = 0;
const APP_LAYER_ERROR: c_int = -1;

// ============================================================================
// External C functions (defined in applayer.c)
// ============================================================================

extern "C" {
    fn profinet_log_notice(msg: *const c_char);
    fn profinet_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { profinet_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { profinet_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a UDP payload for PROFINET DCP.
#[no_mangle]
pub unsafe extern "C" fn rs_profinet_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 12 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if profinet::probe_profinet(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

#[no_mangle]
pub extern "C" fn rs_profinet_state_new() -> *mut c_void {
    let state = Box::new(ProfinetState::new());
    Box::into_raw(state) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut ProfinetState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 12 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut ProfinetState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("PROFINET parse error: {}", e));
            }
            APP_LAYER_ERROR
        }
    }
}

// ============================================================================
// Transaction Access
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const ProfinetState);
    state.tx_count() as u64
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const ProfinetState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut ProfinetState);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
    state.free_logged_transactions();
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_set_logged(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut ProfinetState);
    state.set_logged(tx_index);
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_state_gc(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut ProfinetState);
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::ProfinetTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_profinet_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Get the DCP service type raw value.
#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_get_service_type(tx: *const c_void) -> c_int {
    if tx.is_null() { return -1; }
    let tx = &*(tx as *const state::ProfinetTransaction);
    tx.message.service_id_raw as c_int
}

/// Get the frame ID.
#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_get_frame_id(tx: *const c_void) -> c_int {
    if tx.is_null() { return -1; }
    let tx = &*(tx as *const state::ProfinetTransaction);
    tx.message.frame_id as c_int
}

/// Check if a transaction is a Set operation (security relevant).
#[no_mangle]
pub unsafe extern "C" fn rs_profinet_tx_is_security_relevant(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::ProfinetTransaction);
    if tx.detect_flags.is_security_relevant { 1 } else { 0 }
}
