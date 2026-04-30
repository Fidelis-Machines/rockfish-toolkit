// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for CoAP.
//!
//! This plugin provides:
//! - Protocol detection (probing) for CoAP over UDP ports 5683/5684
//! - Full CoAP message parsing (header, options, payload)
//! - Per-flow state with transaction management
//! - EVE JSON logging of CoAP metadata
//! - Detection keywords: coap.method, coap.uri_path, coap.code_class
//!
//! ## Architecture
//!
//! ```text
//! coap.rs      — Pure Rust CoAP wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod coap;
pub mod logger;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::CoapState;

// ============================================================================
// FFI Constants
// ============================================================================

const APP_LAYER_OK: c_int = 0;
const APP_LAYER_ERROR: c_int = -1;

// ============================================================================
// External C functions (defined in applayer.c)
// ============================================================================

extern "C" {
    fn coap_log_notice(msg: *const c_char);
    fn coap_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { coap_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { coap_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a UDP payload for CoAP.
#[no_mangle]
pub unsafe extern "C" fn rs_coap_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 4 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if coap::probe_coap(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

#[no_mangle]
pub extern "C" fn rs_coap_state_new() -> *mut c_void {
    let state = Box::new(CoapState::new());
    Box::into_raw(state) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut CoapState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn rs_coap_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 4 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut CoapState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("CoAP parse error: {}", e));
            }
            APP_LAYER_ERROR
        }
    }
}

// ============================================================================
// Transaction Access
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn rs_coap_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const CoapState);
    state.tx_count() as u64
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const CoapState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1 // UDP datagrams are always complete
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut CoapState);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
    state.free_logged_transactions();
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_set_logged(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut CoapState);
    state.set_logged(tx_index);
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_state_gc(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut CoapState);
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::CoapTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_coap_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Get the code class.
#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_get_code_class(tx: *const c_void) -> c_int {
    if tx.is_null() { return -1; }
    let tx = &*(tx as *const state::CoapTransaction);
    tx.detect_flags.code_class as c_int
}

/// Get the code detail.
#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_get_code_detail(tx: *const c_void) -> c_int {
    if tx.is_null() { return -1; }
    let tx = &*(tx as *const state::CoapTransaction);
    tx.detect_flags.code_detail as c_int
}

/// Check if a transaction is a request.
#[no_mangle]
pub unsafe extern "C" fn rs_coap_tx_is_request(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::CoapTransaction);
    if tx.detect_flags.is_request { 1 } else { 0 }
}
