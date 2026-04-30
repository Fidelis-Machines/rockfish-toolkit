// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for S7comm.
//!
//! This plugin provides:
//! - Protocol detection (probing) for S7comm over TCP port 102
//! - Full TPKT/COTP/S7comm message parsing
//! - Per-flow state with transaction management
//! - EVE JSON logging of S7comm metadata
//! - Detection keywords: s7comm.msg_type, s7comm.function_code, s7comm.area
//!
//! ## Architecture
//!
//! ```text
//! s7comm.rs    — Pure Rust S7comm wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod logger;
pub mod s7comm;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::S7commState;

// ============================================================================
// FFI Constants
// ============================================================================

/// Success
const APP_LAYER_OK: c_int = 0;
/// Parse error
const APP_LAYER_ERROR: c_int = -1;

// ============================================================================
// External C functions (defined in applayer.c)
// ============================================================================

extern "C" {
    fn s7comm_log_notice(msg: *const c_char);
    fn s7comm_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { s7comm_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { s7comm_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a TCP payload for TPKT + S7comm.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 7 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if s7comm::probe_s7comm(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new S7comm parser state.
#[no_mangle]
pub extern "C" fn rs_s7comm_state_new() -> *mut c_void {
    let state = Box::new(S7commState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free an S7comm parser state.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut S7commState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse an S7comm message.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 7 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut S7commState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("S7comm parse error: {}", e));
            }
            APP_LAYER_ERROR
        }
    }
}

// ============================================================================
// Transaction Access
// ============================================================================

/// Get the number of active transactions.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const S7commState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const S7commState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut S7commState);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
    state.free_logged_transactions();
}

/// Set a transaction as logged.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_set_logged(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut S7commState);
    state.set_logged(tx_index);
}

/// Garbage collect logged transactions.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_state_gc(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut S7commState);
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

/// Generate EVE JSON for a transaction.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::S7commTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_s7comm_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Get the message type raw value.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_get_msg_type(tx: *const c_void) -> c_int {
    if tx.is_null() { return -1; }
    let tx = &*(tx as *const state::S7commTransaction);
    match tx.detect_flags.msg_type_raw {
        Some(v) => v as c_int,
        None => -1,
    }
}

/// Get the function code raw value.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_get_function_code(tx: *const c_void) -> c_int {
    if tx.is_null() { return -1; }
    let tx = &*(tx as *const state::S7commTransaction);
    match tx.detect_flags.function_code_raw {
        Some(v) => v as c_int,
        None => -1,
    }
}

/// Check if a transaction is security-relevant.
#[no_mangle]
pub unsafe extern "C" fn rs_s7comm_tx_is_security_relevant(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::S7commTransaction);
    if tx.detect_flags.is_security_relevant { 1 } else { 0 }
}
