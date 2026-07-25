// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for ASTERIX.
//!
//! This plugin provides:
//! - Protocol detection (probing) for ASTERIX over UDP
//! - ASTERIX data block and record parsing
//! - Per-flow state with category and ICAO address tracking
//! - EVE JSON logging of ASTERIX surveillance metadata
//!
//! ## Architecture
//!
//! The plugin follows the Suricata app-layer template parser pattern:
//!
//! ```text
//! asterix.rs   — Pure Rust ASTERIX wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod asterix;
pub mod logger;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::AsterixState;

// ============================================================================
// FFI Constants (mirror Suricata's app-layer return codes)
// ============================================================================

/// Success
const APP_LAYER_OK: c_int = 0;
/// Parse error
const APP_LAYER_ERROR: c_int = -1;

// ============================================================================
// External C functions (defined in applayer.c)
// ============================================================================

extern "C" {
    fn asterix_log_notice(msg: *const c_char);
    fn asterix_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { asterix_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { asterix_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a UDP payload for ASTERIX data blocks.
///
/// Called by Suricata during protocol detection. Returns 1 if the buffer
/// looks like ASTERIX, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 3 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if asterix::probe_asterix(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new ASTERIX parser state.
/// Called once per flow when ASTERIX is detected.
#[no_mangle]
pub extern "C" fn rs_asterix_state_new() -> *mut c_void {
    let state = Box::new(AsterixState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free an ASTERIX parser state.
/// Called when the flow is cleaned up.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut AsterixState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse an ASTERIX message.
///
/// Returns 0 on success, -1 on unrecoverable parse failure.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 3 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut AsterixState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("ASTERIX parse error: {}", e));
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
pub unsafe extern "C" fn rs_asterix_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const AsterixState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const AsterixState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress (always 1 for UDP — complete in one datagram).
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1 // UDP datagrams are always complete
}

/// Mark a transaction as logged and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_tx_set_logged(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut AsterixState);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
}

/// Garbage collect logged transactions.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_state_gc(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut AsterixState);
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

/// Generate EVE JSON for a transaction.
///
/// Returns a heap-allocated C string that the caller must free with
/// `rs_asterix_json_free()`.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::AsterixTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_asterix_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

/// Combined tx free: mark as logged and garbage collect.
/// Alias for Suricata 8 AppLayerParser.StateTransactionFree callback.
#[no_mangle]
pub unsafe extern "C" fn rs_asterix_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    rs_asterix_tx_set_logged(state, tx_index);
    rs_asterix_state_gc(state);
}
