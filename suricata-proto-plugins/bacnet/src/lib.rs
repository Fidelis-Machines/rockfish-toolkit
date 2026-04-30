// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for BACnet.
//!
//! This plugin provides:
//! - Protocol detection (probing) for BACnet/IP over UDP
//! - Full BVLC + NPDU + APDU message parsing
//! - Per-flow state with device discovery tracking
//! - EVE JSON logging of BACnet metadata
//! - Detection keywords: bacnet.service, bacnet.object_type, bacnet.apdu_type
//!
//! ## Architecture
//!
//! ```text
//! bacnet.rs    — Pure Rust BACnet wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod logger;
pub mod bacnet;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::BacnetState;

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
    fn bacnet_log_notice(msg: *const c_char);
    fn bacnet_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { bacnet_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { bacnet_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a UDP payload for BACnet/IP BVLC header.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 4 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if bacnet::probe_bacnet(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new BACnet parser state.
#[no_mangle]
pub extern "C" fn rs_bacnet_state_new() -> *mut c_void {
    let state = Box::new(BacnetState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free a BACnet parser state.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut BacnetState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse a BACnet message.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 4 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut BacnetState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("BACnet parse error: {}", e));
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
pub unsafe extern "C" fn rs_bacnet_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const BacnetState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const BacnetState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress (always 1 for UDP).
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1 // UDP datagrams are always complete
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut BacnetState);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

/// Generate EVE JSON for a transaction.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::BacnetTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_bacnet_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Get the BVLC function name as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_get_bvlc_function(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::BacnetTransaction);
    match std::ffi::CString::new(tx.detect_flags.bvlc_function.as_str()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the service choice name as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_get_service_choice(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::BacnetTransaction);
    match &tx.detect_flags.service_choice {
        Some(svc) => match std::ffi::CString::new(svc.as_str()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Get the APDU type name as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_get_apdu_type(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::BacnetTransaction);
    match &tx.detect_flags.apdu_type {
        Some(t) => match std::ffi::CString::new(t.as_str()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Check if the message is a broadcast.
#[no_mangle]
pub unsafe extern "C" fn rs_bacnet_tx_is_broadcast(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::BacnetTransaction);
    if tx.detect_flags.is_broadcast { 1 } else { 0 }
}
