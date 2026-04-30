// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for CANopen.
//!
//! This plugin provides:
//! - Protocol detection (probing) for CAN-over-UDP encapsulation
//! - Full CANopen frame parsing (COB-ID, NMT, SDO, PDO, EMCY)
//! - Per-flow state with transaction management
//! - EVE JSON logging of CANopen metadata
//! - Detection keywords: canopen.has_nmt, canopen.has_sdo, canopen.has_pdo
//!
//! ## Architecture
//!
//! ```text
//! canopen.rs   — Pure Rust CANopen wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod canopen;
pub mod logger;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::CanopenState;

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
    fn canopen_log_notice(msg: *const c_char);
    fn canopen_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { canopen_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { canopen_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a UDP payload for CAN-over-UDP encapsulation with CANopen frames.
///
/// Called by Suricata during protocol detection. Returns 1 if the buffer
/// looks like CANopen, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 20 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if canopen::probe_canopen(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new CANopen parser state.
#[no_mangle]
pub extern "C" fn rs_canopen_state_new() -> *mut c_void {
    let state = Box::new(CanopenState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free a CANopen parser state.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut CanopenState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse a CANopen message.
///
/// Returns 0 on success, -1 on unrecoverable parse failure.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 4 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut CanopenState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("CANopen parse error: {}", e));
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
pub unsafe extern "C" fn rs_canopen_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const CanopenState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const CanopenState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress (always 1 for UDP — complete in one datagram).
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut CanopenState);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

/// Generate EVE JSON for a transaction.
///
/// Returns a heap-allocated C string that the caller must free with
/// `rs_canopen_json_free()`.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::CanopenTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_canopen_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Check if a transaction contains NMT commands.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_has_nmt(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::CanopenTransaction);
    if tx.detect_flags.has_nmt { 1 } else { 0 }
}

/// Check if a transaction contains SDO transfers.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_has_sdo(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::CanopenTransaction);
    if tx.detect_flags.has_sdo { 1 } else { 0 }
}

/// Check if a transaction contains PDO data.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_has_pdo(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::CanopenTransaction);
    if tx.detect_flags.has_pdo { 1 } else { 0 }
}

/// Check if a transaction contains emergency frames.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_has_emergency(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::CanopenTransaction);
    if tx.detect_flags.has_emergency { 1 } else { 0 }
}

/// Get the number of CAN frames in the message.
#[no_mangle]
pub unsafe extern "C" fn rs_canopen_tx_get_frame_count(tx: *const c_void) -> u32 {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::CanopenTransaction);
    tx.detect_flags.frame_count as u32
}
