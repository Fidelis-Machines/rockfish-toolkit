// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for IEC 60870-5-104 (IEC 104).
//!
//! This plugin provides:
//! - Protocol detection (probing) for IEC 104 over TCP (port 2404)
//! - Full IEC 104 APDU parsing (I/S/U frames, ASDU)
//! - Per-flow state with transaction management
//! - EVE JSON logging of IEC 104 metadata
//! - Detection keywords: iec104.is_command, iec104.is_control_action
//!
//! ## Architecture
//!
//! The plugin follows the Suricata app-layer template parser pattern:
//!
//! ```text
//! iec104.rs    — Pure Rust IEC 104 wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```
//!
//! The IEC 104 wire parser (iec104.rs) is intentionally independent of
//! Suricata so it can be reused in other contexts.

pub mod iec104;
pub mod logger;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::Iec104State;

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
    fn iec104_log_notice(msg: *const c_char);
    fn iec104_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { iec104_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { iec104_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a TCP payload for the IEC 104 start byte (0x68).
///
/// Called by Suricata during protocol detection. Returns 1 if the buffer
/// looks like IEC 104, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 6 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if iec104::probe_iec104(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new IEC 104 parser state.
/// Called once per flow when IEC 104 is detected.
#[no_mangle]
pub extern "C" fn rs_iec104_state_new() -> *mut c_void {
    let state = Box::new(Iec104State::new());
    Box::into_raw(state) as *mut c_void
}

/// Free an IEC 104 parser state.
/// Called when the flow is cleaned up.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut Iec104State));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse an IEC 104 message.
///
/// Returns 0 on success, -1 on unrecoverable parse failure.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 6 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut Iec104State);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("IEC 104 parse error: {}", e));
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
pub unsafe extern "C" fn rs_iec104_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const Iec104State);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const Iec104State);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress (always 1 for TCP segments that are fully parsed).
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut Iec104State);
    if let Some(tx) = state.transactions.get_mut(tx_index as usize) {
        tx.logged = true;
    }
    state.free_logged_transactions();
}

/// Mark a transaction as logged.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_set_logged(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut Iec104State);
    state.set_logged(tx_index);
}

/// Garbage collect completed transactions.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_state_gc(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut Iec104State);
    state.free_logged_transactions();
}

// ============================================================================
// EVE JSON Logging
// ============================================================================

/// Generate EVE JSON for a transaction.
///
/// Returns a heap-allocated C string that the caller must free with
/// `rs_iec104_json_free()`.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::Iec104Transaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_iec104_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
//
// These provide the backing functions for Suricata rule keywords:
//   iec104.is_command;
//   iec104.is_control_action;
//   iec104.is_system_command;
//   iec104.has_u_control;
// ============================================================================

/// Check if a transaction contains command-direction type IDs.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_is_command(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::Iec104Transaction);
    if tx.detect_flags.is_command { 1 } else { 0 }
}

/// Check if a transaction contains direct control actions.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_is_control_action(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::Iec104Transaction);
    if tx.detect_flags.is_control_action { 1 } else { 0 }
}

/// Check if a transaction contains system management commands.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_is_system_command(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::Iec104Transaction);
    if tx.detect_flags.is_system_command { 1 } else { 0 }
}

/// Check if a transaction contains U-frame control functions.
#[no_mangle]
pub unsafe extern "C" fn rs_iec104_tx_has_u_control(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::Iec104Transaction);
    if tx.detect_flags.has_u_control { 1 } else { 0 }
}
