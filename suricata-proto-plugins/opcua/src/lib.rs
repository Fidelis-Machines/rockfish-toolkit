// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for OPC UA.
//!
//! This plugin provides:
//! - Protocol detection (probing) for OPC UA over TCP
//! - Full OPC UA binary message parsing (header + secure channel + services)
//! - Per-flow state with session and security tracking
//! - EVE JSON logging of OPC UA metadata
//! - Detection keywords: opcua.message_type, opcua.service_type, opcua.security_mode
//!
//! ## Architecture
//!
//! ```text
//! opcua.rs     — Pure Rust OPC UA wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod logger;
pub mod opcua;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::OpcuaState;

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
    fn opcua_log_notice(msg: *const c_char);
    fn opcua_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { opcua_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { opcua_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a TCP payload for OPC UA message header.
///
/// Called by Suricata during protocol detection. Returns 1 if the buffer
/// looks like OPC UA, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 8 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if opcua::probe_opcua(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new OPC UA parser state.
#[no_mangle]
pub extern "C" fn rs_opcua_state_new() -> *mut c_void {
    let state = Box::new(OpcuaState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free an OPC UA parser state.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut OpcuaState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse an OPC UA message.
///
/// Returns 0 on success, -1 on unrecoverable parse failure.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 8 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut OpcuaState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("OPC UA parse error: {}", e));
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
pub unsafe extern "C" fn rs_opcua_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const OpcuaState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const OpcuaState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress (always 1 for TCP messages — complete when parsed).
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut OpcuaState);
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
/// `rs_opcua_json_free()`.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::OpcuaTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_opcua_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Get the message type as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_tx_get_message_type(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::OpcuaTransaction);
    match std::ffi::CString::new(tx.detect_flags.message_type.as_str()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the service type as a C string (NULL if not applicable).
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_tx_get_service_type(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::OpcuaTransaction);
    match &tx.detect_flags.service_type {
        Some(svc) => match std::ffi::CString::new(svc.as_str()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Get the security mode as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_opcua_tx_get_security_mode(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::OpcuaTransaction);
    match std::ffi::CString::new(tx.detect_flags.security_mode.as_str()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
