// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for EtherNet/IP (CIP).
//!
//! This plugin provides:
//! - Protocol detection (probing) for EtherNet/IP over TCP and UDP
//! - Full encapsulation header and CIP message parsing
//! - Per-flow state with session tracking
//! - EVE JSON logging of EtherNet/IP and CIP metadata
//! - Detection keywords: enip.command, enip.cip_service, enip.cip_class
//!
//! ## Architecture
//!
//! ```text
//! enip.rs      — Pure Rust EtherNet/IP wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod logger;
pub mod enip;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::EnipState;

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
    fn enip_log_notice(msg: *const c_char);
    fn enip_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { enip_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { enip_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a TCP/UDP payload for EtherNet/IP encapsulation header.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 24 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if enip::probe_enip(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new EtherNet/IP parser state.
#[no_mangle]
pub extern "C" fn rs_enip_state_new() -> *mut c_void {
    let state = Box::new(EnipState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free an EtherNet/IP parser state.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut EnipState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse an EtherNet/IP message.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 24 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut EnipState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("EtherNet/IP parse error: {}", e));
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
pub unsafe extern "C" fn rs_enip_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const EnipState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const EnipState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut EnipState);
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
pub unsafe extern "C" fn rs_enip_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::EnipTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_enip_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Get the encapsulation command name as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_command(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::EnipTransaction);
    match std::ffi::CString::new(tx.detect_flags.command.as_str()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the CIP service name as a C string.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_cip_service(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() { return ptr::null_mut(); }
    let tx = &*(tx as *const state::EnipTransaction);
    match &tx.detect_flags.cip_service {
        Some(svc) => match std::ffi::CString::new(svc.as_str()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Get the CIP class ID.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_cip_class(
    tx: *const c_void,
) -> u16 {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::EnipTransaction);
    tx.detect_flags.cip_class
}

/// Get the session handle.
#[no_mangle]
pub unsafe extern "C" fn rs_enip_tx_get_session_handle(
    tx: *const c_void,
) -> u32 {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::EnipTransaction);
    tx.detect_flags.session_handle
}
