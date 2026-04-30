// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//
//! Suricata application-layer parser plugin for EtherCAT.
//!
//! This plugin provides:
//! - Protocol detection (probing) for EtherCAT over UDP and raw Ethernet
//! - Full EtherCAT frame parsing (header + datagrams + mailbox detection)
//! - Per-flow state with transaction management
//! - EVE JSON logging of EtherCAT metadata
//! - Detection keywords: ethercat.is_cyclic, ethercat.has_mailbox, ethercat.command
//!
//! ## Architecture
//!
//! ```text
//! ethercat.rs  — Pure Rust EtherCAT wire protocol parser (no Suricata deps)
//! state.rs     — Per-flow parser state and transaction management
//! logger.rs    — EVE JSON generation
//! lib.rs       — Suricata FFI bridge (C-extern callbacks)
//! plugin.c     — Plugin entry point (SCPluginRegister)
//! applayer.c   — App-layer registration (RustParser construction)
//! ```

pub mod ethercat;
pub mod logger;
pub mod state;

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use state::EthercatState;

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
    fn ethercat_log_notice(msg: *const c_char);
    fn ethercat_log_error(msg: *const c_char);
}

#[allow(dead_code)]
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { ethercat_log_notice(c_msg.as_ptr()) }
    }
}

fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe { ethercat_log_error(c_msg.as_ptr()) }
    }
}

// ============================================================================
// Protocol Probing
// ============================================================================

/// Probe a payload for EtherCAT protocol signatures.
///
/// Called by Suricata during protocol detection. Returns 1 if the buffer
/// looks like EtherCAT, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_probe(
    buf: *const u8,
    len: u32,
) -> c_int {
    if buf.is_null() || len < 4 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buf, len as usize);
    if ethercat::probe_ethercat(data) { 1 } else { 0 }
}

// ============================================================================
// State Lifecycle
// ============================================================================

/// Allocate a new EtherCAT parser state.
#[no_mangle]
pub extern "C" fn rs_ethercat_state_new() -> *mut c_void {
    let state = Box::new(EthercatState::new());
    Box::into_raw(state) as *mut c_void
}

/// Free an EtherCAT parser state.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_state_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut EthercatState));
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse an EtherCAT message.
///
/// Returns 0 on success, -1 on unrecoverable parse failure.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_parse(
    state: *mut c_void,
    buf: *const u8,
    len: u32,
) -> c_int {
    if state.is_null() || buf.is_null() || len < 2 {
        return APP_LAYER_ERROR;
    }

    let state = &mut *(state as *mut EthercatState);
    let data = std::slice::from_raw_parts(buf, len as usize);

    match state.parse(data) {
        Ok(_tx_id) => APP_LAYER_OK,
        Err(e) => {
            state.parse_errors += 1;
            if state.parse_errors <= 3 {
                log_error(&format!("EtherCAT parse error: {}", e));
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
pub unsafe extern "C" fn rs_ethercat_get_tx_count(state: *const c_void) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = &*(state as *const EthercatState);
    state.tx_count() as u64
}

/// Get a transaction by index.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_get_tx(
    state: *const c_void,
    tx_index: u64,
) -> *const c_void {
    if state.is_null() {
        return ptr::null();
    }
    let state = &*(state as *const EthercatState);
    match state.transactions.get(tx_index as usize) {
        Some(tx) => tx as *const _ as *const c_void,
        None => ptr::null(),
    }
}

/// Get transaction progress (always 1 for UDP — complete in one datagram).
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_tx_get_progress(
    _tx: *const c_void,
    _direction: u8,
) -> c_int {
    1
}

/// Mark a transaction as complete and eligible for cleanup.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_tx_free(
    state: *mut c_void,
    tx_index: u64,
) {
    if state.is_null() {
        return;
    }
    let state = &mut *(state as *mut EthercatState);
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
/// `rs_ethercat_json_free()`.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_tx_get_json(
    tx: *const c_void,
) -> *mut c_char {
    if tx.is_null() {
        return ptr::null_mut();
    }
    let tx = &*(tx as *const state::EthercatTransaction);
    let json_str = logger::log_transaction_string(tx);
    match std::ffi::CString::new(json_str) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a JSON string returned by `rs_ethercat_tx_get_json`.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_json_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(std::ffi::CString::from_raw(ptr));
    }
}

// ============================================================================
// Detection Keywords
// ============================================================================

/// Check if a transaction contains cyclic (process data) commands.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_tx_is_cyclic(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::EthercatTransaction);
    if tx.detect_flags.is_cyclic { 1 } else { 0 }
}

/// Check if a transaction contains mailbox data.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_tx_has_mailbox(tx: *const c_void) -> c_int {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::EthercatTransaction);
    if tx.detect_flags.has_mailbox { 1 } else { 0 }
}

/// Get the number of datagrams.
#[no_mangle]
pub unsafe extern "C" fn rs_ethercat_tx_get_datagram_count(tx: *const c_void) -> u32 {
    if tx.is_null() { return 0; }
    let tx = &*(tx as *const state::EthercatTransaction);
    tx.detect_flags.datagram_count as u32
}
