// FMADIO Ring Buffer Capture Plugin for Suricata
// Copyright 2025-2026. Fidelis Farm & Technologies, LLC
// SPDX-License-Identifier: GPL-2.0-only
//
// This module provides the Rust implementation for the FMADIO Ring Buffer
// capture plugin. It exports extern "C" functions that are called by
// Suricata's thread module system.

pub mod ring;
pub mod thread;

use std::ffi::{c_void, CStr};
use std::os::raw::{c_char, c_int};
use std::time::Duration;

use ring::FmadioRingCapture;
use thread::FmadioThreadVars;

// Suricata constants (from tm-threads-common.h)
const TM_ECODE_OK: c_int = 0;
const TM_ECODE_FAILED: c_int = 1;

// Suricata packet source (from decode.h)
const PKT_SRC_WIRE: u8 = 1;

// Datalink type (from pcap/dlt.h)
const LINKTYPE_ETHERNET: c_int = 1;

// Thread flags (from threadvars.h)
const THV_RUNNING: u32 = 1 << 13;

// External C wrapper functions (defined in source.c)
// These wrap Suricata functions/macros/inline functions to make them
// callable from Rust. All Suricata types are passed as opaque c_void pointers.
extern "C" {
    // Packet pool functions
    fn fmadio_packet_pool_wait();
    fn fmadio_packet_get_from_queue_or_alloc() -> *mut c_void;
    fn fmadio_return_packet_to_pool(tv: *mut c_void, p: *mut c_void);

    // Packet manipulation
    fn fmadio_packet_set_source(p: *mut c_void, src: u8);
    fn fmadio_packet_set_datalink(p: *mut c_void, datalink: c_int);
    fn fmadio_packet_set_data(p: *mut c_void, data: *const u8, len: u32) -> c_int;
    fn fmadio_packet_set_time(p: *mut c_void, secs: u64, usecs: u32);

    // Thread functions
    fn fmadio_threads_set_flag(tv: *mut c_void, flag: u32);
    fn fmadio_slot_process_pkt(tv: *mut c_void, slot: *mut c_void, p: *mut c_void) -> c_int;
    fn fmadio_capture_handle_timeout(tv: *mut c_void, p: *mut c_void);

    // Stats
    fn fmadio_stats_register_counter(name: *const c_char, tv: *mut c_void) -> u16;
    fn fmadio_stats_set_ui64(tv: *mut c_void, counter: u16, value: u64);
    fn fmadio_stats_sync_if_signalled(tv: *mut c_void);

    // Slot navigation
    fn fmadio_get_slot_next(slot: *mut c_void) -> *mut c_void;

    // Logging
    fn fmadio_log_notice(msg: *const c_char);
    fn fmadio_log_error(msg: *const c_char);

    // Control flags
    fn fmadio_should_stop() -> c_int;
}

/// Helper to get next slot from TmSlot
/// Uses C wrapper to access slot->slot_next safely.
unsafe fn get_slot_next(slot: *mut c_void) -> *mut c_void {
    fmadio_get_slot_next(slot)
}

/// Log a notice message
fn log_notice(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe {
            fmadio_log_notice(c_msg.as_ptr());
        }
    }
}

/// Log an error message
fn log_error(msg: &str) {
    if let Ok(c_msg) = std::ffi::CString::new(msg) {
        unsafe {
            fmadio_log_error(c_msg.as_ptr());
        }
    }
}

/// Extract ring ID from path.
///
/// Tries to parse a numeric suffix from the ring path.
/// For example, "/opt/fmadio/queue/lxc_ring0" returns 0,
/// "/opt/fmadio/queue/lxc_ring1" returns 1.
/// Defaults to 0 if no number found.
fn extract_ring_id(path: &str) -> u32 {
    // Find the last non-digit character position
    if let Some(pos) = path.rfind(|c: char| !c.is_ascii_digit()) {
        // Check if there are digits after it
        if pos + 1 < path.len() {
            if let Ok(id) = path[pos + 1..].parse::<u32>() {
                return id;
            }
        }
    }
    0
}

// ============================================================================
// FFI Exports - Thread Module Callbacks
// ============================================================================

/// Thread initialization callback.
///
/// Called when a worker thread starts. Allocates thread context and opens
/// the FMADIO ring buffer.
///
/// # Arguments
/// * `tv` - Suricata ThreadVars pointer
/// * `initdata` - Ring buffer path as C string (from capture-plugin-args)
/// * `data` - Output pointer to store allocated thread context
///
/// # Returns
/// * `TM_ECODE_OK` on success
/// * `TM_ECODE_FAILED` on error
#[no_mangle]
pub extern "C" fn fmadio_thread_init(
    tv: *mut c_void,
    initdata: *const c_void,
    data: *mut *mut c_void,
) -> c_int {
    // Get ring path from initdata (passed as capture-plugin-args)
    let ring_path = if initdata.is_null() {
        // Default path
        "/opt/fmadio/queue/lxc_ring0"
    } else {
        unsafe {
            match CStr::from_ptr(initdata as *const c_char).to_str() {
                Ok(s) => s,
                Err(_) => {
                    log_error("Invalid ring path encoding");
                    return TM_ECODE_FAILED;
                }
            }
        }
    };

    // Extract ring ID from path for unique stats
    let ring_id = extract_ring_id(ring_path);

    log_notice(&format!("Opening FMADIO ring buffer {}: {}", ring_id, ring_path));

    // Open the ring buffer
    let ring = match FmadioRingCapture::open(ring_path, false) {
        Ok(r) => r,
        Err(e) => {
            log_error(&format!("Failed to open ring buffer {}: {:?}", ring_id, e));
            return TM_ECODE_FAILED;
        }
    };

    // Allocate thread context
    let mut ptv = Box::new(FmadioThreadVars::new());
    ptv.tv = tv;
    ptv.ring = Box::into_raw(Box::new(ring));
    ptv.ring_id = ring_id;

    // Store ring path
    if let Ok(path_cstr) = std::ffi::CString::new(ring_path) {
        ptv.ring_path = path_cstr.into_raw();
    }

    // Register stats counters with ring ID for per-ring stats
    unsafe {
        let name_pkts = std::ffi::CString::new(
            format!("capture.fmadio_ring{}.packets", ring_id)
        ).unwrap();
        let name_bytes = std::ffi::CString::new(
            format!("capture.fmadio_ring{}.bytes", ring_id)
        ).unwrap();
        let name_drops = std::ffi::CString::new(
            format!("capture.fmadio_ring{}.drops", ring_id)
        ).unwrap();

        ptv.counter_pkts = fmadio_stats_register_counter(name_pkts.as_ptr(), tv);
        ptv.counter_bytes = fmadio_stats_register_counter(name_bytes.as_ptr(), tv);
        ptv.counter_drops = fmadio_stats_register_counter(name_drops.as_ptr(), tv);
    }

    // Return thread context
    unsafe {
        *data = Box::into_raw(ptv) as *mut c_void;
    }

    log_notice(&format!("FMADIO ring buffer {} opened successfully", ring_id));
    TM_ECODE_OK
}

/// Main packet acquisition loop.
///
/// Called by Suricata to run the capture loop. Reads packets from the
/// FMADIO ring buffer and passes them through the processing pipeline.
///
/// # Arguments
/// * `tv` - Suricata ThreadVars pointer
/// * `data` - Thread context (FmadioThreadVars)
/// * `slot` - Current TmSlot in the pipeline
///
/// # Returns
/// * `TM_ECODE_OK` on normal exit
/// * `TM_ECODE_FAILED` on error
#[no_mangle]
pub extern "C" fn fmadio_pkt_acq_loop(
    tv: *mut c_void,
    data: *mut c_void,
    slot: *mut c_void,
) -> c_int {
    let ptv = unsafe { &mut *(data as *mut FmadioThreadVars) };

    // Store slot for later use
    ptv.slot = slot;

    // Get the next slot in the pipeline (decode module)
    let slot_next = unsafe { get_slot_next(slot) };

    // Signal that we're running
    unsafe {
        fmadio_threads_set_flag(tv, THV_RUNNING);
    }

    // Adaptive backoff: start at 0, increase when idle, reset on packet
    const BACKOFF_MIN_US: u64 = 0;
    const BACKOFF_MAX_US: u64 = 1000; // 1ms max
    const BACKOFF_STEP_US: u64 = 100; // increase by 100us each idle iteration
    let mut backoff_us: u64 = BACKOFF_MIN_US;
    let mut idle_count: u32 = 0;

    // Main acquisition loop
    loop {
        // Check for shutdown signal
        if unsafe { fmadio_should_stop() } != 0 {
            break;
        }

        // Check for break loop flag
        if ptv.break_loop {
            ptv.break_loop = false; // Reset for next iteration
            break;
        }

        // Try to receive a packet from the ring buffer first
        let ring = unsafe { ptv.ring_mut() };
        match ring.recv_packet() {
            Ok(Some(recv_pkt)) => {
                // Got packet - now wait for pool and get a Suricata packet
                unsafe {
                    fmadio_packet_pool_wait();
                }
                let p = unsafe { fmadio_packet_get_from_queue_or_alloc() };
                if p.is_null() {
                    log_error("Failed to get packet from pool");
                    return TM_ECODE_FAILED;
                }

                // Set packet source
                unsafe {
                    fmadio_packet_set_source(p, PKT_SRC_WIRE);
                }

                // Set datalink type (Ethernet)
                unsafe {
                    fmadio_packet_set_datalink(p, LINKTYPE_ETHERNET);
                }

                // Set timestamp (convert nanoseconds to seconds + microseconds)
                let secs = recv_pkt.timestamp_ns / 1_000_000_000;
                let usecs = ((recv_pkt.timestamp_ns % 1_000_000_000) / 1000) as u32;
                unsafe {
                    fmadio_packet_set_time(p, secs, usecs);
                }

                // Set packet data (zero-copy pointer into ring buffer)
                unsafe {
                    if fmadio_packet_set_data(p, recv_pkt.data, recv_pkt.len as u32) != 0 {
                        log_error("Failed to set packet data");
                        fmadio_return_packet_to_pool(tv, p);
                        continue;
                    }
                }

                // Update stats
                ptv.pkts += 1;
                ptv.bytes += recv_pkt.len as u64;

                // Reset backoff and idle count when receiving packets
                backoff_us = BACKOFF_MIN_US;
                idle_count = 0;

                // Process packet through the pipeline
                unsafe {
                    if fmadio_slot_process_pkt(tv, slot_next, p) != TM_ECODE_OK {
                        log_error("Failed to process packet");
                        return TM_ECODE_FAILED;
                    }
                }
            }
            Ok(None) => {
                idle_count += 1;

                // Every 100 idle iterations, do timeout handling
                if idle_count >= 100 {
                    idle_count = 0;
                    let p = unsafe { fmadio_packet_get_from_queue_or_alloc() };
                    if !p.is_null() {
                        unsafe {
                            fmadio_capture_handle_timeout(tv, p);
                        }
                    }
                }

                // Adaptive backoff
                if backoff_us > 0 {
                    std::thread::sleep(Duration::from_micros(backoff_us));
                }
                backoff_us = (backoff_us + BACKOFF_STEP_US).min(BACKOFF_MAX_US);
            }
            Err(ring::FmadioRingError::EndOfStream) => {
                log_notice("End of stream reached");
                break;
            }
            Err(e) => {
                log_error(&format!("Ring buffer error: {:?}", e));
                return TM_ECODE_FAILED;
            }
        }

        // Sync stats periodically
        unsafe {
            fmadio_stats_sync_if_signalled(tv);
        }
    }

    TM_ECODE_OK
}

/// Signal the acquisition loop to break.
///
/// Called when Suricata wants to stop the capture.
///
/// # Arguments
/// * `tv` - Suricata ThreadVars pointer
/// * `data` - Thread context (FmadioThreadVars)
///
/// # Returns
/// * `TM_ECODE_OK` always
#[no_mangle]
pub extern "C" fn fmadio_pkt_acq_break_loop(
    _tv: *mut c_void,
    data: *mut c_void,
) -> c_int {
    if !data.is_null() {
        let ptv = unsafe { &mut *(data as *mut FmadioThreadVars) };
        ptv.break_loop = true;
    }
    TM_ECODE_OK
}

/// Thread deinitialization callback.
///
/// Called when a worker thread exits. Cleans up resources.
///
/// # Arguments
/// * `tv` - Suricata ThreadVars pointer
/// * `data` - Thread context (FmadioThreadVars)
///
/// # Returns
/// * `TM_ECODE_OK` always
#[no_mangle]
pub extern "C" fn fmadio_thread_deinit(
    _tv: *mut c_void,
    data: *mut c_void,
) -> c_int {
    if !data.is_null() {
        // Take ownership and drop
        let ptv = unsafe { Box::from_raw(data as *mut FmadioThreadVars) };
        log_notice(&format!(
            "FMADIO ring {} closed: {} packets, {} bytes, {} drops",
            ptv.ring_id, ptv.pkts, ptv.bytes, ptv.drops
        ));
        // ptv drops here, which closes the ring buffer
    }
    TM_ECODE_OK
}

/// Print thread statistics on exit.
///
/// Called when the thread exits to log final statistics.
///
/// # Arguments
/// * `tv` - Suricata ThreadVars pointer
/// * `data` - Thread context (FmadioThreadVars)
#[no_mangle]
pub extern "C" fn fmadio_thread_exit_print_stats(
    tv: *mut c_void,
    data: *mut c_void,
) {
    if data.is_null() {
        return;
    }

    let ptv = unsafe { &*(data as *const FmadioThreadVars) };

    // Update final stats
    unsafe {
        fmadio_stats_set_ui64(tv, ptv.counter_pkts, ptv.pkts);
        fmadio_stats_set_ui64(tv, ptv.counter_bytes, ptv.bytes);
        fmadio_stats_set_ui64(tv, ptv.counter_drops, ptv.drops);
    }

    log_notice(&format!(
        "FMADIO Ring {} stats: pkts={}, bytes={}, drops={}",
        ptv.ring_id, ptv.pkts, ptv.bytes, ptv.drops
    ));
}
