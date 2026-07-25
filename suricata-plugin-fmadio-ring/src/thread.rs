// FMADIO Ring Buffer Capture Plugin for Suricata
// Copyright 2025-2026. Fidelis Farm & Technologies, LLC
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::c_void;

use crate::ring::FmadioRingCapture;

/// Per-thread capture context
///
/// This structure is allocated in ThreadInit and passed to all thread callbacks.
/// It holds the ring buffer handle and statistics.
#[repr(C)]
pub struct FmadioThreadVars {
    /// Ring buffer capture handle (Box pointer, owned)
    pub ring: *mut FmadioRingCapture,

    /// Suricata ThreadVars pointer (opaque)
    pub tv: *mut c_void,

    /// Next slot in the processing pipeline (TmSlot*)
    pub slot: *mut c_void,

    /// Ring buffer path (owned C string)
    pub ring_path: *mut libc::c_char,

    /// Ring buffer identifier (0-based index from config)
    /// Used to differentiate stats counters between rings
    pub ring_id: u32,

    /// Packets received counter
    pub pkts: u64,

    /// Bytes received counter
    pub bytes: u64,

    /// Packets dropped (ring overrun, etc.)
    pub drops: u64,

    /// Suricata stats counter ID for packets
    pub counter_pkts: u16,

    /// Suricata stats counter ID for bytes
    pub counter_bytes: u16,

    /// Suricata stats counter ID for drops
    pub counter_drops: u16,

    /// Flag to signal loop should break
    pub break_loop: bool,
}

impl FmadioThreadVars {
    /// Create a new thread context
    pub fn new() -> Self {
        Self {
            ring: std::ptr::null_mut(),
            tv: std::ptr::null_mut(),
            slot: std::ptr::null_mut(),
            ring_path: std::ptr::null_mut(),
            ring_id: 0,
            pkts: 0,
            bytes: 0,
            drops: 0,
            counter_pkts: 0,
            counter_bytes: 0,
            counter_drops: 0,
            break_loop: false,
        }
    }

    /// Check if the ring is open
    pub fn is_ring_open(&self) -> bool {
        !self.ring.is_null()
    }

    /// Get ring capture reference (unsafe - caller must ensure ring is open)
    pub unsafe fn ring_ref(&self) -> &FmadioRingCapture {
        &*self.ring
    }

    /// Get ring capture mutable reference (unsafe - caller must ensure ring is open)
    pub unsafe fn ring_mut(&mut self) -> &mut FmadioRingCapture {
        &mut *self.ring
    }
}

impl Default for FmadioThreadVars {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FmadioThreadVars {
    fn drop(&mut self) {
        // Free the ring capture if allocated
        if !self.ring.is_null() {
            unsafe {
                let _ = Box::from_raw(self.ring);
            }
            self.ring = std::ptr::null_mut();
        }

        // Free the ring path string if allocated
        if !self.ring_path.is_null() {
            unsafe {
                let _ = std::ffi::CString::from_raw(self.ring_path);
            }
            self.ring_path = std::ptr::null_mut();
        }
    }
}
