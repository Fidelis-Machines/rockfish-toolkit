// FMADIO Ring Buffer Capture Plugin for Suricata
// Copyright 2025-2026. Fidelis Farm & Technologies, LLC
// SPDX-License-Identifier: GPL-2.0-only
//
// Reference: https://github.com/fmadio/platform/blob/main/fmadio2pcap/main.c
// API: https://github.com/fmadio/platform/blob/main/include/fmadio_packet.h

use std::fs::OpenOptions;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::sync::atomic::Ordering;

/// Ring buffer version identifier
pub const FMADRING_VERSION: u32 = 0x00000100;

/// Maximum packet payload size (10KB)
pub const FMADRING_ENTRYSIZE: usize = 10 * 1024;

/// Ring buffer entry count
pub const FMADRING_ENTRYCNT: usize = 1024;

/// Total mmap size (16MB)
pub const FMADRING_MAPSIZE: usize = 16 * 1024 * 1024;

/// Page size for alignment
pub const PAGE_SIZE: usize = 4096;

/// Header size (3 pages: metadata + put + get)
pub const HEADER_SIZE: usize = 3 * PAGE_SIZE;

/// Size of each packet entry including padding (12KB aligned to 4KB page)
pub const PACKET_ENTRY_SIZE: usize = 12 * 1024;

/// FMADIO ring packet flags
pub mod flags {
    /// End of stream marker (bit 0)
    pub const FMADRING_FLAG_EOF: u8 = 1 << 0;
    /// Frame Check Sequence error (bit 1)
    pub const FMADRING_FLAG_FCSERR: u8 = 1 << 1;
}

/// FMADIO ring buffer error types
#[derive(Debug)]
pub enum FmadioRingError {
    OpenFailed(io::Error),
    MmapFailed(String),
    InvalidFormat,
    EndOfStream,
    VersionMismatch { expected: u32, actual: u32 },
}

/// FMADIO ring packet structure (matches fFMADRingPacket_t)
/// Total size: 12KB (10KB payload + 24 byte header + 2024 byte padding)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FmadioRingPacket {
    /// 64-bit nanosecond timestamp (offset 0)
    pub ts: u64,
    /// Wire length (offset 8)
    pub length_wire: u16,
    /// Capture length (offset 10)
    pub length_capture: u16,
    /// Port number (offset 12)
    pub port: u8,
    /// Flags: bit 0 = EOF, bit 1 = FCS error (offset 13)
    pub flag: u8,
    /// Padding (offset 14-15)
    pub _pad1: [u8; 2],
    /// Storage ID (offset 16)
    pub storage_id: u64,
    /// Packet payload - 10KB (offset 24)
    pub payload: [u8; FMADRING_ENTRYSIZE],
    /// Alignment padding to 12KB (offset 10264)
    pub _pad_align: [u8; 2024],
}

/// Ring buffer header metadata section (first 4KB page)
#[repr(C, packed)]
struct RingMetadata {
    /// Version identifier (offset 0)
    version: u32,
    /// Total size (offset 4)
    size: u32,
    /// Packet size (offset 8)
    size_packet: u32,
    /// Path string (offset 12, 128 bytes)
    path: [u8; 128],
    /// Depth - number of entries (offset 140)
    depth: u32,
    /// Padding (offset 144)
    _pad_depth: u32,
    /// Mask for wraparound (offset 148)
    mask: u32,
    /// More padding/fields to 4KB
    _pad0: [u8; PAGE_SIZE - 152],
}

/// Ring buffer Put section (second 4KB page, offset 4096)
#[repr(C, packed)]
struct RingPut {
    /// Put pointer (entry index, unmasked) - volatile
    put: i64,
    /// Total bytes written - volatile
    put_byte: u64,
    /// Timestamp of last written packet - volatile
    put_pkt_ts: u64,
    /// Padding to 4KB
    _pad: [u8; PAGE_SIZE - 24],
}

/// Ring buffer Get section (third 4KB page, offset 8192)
#[repr(C, packed)]
struct RingGet {
    /// Get pointer (entry index, unmasked) - volatile
    get: i64,
    /// Total bytes read - volatile
    get_byte: u64,
    /// Timestamp of last read packet - volatile
    get_pkt_ts: u64,
    /// Padding to 4KB
    _pad: [u8; PAGE_SIZE - 24],
}

/// Received packet data (returned from recv_packet)
pub struct ReceivedPacket {
    /// Nanosecond timestamp
    pub timestamp_ns: u64,
    /// Packet data pointer (points into mmap'd ring buffer)
    pub data: *const u8,
    /// Packet length
    pub len: usize,
    /// Wire length (may be larger than len if truncated)
    pub wire_len: usize,
    /// True if packet has FCS error
    pub fcs_error: bool,
}

/// FMADIO ring buffer capture handle
pub struct FmadioRingCapture {
    /// Memory-mapped ring buffer
    ring_ptr: *mut u8,
    /// Size of mapped region
    ring_size: usize,
    /// File descriptor (kept open)
    _fd: std::fs::File,
    /// Current read position (entry index)
    read_pos: i64,
    /// Ring depth (number of entries) - stored for debugging
    _depth: u32,
    /// Ring mask for wraparound
    mask: u32,
    /// Packets received
    pub packets_received: u64,
    /// Packets with FCS errors
    pub packets_fcs_error: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Whether to include FCS error packets
    include_fcs_errors: bool,
}

// Safety: The ring buffer pointer is only accessed from a single thread
// and the mmap region stays valid for the lifetime of the struct
unsafe impl Send for FmadioRingCapture {}

impl FmadioRingCapture {
    /// Open FMADIO ring buffer for reading
    ///
    /// # Arguments
    /// * `path` - Path to ring buffer file (e.g., `/opt/fmadio/queue/lxc_ring0`)
    /// * `include_fcs_errors` - Whether to include packets with FCS errors
    pub fn open<P: AsRef<Path>>(path: P, include_fcs_errors: bool) -> Result<Self, FmadioRingError> {
        let path = path.as_ref();

        // Open the ring file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(FmadioRingError::OpenFailed)?;

        let fd = file.as_raw_fd();

        // Get file size for mmap
        let metadata = file.metadata().map_err(FmadioRingError::OpenFailed)?;
        let file_size = metadata.len() as usize;

        if file_size == 0 {
            return Err(FmadioRingError::InvalidFormat);
        }

        // Use the standard FMADIO map size or file size, whichever is smaller
        let map_size = file_size.min(FMADRING_MAPSIZE);

        // Memory map the ring buffer
        let ring_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if ring_ptr == libc::MAP_FAILED {
            return Err(FmadioRingError::MmapFailed(
                io::Error::last_os_error().to_string(),
            ));
        }

        // Read header metadata (use read_unaligned for packed struct)
        let (version, _size, _size_packet, depth, mask): (u32, u32, u32, u32, u32) = unsafe {
            let meta = ring_ptr as *const RingMetadata;
            (
                ptr::read_unaligned(ptr::addr_of!((*meta).version)),
                ptr::read_unaligned(ptr::addr_of!((*meta).size)),
                ptr::read_unaligned(ptr::addr_of!((*meta).size_packet)),
                ptr::read_unaligned(ptr::addr_of!((*meta).depth)),
                ptr::read_unaligned(ptr::addr_of!((*meta).mask)),
            )
        };

        // Verify version
        if version != FMADRING_VERSION {
            unsafe {
                libc::munmap(ring_ptr, map_size);
            }
            return Err(FmadioRingError::VersionMismatch {
                expected: FMADRING_VERSION,
                actual: version,
            });
        }

        // Read initial Get position
        let get_pos = unsafe {
            let get_section = (ring_ptr as *const u8).add(2 * PAGE_SIZE) as *const RingGet;
            ptr::read_unaligned(ptr::addr_of!((*get_section).get))
        };

        // Start at current Get position
        let initial_pos = get_pos;

        Ok(Self {
            ring_ptr: ring_ptr as *mut u8,
            ring_size: map_size,
            _fd: file,
            read_pos: initial_pos,
            _depth: depth,
            mask,
            packets_received: 0,
            packets_fcs_error: 0,
            bytes_received: 0,
            include_fcs_errors,
        })
    }

    /// Get current Put position (where writer is)
    fn put_pos(&self) -> i64 {
        unsafe {
            let put_section = self.ring_ptr.add(PAGE_SIZE) as *const RingPut;
            // Use volatile read for cross-process visibility
            let put_ptr = ptr::addr_of!((*put_section).put);
            ptr::read_volatile(put_ptr as *const i64)
        }
    }

    /// Update Get position (where we've read to)
    fn update_get_pos(&mut self, pos: i64) {
        unsafe {
            let get_section = self.ring_ptr.add(2 * PAGE_SIZE) as *mut RingGet;
            // Use volatile write for cross-process visibility
            let get_ptr = ptr::addr_of_mut!((*get_section).get);
            ptr::write_volatile(get_ptr as *mut i64, pos);
            // Memory fence to ensure visibility
            std::sync::atomic::fence(Ordering::Release);
        }
    }

    /// Get packet at specified entry index
    fn get_packet(&self, entry_idx: i64) -> *const FmadioRingPacket {
        // Apply mask to get actual ring index
        let ring_idx = (entry_idx as u32 & self.mask) as usize;

        // Packets start after 3 pages of header (12KB)
        // Each packet entry is 12KB
        let packet_offset = HEADER_SIZE + (ring_idx * PACKET_ENTRY_SIZE);

        unsafe { self.ring_ptr.add(packet_offset) as *const FmadioRingPacket }
    }

    /// Try to receive next packet (non-blocking)
    ///
    /// Returns:
    /// - `Ok(Some(packet))` - Packet received
    /// - `Ok(None)` - No packet available (would block)
    /// - `Err(EndOfStream)` - End of stream reached
    pub fn recv_packet(&mut self) -> Result<Option<ReceivedPacket>, FmadioRingError> {
        let put_pos = self.put_pos();

        // Check if there's data available
        if self.read_pos == put_pos {
            return Ok(None);
        }

        // Get packet at current position
        let packet_ptr = self.get_packet(self.read_pos);

        // Read packet header fields using unaligned reads (packed struct)
        let (timestamp_ns, length_wire, length_capture, flag) = unsafe {
            (
                ptr::read_unaligned(ptr::addr_of!((*packet_ptr).ts)),
                ptr::read_unaligned(ptr::addr_of!((*packet_ptr).length_wire)),
                ptr::read_unaligned(ptr::addr_of!((*packet_ptr).length_capture)),
                ptr::read_unaligned(ptr::addr_of!((*packet_ptr).flag)),
            )
        };

        // Check for EOF
        if flag & flags::FMADRING_FLAG_EOF != 0 {
            return Err(FmadioRingError::EndOfStream);
        }

        // Check for FCS error
        let has_fcs_error = flag & flags::FMADRING_FLAG_FCSERR != 0;
        if has_fcs_error {
            self.packets_fcs_error += 1;
            if !self.include_fcs_errors {
                // Skip this packet
                self.read_pos += 1;
                self.update_get_pos(self.read_pos);
                return Ok(None);
            }
        }

        let len = (length_capture as usize).min(FMADRING_ENTRYSIZE);

        // Get pointer to payload data
        let data_ptr = unsafe { ptr::addr_of!((*packet_ptr).payload) as *const u8 };

        // Advance read position
        self.read_pos += 1;
        self.update_get_pos(self.read_pos);
        self.packets_received += 1;
        self.bytes_received += len as u64;

        Ok(Some(ReceivedPacket {
            timestamp_ns,
            data: data_ptr,
            len,
            wire_len: length_wire as usize,
            fcs_error: has_fcs_error,
        }))
    }

    /// Get number of packets available in ring
    pub fn packets_available(&self) -> u64 {
        let put_pos = self.put_pos();
        if put_pos >= self.read_pos {
            (put_pos - self.read_pos) as u64
        } else {
            0
        }
    }
}

impl Drop for FmadioRingCapture {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring_ptr as *mut libc::c_void, self.ring_size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_struct_size() {
        // Verify our packet struct is 12KB
        assert_eq!(std::mem::size_of::<FmadioRingPacket>(), PACKET_ENTRY_SIZE);
    }

    #[test]
    fn test_header_sizes() {
        assert_eq!(std::mem::size_of::<RingMetadata>(), PAGE_SIZE);
        assert_eq!(std::mem::size_of::<RingPut>(), PAGE_SIZE);
        assert_eq!(std::mem::size_of::<RingGet>(), PAGE_SIZE);
    }

    #[test]
    fn test_flags() {
        assert_eq!(flags::FMADRING_FLAG_EOF, 1 << 0);
        assert_eq!(flags::FMADRING_FLAG_FCSERR, 1 << 1);
    }
}
