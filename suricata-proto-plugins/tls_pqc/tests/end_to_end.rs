// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! End-to-end integration test: drive a synthetic TLS 1.3 handshake
//! (X25519MLKEM768 hybrid) through the plugin's FFI just as Suricata's
//! C callbacks would, then check the verdict via `rs_pqc_take_stats`.
//!
//! Verifies the whole path: handshake bytes → parser → state → verdict →
//! FFI stats struct, with no Suricata runtime needed.

use std::ffi::CString;

// The plugin's logger callbacks are normally defined in output.c. For the
// integration test we provide trivial Rust stubs so the linker is happy
// when the test binary pulls in the staticlib's extern declarations.
#[no_mangle]
pub extern "C" fn pqc_log_notice(_msg: *const std::os::raw::c_char) {}
#[no_mangle]
pub extern "C" fn pqc_log_error(_msg: *const std::os::raw::c_char) {}

use suricata_tls_pqc::{rs_pqc_deinit, rs_pqc_init, rs_pqc_observe, rs_pqc_take_stats, PqcStats};

fn null_term(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

fn ffi_init() {
    let cfg = CString::new(r#"{"tcp_enabled":true,"sample_rate":1,"max_flows":1000,"max_packets_per_dir":8}"#).unwrap();
    let rc = rs_pqc_init(cfg.as_ptr());
    assert_eq!(rc, 0, "rs_pqc_init failed");
}

// ── Synthetic handshake bytes ────────────────────────────────────────

fn synth_client_hello(groups: &[u16]) -> Vec<u8> {
    let mut hs = Vec::new();
    hs.extend_from_slice(&[0x03, 0x03]);       // legacy_version
    hs.extend_from_slice(&[0u8; 32]);          // random
    hs.push(0);                                // session_id len
    hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite
    hs.extend_from_slice(&[0x01, 0x00]);       // compression methods

    let mut sg = Vec::new();
    sg.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        sg.extend_from_slice(&g.to_be_bytes());
    }
    let mut ext = Vec::new();
    ext.extend_from_slice(&10u16.to_be_bytes());
    ext.extend_from_slice(&(sg.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sg);
    hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ext);

    let mut msg = Vec::new();
    msg.push(1); // ClientHello
    let n = hs.len() as u32;
    msg.push(((n >> 16) & 0xff) as u8);
    msg.push(((n >> 8) & 0xff) as u8);
    msg.push((n & 0xff) as u8);
    msg.extend_from_slice(&hs);

    let mut rec = Vec::new();
    rec.push(22); // handshake
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    rec.extend_from_slice(&msg);
    rec
}

fn synth_server_hello(chosen_group: u16) -> Vec<u8> {
    let mut hs = Vec::new();
    hs.extend_from_slice(&[0x03, 0x03]);
    hs.extend_from_slice(&[0u8; 32]);
    hs.push(0);
    hs.extend_from_slice(&[0x13, 0x01]);
    hs.push(0);

    let mut ext = Vec::new();
    // supported_versions = TLS 1.3
    ext.extend_from_slice(&43u16.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&0x0304u16.to_be_bytes());
    // key_share
    let mut ks = Vec::new();
    ks.extend_from_slice(&chosen_group.to_be_bytes());
    ks.extend_from_slice(&4u16.to_be_bytes());
    ks.extend_from_slice(&[0u8; 4]);
    ext.extend_from_slice(&51u16.to_be_bytes());
    ext.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ks);

    hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ext);

    let mut msg = Vec::new();
    msg.push(2); // ServerHello
    let n = hs.len() as u32;
    msg.push(((n >> 16) & 0xff) as u8);
    msg.push(((n >> 8) & 0xff) as u8);
    msg.push((n & 0xff) as u8);
    msg.extend_from_slice(&hs);

    let mut rec = Vec::new();
    rec.push(22);
    rec.extend_from_slice(&[0x03, 0x03]);
    rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    rec.extend_from_slice(&msg);
    rec
}

fn zero_stats() -> PqcStats {
    // SAFETY: PqcStats is repr(C) with only POD fields.
    unsafe { std::mem::zeroed() }
}

/// One combined test so the global state is consumed in a predictable order.
#[test]
fn end_to_end_handshake_flows() {
    ffi_init();

    // ── 1. NIST-compliant flow: PQ offered + PQ chosen ──────────────
    {
        let flow_id: u64 = 0xc0ffee01;
        let ch = synth_client_hello(&[4588, 29, 23, 24]);
        let sh = synth_server_hello(4588);
        rs_pqc_observe(flow_id, 0, ch.as_ptr(), ch.len() as u32);
        rs_pqc_observe(flow_id, 1, sh.as_ptr(), sh.len() as u32);
        let mut s = zero_stats();
        let rc = rs_pqc_take_stats(flow_id, &mut s as *mut _);
        assert_eq!(rc, 1, "compliant flow: no stats returned");
        assert_eq!(s.valid, 1);
        assert_eq!(s.client_offered_pqc, 1);
        assert_eq!(s.server_chosen_pqc, 1);
        assert_eq!(s.nist_compliant, 1);
        assert_eq!(s.has_server_chosen, 1);
        assert_eq!(s.server_chosen_group, 4588);
        assert_eq!(s.tls_version_be, 0x0304);
        assert_eq!(null_term(&s.server_chosen_group_name), "X25519MLKEM768");
        assert_eq!(null_term(&s.exposure_class), "compliant");
        assert_eq!(s.client_groups_len, 4);
        assert_eq!(&s.client_supported_groups[..4], &[4588u16, 29, 23, 24]);
    }

    // ── 2. Server-lagging flow ──────────────────────────────────────
    {
        let flow_id: u64 = 0xc0ffee02;
        let ch = synth_client_hello(&[4588, 29]);
        let sh = synth_server_hello(29);
        rs_pqc_observe(flow_id, 0, ch.as_ptr(), ch.len() as u32);
        rs_pqc_observe(flow_id, 1, sh.as_ptr(), sh.len() as u32);
        let mut s = zero_stats();
        assert_eq!(rs_pqc_take_stats(flow_id, &mut s as *mut _), 1);
        assert_eq!(s.client_offered_pqc, 1);
        assert_eq!(s.server_chosen_pqc, 0);
        assert_eq!(s.nist_compliant, 0);
        assert_eq!(s.server_chosen_group, 29);
        assert_eq!(null_term(&s.exposure_class), "server_lagging");
    }

    // ── 3. Client-lagging flow ──────────────────────────────────────
    {
        let flow_id: u64 = 0xc0ffee03;
        let ch = synth_client_hello(&[29, 23, 24]);
        let sh = synth_server_hello(29);
        rs_pqc_observe(flow_id, 0, ch.as_ptr(), ch.len() as u32);
        rs_pqc_observe(flow_id, 1, sh.as_ptr(), sh.len() as u32);
        let mut s = zero_stats();
        assert_eq!(rs_pqc_take_stats(flow_id, &mut s as *mut _), 1);
        assert_eq!(s.client_offered_pqc, 0);
        assert_eq!(s.server_chosen_pqc, 0);
        assert_eq!(s.nist_compliant, 0);
        assert_eq!(null_term(&s.exposure_class), "client_lagging");
    }

    // ── 4. Unknown flow returns 0 ───────────────────────────────────
    {
        let mut s = zero_stats();
        assert_eq!(rs_pqc_take_stats(0xdeadbeef, &mut s as *mut _), 0);
    }

    rs_pqc_deinit();
}
