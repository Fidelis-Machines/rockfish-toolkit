// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! TLS handshake parser — just enough to extract the supported_groups
//! extension from a ClientHello and the chosen named_group from a TLS 1.3
//! ServerHello key_share extension.
//!
//! Designed to be safe on adversarial input — every length read is
//! length-checked against the remaining buffer; we never panic, we return
//! `None` and bail out on the first inconsistency.
//!
//! ## TLS record format we accept
//!
//! ```text
//!   uint8   content_type    (22 = handshake)
//!   uint16  legacy_version  (0x0301 for TLS 1.0 record)
//!   uint16  length          (record body length)
//!   <body...>
//! ```
//!
//! The handshake body inside a single record:
//!
//! ```text
//!   uint8   msg_type        (1 = ClientHello, 2 = ServerHello)
//!   uint24  length          (handshake message length)
//!   <hs_body...>
//! ```
//!
//! For ClientHello and ServerHello we then walk past the legacy fields and
//! extension list, looking for extension type 10 (supported_groups) and
//! 51 (key_share).
//!
//! We do NOT try to reassemble records that span multiple TCP segments;
//! ClientHello and the relevant ServerHello key_share both fit inside the
//! first record in practice. If a handshake spans segments we silently
//! return `None` for that side — the report falls back to "unknown".

const HS_CONTENT_TYPE: u8 = 22;
const HS_TYPE_CLIENT_HELLO: u8 = 1;
const HS_TYPE_SERVER_HELLO: u8 = 2;

const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_KEY_SHARE: u16 = 51;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// Outcome of parsing a single TCP segment that we believe contains
/// handshake bytes.
#[derive(Debug, Default, Clone)]
pub struct ParsedHandshake {
    /// Found a ClientHello; supported_groups list (codepoints).
    pub client_supported_groups: Option<Vec<u16>>,
    /// Found a ServerHello; the chosen named_group from key_share (TLS 1.3).
    /// `None` if the record was a TLS 1.2 ServerHello (no key_share).
    pub server_chosen_group: Option<u16>,
    /// Negotiated TLS version, when extractable (e.g. 0x0303 = TLS 1.2,
    /// 0x0304 = TLS 1.3). For TLS 1.3 ServerHellos the legacy_version
    /// field reads 0x0303 and the real version is in supported_versions.
    pub negotiated_version: Option<u16>,
}

impl ParsedHandshake {
    pub fn is_empty(&self) -> bool {
        self.client_supported_groups.is_none()
            && self.server_chosen_group.is_none()
            && self.negotiated_version.is_none()
    }
}

/// Try to parse `buf` as one or more contiguous TLS records. Stops at the
/// first error. Multiple ClientHello / ServerHello in one segment is highly
/// unusual but harmless — we just overwrite.
pub fn parse_segment(buf: &[u8]) -> ParsedHandshake {
    let mut out = ParsedHandshake::default();
    let mut cursor = 0;
    while cursor + 5 <= buf.len() {
        let content_type = buf[cursor];
        // legacy_version at cursor+1..=cursor+2
        let rec_len = u16::from_be_bytes([buf[cursor + 3], buf[cursor + 4]]) as usize;
        let body_start = cursor + 5;
        let body_end = body_start.checked_add(rec_len);
        let Some(body_end) = body_end else { break };
        if body_end > buf.len() {
            // Record extends beyond this segment; bail rather than misread.
            break;
        }
        if content_type == HS_CONTENT_TYPE {
            parse_handshake_record(&buf[body_start..body_end], &mut out);
        }
        cursor = body_end;
    }
    out
}

fn parse_handshake_record(body: &[u8], out: &mut ParsedHandshake) {
    let mut cursor = 0;
    while cursor + 4 <= body.len() {
        let msg_type = body[cursor];
        let msg_len = u24_be(&body[cursor + 1..cursor + 4]);
        let msg_start = cursor + 4;
        let msg_end = msg_start.checked_add(msg_len as usize);
        let Some(msg_end) = msg_end else { return };
        if msg_end > body.len() {
            return;
        }
        let msg_body = &body[msg_start..msg_end];
        match msg_type {
            HS_TYPE_CLIENT_HELLO => parse_client_hello(msg_body, out),
            HS_TYPE_SERVER_HELLO => parse_server_hello(msg_body, out),
            _ => {}
        }
        cursor = msg_end;
    }
}

fn parse_client_hello(buf: &[u8], out: &mut ParsedHandshake) {
    // ClientHello body layout (TLS 1.2/1.3, RFC 8446 §4.1.2):
    //   uint16    legacy_version (2)
    //   opaque    random[32]
    //   opaque    legacy_session_id<0..32>      (1B len + payload)
    //   CipherSuite cipher_suites<2..2^16-2>    (2B len + N×2)
    //   opaque    compression_methods<1..2^8-1> (1B len + payload)
    //   Extension extensions<8..2^16-1>         (2B len + extension blob)
    if buf.len() < 2 + 32 + 1 {
        return;
    }
    let mut p = 0;
    p += 2; // legacy_version
    p += 32; // random
    let Some(p1) = skip_u8_vec(buf, p) else { return }; // session_id
    let Some(p2) = skip_u16_vec(buf, p1) else { return }; // cipher_suites
    let Some(p3) = skip_u8_vec(buf, p2) else { return }; // compression_methods
    let exts = match read_u16_vec(buf, p3) {
        Some(v) => v,
        None => return,
    };
    walk_extensions(exts, |ext_type, ext_body| {
        if ext_type == EXT_SUPPORTED_GROUPS {
            if let Some(list) = parse_supported_groups_extension(ext_body) {
                out.client_supported_groups = Some(list);
            }
        }
    });
}

fn parse_server_hello(buf: &[u8], out: &mut ParsedHandshake) {
    // ServerHello body layout (RFC 8446 §4.1.3 for TLS 1.3; same prelude
    // for 1.2 with extensions only present from 1.2 onward):
    //   uint16   legacy_version (2)
    //   opaque   random[32]
    //   opaque   legacy_session_id_echo<0..32>  (1B len + payload)
    //   CipherSuite  cipher_suite (2)
    //   uint8    legacy_compression_method (1)
    //   Extension extensions<6..2^16-1>          (2B len + extension blob)
    if buf.len() < 2 + 32 + 1 + 2 + 1 {
        return;
    }
    let legacy_version = u16::from_be_bytes([buf[0], buf[1]]);
    out.negotiated_version = Some(legacy_version);
    let mut p = 2 + 32;
    let Some(p1) = skip_u8_vec(buf, p) else { return };
    p = p1;
    p += 2; // cipher_suite
    p += 1; // legacy_compression_method
    if p > buf.len() {
        return;
    }
    // Extensions are optional in TLS 1.0/1.1 ServerHello; assume present
    // when buffer has space remaining.
    let exts = match read_u16_vec(buf, p) {
        Some(v) => v,
        None => return,
    };
    walk_extensions(exts, |ext_type, ext_body| {
        match ext_type {
            EXT_KEY_SHARE => {
                if let Some(group) = parse_server_key_share(ext_body) {
                    out.server_chosen_group = Some(group);
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                // Server's supported_versions in a ServerHello is exactly
                // 2 bytes: the chosen TLS version. RFC 8446 §4.2.1.
                if ext_body.len() == 2 {
                    out.negotiated_version =
                        Some(u16::from_be_bytes([ext_body[0], ext_body[1]]));
                }
            }
            _ => {}
        }
    });
}

/// supported_groups extension body (RFC 8422 §5.1.1 / RFC 8446 §4.2.7):
///   NamedGroup named_group_list<2..2^16-1>   (2B len + N×2)
fn parse_supported_groups_extension(body: &[u8]) -> Option<Vec<u16>> {
    if body.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let list = body.get(2..2 + list_len)?;
    if list.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(list.len() / 2);
    let mut i = 0;
    while i + 2 <= list.len() {
        out.push(u16::from_be_bytes([list[i], list[i + 1]]));
        i += 2;
    }
    Some(out)
}

/// ServerHello key_share extension body (RFC 8446 §4.2.8):
///   KeyShareEntry server_share { NamedGroup group; opaque key_exchange<1..2^16-1>; }
/// A HelloRetryRequest variant carries only `NamedGroup selected_group` (no key).
/// Both start with a 2-byte NamedGroup, so we just read the first two bytes.
fn parse_server_key_share(body: &[u8]) -> Option<u16> {
    if body.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([body[0], body[1]]))
}

/// Helper: walk an extension blob `<u16_len> [<u16 type><u16 len><body...>]*`.
fn walk_extensions<F: FnMut(u16, &[u8])>(blob: &[u8], mut visit: F) {
    let mut cursor = 0;
    while cursor + 4 <= blob.len() {
        let ext_type = u16::from_be_bytes([blob[cursor], blob[cursor + 1]]);
        let ext_len =
            u16::from_be_bytes([blob[cursor + 2], blob[cursor + 3]]) as usize;
        let body_start = cursor + 4;
        let body_end = body_start.checked_add(ext_len);
        let Some(body_end) = body_end else { return };
        if body_end > blob.len() {
            return;
        }
        visit(ext_type, &blob[body_start..body_end]);
        cursor = body_end;
    }
}

// ── tiny bounds-checked length-prefix helpers ───────────────────────────

fn u24_be(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

fn skip_u8_vec(buf: &[u8], at: usize) -> Option<usize> {
    let len = *buf.get(at)? as usize;
    at.checked_add(1)?.checked_add(len).filter(|&n| n <= buf.len())
}

fn skip_u16_vec(buf: &[u8], at: usize) -> Option<usize> {
    let lo = buf.get(at).copied()? as usize;
    let hi = buf.get(at + 1).copied()? as usize;
    let len = (lo << 8) | hi;
    at.checked_add(2)?.checked_add(len).filter(|&n| n <= buf.len())
}

fn read_u16_vec(buf: &[u8], at: usize) -> Option<&[u8]> {
    let lo = buf.get(at).copied()? as usize;
    let hi = buf.get(at + 1).copied()? as usize;
    let len = (lo << 8) | hi;
    buf.get(at + 2..at + 2 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS record wrapping a ClientHello whose supported_groups
    /// extension lists [X25519MLKEM768, X25519, secp256r1].
    fn synth_client_hello_with_pq() -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(0x03);
        hs.push(0x03); // legacy_version = TLS 1.2
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id len = 0
        // cipher_suites
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 suite: TLS_AES_128_GCM_SHA256
        hs.extend_from_slice(&[0x01, 0x00]); // compression_methods: [null]

        // ── extensions ──
        let mut ext_blob = Vec::new();
        // supported_groups (type 10): list is [4588, 29, 23]
        let sg_list: [u16; 3] = [4588, 29, 23];
        let mut sg = Vec::new();
        sg.extend_from_slice(&((sg_list.len() * 2) as u16).to_be_bytes());
        for g in sg_list {
            sg.extend_from_slice(&g.to_be_bytes());
        }
        ext_blob.extend_from_slice(&10u16.to_be_bytes());
        ext_blob.extend_from_slice(&(sg.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(&sg);

        hs.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext_blob);

        // Wrap in handshake message header (type 1, 24-bit length)
        let mut msg = Vec::new();
        msg.push(HS_TYPE_CLIENT_HELLO);
        let mlen = hs.len() as u32;
        msg.push(((mlen >> 16) & 0xff) as u8);
        msg.push(((mlen >> 8) & 0xff) as u8);
        msg.push((mlen & 0xff) as u8);
        msg.extend_from_slice(&hs);

        // Wrap in TLS record (content_type 22, length)
        let mut rec = Vec::new();
        rec.push(HS_CONTENT_TYPE);
        rec.extend_from_slice(&[0x03, 0x01]); // legacy_version
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    /// Build a TLS 1.3 ServerHello with key_share selecting X25519MLKEM768
    /// and supported_versions naming TLS 1.3.
    fn synth_server_hello_pq() -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // legacy_version (1.2)
        hs.extend_from_slice(&[0u8; 32]);    // random
        hs.push(0);                          // session_id_echo len
        hs.extend_from_slice(&[0x13, 0x01]); // cipher_suite
        hs.push(0);                          // legacy_compression_method

        // extensions
        let mut ext_blob = Vec::new();
        // supported_versions = TLS 1.3 (server form: just 2 bytes)
        ext_blob.extend_from_slice(&43u16.to_be_bytes());
        ext_blob.extend_from_slice(&2u16.to_be_bytes());
        ext_blob.extend_from_slice(&0x0304u16.to_be_bytes());
        // key_share: NamedGroup = 4588 (X25519MLKEM768), key_exchange = 4 bytes of zeros
        let mut ks = Vec::new();
        ks.extend_from_slice(&4588u16.to_be_bytes());
        ks.extend_from_slice(&4u16.to_be_bytes()); // key_exchange len
        ks.extend_from_slice(&[0u8; 4]);
        ext_blob.extend_from_slice(&51u16.to_be_bytes());
        ext_blob.extend_from_slice(&(ks.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(&ks);

        hs.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext_blob);

        let mut msg = Vec::new();
        msg.push(HS_TYPE_SERVER_HELLO);
        let mlen = hs.len() as u32;
        msg.push(((mlen >> 16) & 0xff) as u8);
        msg.push(((mlen >> 8) & 0xff) as u8);
        msg.push((mlen & 0xff) as u8);
        msg.extend_from_slice(&hs);

        let mut rec = Vec::new();
        rec.push(HS_CONTENT_TYPE);
        rec.extend_from_slice(&[0x03, 0x03]);
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    #[test]
    fn parses_client_hello_supported_groups() {
        let buf = synth_client_hello_with_pq();
        let parsed = parse_segment(&buf);
        assert_eq!(parsed.client_supported_groups.as_deref(), Some(&[4588u16, 29, 23][..]));
        assert_eq!(parsed.server_chosen_group, None);
    }

    #[test]
    fn parses_server_hello_key_share() {
        let buf = synth_server_hello_pq();
        let parsed = parse_segment(&buf);
        assert_eq!(parsed.server_chosen_group, Some(4588));
        assert_eq!(parsed.negotiated_version, Some(0x0304));
    }

    #[test]
    fn ignores_non_handshake_records() {
        let buf = vec![23u8, 0x03, 0x03, 0x00, 0x00]; // application_data, empty
        let parsed = parse_segment(&buf);
        assert!(parsed.is_empty());
    }

    #[test]
    fn truncated_does_not_panic() {
        let buf = synth_client_hello_with_pq();
        for cut in 0..buf.len() {
            let _ = parse_segment(&buf[..cut]); // must not panic on any prefix
        }
    }
}
