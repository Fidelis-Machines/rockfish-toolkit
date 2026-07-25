// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! TLS supported_groups / key_share codepoint classification.
//!
//! Source: IANA TLS Supported Groups registry plus current IETF drafts
//! (draft-ietf-tls-mlkem, draft-kwiatkowski-tls-ecdhe-mlkem) and NIST IR 8547
//! transition guidance (2024).
//!
//! Classification:
//!   * `GroupClass::Pq`            — NIST-finalized PQ KEM, hybrid or standalone
//!   * `GroupClass::PqDraft`       — pre-standardization PQ hybrids in use
//!                                   on the wire (Chrome/Cloudflare 2023-24)
//!   * `GroupClass::ClassicalEcdh` — elliptic-curve Diffie-Hellman (vulnerable
//!                                   to "harvest now, decrypt later")
//!   * `GroupClass::ClassicalFfdhe`— finite-field DH (also vulnerable)
//!   * `GroupClass::Grease`        — GREASE codepoints (RFC 8701) — ignored
//!   * `GroupClass::Unknown`       — outside any known class

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupClass {
    Pq,
    PqDraft,
    ClassicalEcdh,
    ClassicalFfdhe,
    Grease,
    Unknown,
}

impl GroupClass {
    /// True if the group provides post-quantum security (standardized or
    /// pre-standard hybrid). These satisfy NIST IR 8547 transition guidance.
    pub fn is_pq(self) -> bool {
        matches!(self, GroupClass::Pq | GroupClass::PqDraft)
    }

    pub fn name(self) -> &'static str {
        match self {
            GroupClass::Pq => "pq",
            GroupClass::PqDraft => "pq_draft",
            GroupClass::ClassicalEcdh => "classical_ecdh",
            GroupClass::ClassicalFfdhe => "classical_ffdhe",
            GroupClass::Grease => "grease",
            GroupClass::Unknown => "unknown",
        }
    }
}

/// Human-readable name for a known group codepoint.
pub fn group_name(codepoint: u16) -> &'static str {
    match codepoint {
        // ── NIST-finalized post-quantum (ML-KEM = FIPS 203) ─────────────
        4587 => "ML-KEM-512",
        4588 => "X25519MLKEM768",
        4589 => "ML-KEM-1024",

        // ── Pre-standardization Kyber draft hybrids (still seen on wire) ─
        25497 => "X25519Kyber768Draft00",
        25498 => "SecP256r1Kyber768Draft00",

        // ── Classical ECDHE ─────────────────────────────────────────────
        23 => "secp256r1",
        24 => "secp384r1",
        25 => "secp521r1",
        29 => "X25519",
        30 => "X448",

        // ── Legacy / brainpool (still used in EU government PKI) ────────
        26 => "brainpoolP256r1",
        27 => "brainpoolP384r1",
        28 => "brainpoolP512r1",

        // ── Finite-field DH (RFC 7919) ──────────────────────────────────
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        258 => "ffdhe4096",
        259 => "ffdhe6144",
        260 => "ffdhe8192",

        _ => "other",
    }
}

/// Classify a single codepoint.
pub fn classify(codepoint: u16) -> GroupClass {
    // GREASE: 0x?A?A pattern per RFC 8701. Suricata's parser filters these
    // before they reach JA3; we replicate that here so they don't show up
    // as "unknown" in the report.
    if is_grease(codepoint) {
        return GroupClass::Grease;
    }
    match codepoint {
        4587 | 4588 | 4589 => GroupClass::Pq,
        25497 | 25498 => GroupClass::PqDraft,
        23 | 24 | 25 | 29 | 30 | 26 | 27 | 28 => GroupClass::ClassicalEcdh,
        256..=260 => GroupClass::ClassicalFfdhe,
        _ => GroupClass::Unknown,
    }
}

/// RFC 8701 GREASE codepoint detection: 16-bit values of form 0x?A?A where
/// both bytes are the same and the low nibble of each is 0xA.
pub fn is_grease(codepoint: u16) -> bool {
    let lo = (codepoint & 0xff) as u8;
    let hi = (codepoint >> 8) as u8;
    lo == hi && (lo & 0x0f) == 0x0a
}

/// True if any non-GREASE codepoint in `groups` is post-quantum.
pub fn any_pq(groups: &[u16]) -> bool {
    groups.iter().any(|&g| classify(g).is_pq())
}

/// Reduce a list of offered groups to a single coarse class for reporting.
/// Returns the "strongest" present (Pq > PqDraft > ClassicalEcdh > ClassicalFfdhe).
pub fn dominant_class(groups: &[u16]) -> GroupClass {
    let mut have_pq = false;
    let mut have_pq_draft = false;
    let mut have_ecdh = false;
    let mut have_ffdhe = false;
    for &g in groups {
        match classify(g) {
            GroupClass::Pq => have_pq = true,
            GroupClass::PqDraft => have_pq_draft = true,
            GroupClass::ClassicalEcdh => have_ecdh = true,
            GroupClass::ClassicalFfdhe => have_ffdhe = true,
            _ => {}
        }
    }
    if have_pq { return GroupClass::Pq; }
    if have_pq_draft { return GroupClass::PqDraft; }
    if have_ecdh { return GroupClass::ClassicalEcdh; }
    if have_ffdhe { return GroupClass::ClassicalFfdhe; }
    GroupClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_groups() {
        assert_eq!(classify(4588), GroupClass::Pq);       // X25519MLKEM768
        assert_eq!(classify(4587), GroupClass::Pq);       // ML-KEM-512
        assert_eq!(classify(25497), GroupClass::PqDraft); // X25519Kyber768Draft00
    }

    #[test]
    fn classical_groups() {
        assert_eq!(classify(29), GroupClass::ClassicalEcdh);  // X25519
        assert_eq!(classify(23), GroupClass::ClassicalEcdh);  // secp256r1
        assert_eq!(classify(256), GroupClass::ClassicalFfdhe);// ffdhe2048
    }

    #[test]
    fn grease_detected() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(is_grease(0x3a3a));
        assert!(!is_grease(0x1d));     // X25519
        assert!(!is_grease(0x11ec));   // X25519MLKEM768
    }

    #[test]
    fn any_pq_helper() {
        assert!(any_pq(&[4588, 29, 23, 24]));     // PQ + classical mix
        assert!(!any_pq(&[29, 23, 24]));          // classical only
        assert!(!any_pq(&[0x0a0a, 29]));          // GREASE + classical
        assert!(any_pq(&[25497, 29]));            // draft PQ + classical
    }

    #[test]
    fn dominant_picks_strongest() {
        assert_eq!(dominant_class(&[4588, 29]), GroupClass::Pq);
        assert_eq!(dominant_class(&[25497, 29]), GroupClass::PqDraft);
        assert_eq!(dominant_class(&[29, 23]), GroupClass::ClassicalEcdh);
        assert_eq!(dominant_class(&[256]), GroupClass::ClassicalFfdhe);
    }
}
