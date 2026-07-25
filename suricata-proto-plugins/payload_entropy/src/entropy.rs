// Fidelis Farm & Technologies, LLC / Copyright 2025-2026
// SPDX-License-Identifier: GPL-2.0-only
//! Shannon entropy over a 256-symbol byte histogram.

/// Shannon entropy in bits/byte (0.0 .. 8.0).
///
/// Returns 0.0 for an empty histogram. The histogram counts must reflect the
/// actual sample size — `total` should equal the sum of `histogram` entries.
pub fn shannon_bits_per_byte(histogram: &[u16; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let inv_total = 1.0 / total as f64;
    let mut h = 0.0;
    for &count in histogram.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 * inv_total;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_zero() {
        let hist = [0u16; 256];
        assert_eq!(shannon_bits_per_byte(&hist, 0), 0.0);
    }

    #[test]
    fn single_symbol_zero_entropy() {
        let mut hist = [0u16; 256];
        hist[b'A' as usize] = 1000;
        let h = shannon_bits_per_byte(&hist, 1000);
        assert!(h.abs() < 1e-9, "expected ~0, got {h}");
    }

    #[test]
    fn uniform_eight_bits() {
        let mut hist = [0u16; 256];
        for c in hist.iter_mut() {
            *c = 32;
        }
        let total: u64 = 256 * 32;
        let h = shannon_bits_per_byte(&hist, total);
        // Uniform over 256 symbols → exactly 8 bits.
        assert!((h - 8.0).abs() < 1e-9, "expected 8.0, got {h}");
    }

    #[test]
    fn coin_flip_one_bit() {
        let mut hist = [0u16; 256];
        hist[0] = 500;
        hist[1] = 500;
        let h = shannon_bits_per_byte(&hist, 1000);
        assert!((h - 1.0).abs() < 1e-9, "expected 1.0, got {h}");
    }
}
