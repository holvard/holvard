// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Arithmetic in GF(256), the field SLIP-39 shares bytes over.
//!
//! The field is the one AES uses: polynomials over GF(2) modulo
//! x^8 + x^4 + x^3 + x + 1. Adding two elements is XOR. Both functions here
//! run in the same time whatever the inputs, with no lookup tables, so the
//! secret bytes they handle cannot leak through timing or the CPU cache.

/// Multiplies two field elements.
///
/// Schoolbook multiplication, one bit of `b` per step: add `a` when the bit
/// is set, then multiply `a` by x (shift left, reducing by 0x1b when the
/// top bit falls off). Masks replace branches so timing does not depend
/// on the values.
pub(crate) fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut product = 0u8;
    for _ in 0..8 {
        let take = 0u8.wrapping_sub(b & 1); // 0xff if the low bit of b is set
        product ^= a & take;
        let reduce = 0u8.wrapping_sub(a.wrapping_shr(7)); // 0xff if a overflows
        a = a.wrapping_shl(1) ^ (0x1b & reduce);
        b = b.wrapping_shr(1);
    }
    product
}

/// Returns the multiplicative inverse of a non-zero field element.
///
/// Every non-zero element satisfies a^255 = 1, so a^254 is its inverse.
/// 254 = 2 + 4 + 8 + … + 128, so the loop multiplies the squares
/// a^2, a^4, …, a^128 together. The inverse of 0 comes out as 0; callers
/// never divide by zero because share indices are distinct.
pub(crate) fn inv(a: u8) -> u8 {
    let mut power = a;
    let mut result = 1u8;
    for _ in 0..7 {
        power = mul(power, power);
        result = mul(result, power);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values from FIPS-197 (AES), which uses the same field:
    // section 4.2 and its worked examples.
    #[test]
    fn multiplication_matches_fips_197() {
        assert_eq!(mul(0x57, 0x83), 0xc1);
        assert_eq!(mul(0x57, 0x13), 0xfe);
        assert_eq!(mul(0x57, 0x02), 0xae);
        assert_eq!(mul(0x57, 0x01), 0x57);
        assert_eq!(mul(0x57, 0x00), 0x00);
    }

    #[test]
    fn inverse_of_0x53_is_0xca() {
        assert_eq!(inv(0x53), 0xca);
        assert_eq!(inv(0xca), 0x53);
        assert_eq!(inv(0x01), 0x01);
    }

    #[test]
    fn every_non_zero_element_times_its_inverse_is_one() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a = {a:#04x}");
        }
    }
}
