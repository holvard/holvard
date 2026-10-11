// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Shamir's secret sharing over GF(256), byte by byte, as SLIP-39 uses it:
//! interpolation and `RecoverSecret` with its digest check.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::Error;
use super::gf256::{inv, mul};

/// Index at which the secret sits on the polynomial.
pub(crate) const SECRET_INDEX: u8 = 255;
/// Index at which the digest sits on the polynomial.
pub(crate) const DIGEST_INDEX: u8 = 254;

/// Bytes of the digest stored in front of the random part.
const DIGEST_LENGTH: usize = 4;

/// Evaluates at `x` the polynomial through `points` (index, value bytes),
/// separately for each byte position, with the Lagrange formula from
/// "Polynomial interpolation". In GF(256) subtraction is XOR.
pub(crate) fn interpolate(x: u8, points: &[(u8, &[u8])]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length = points
        .first()
        .map(|(_, value)| value.len())
        .ok_or(Error::InvalidLength)?;
    if points.iter().any(|(_, value)| value.len() != length) {
        return Err(Error::InvalidLength);
    }
    for (i, (xi, _)) in points.iter().enumerate() {
        if points
            .iter()
            .skip(i.saturating_add(1))
            .any(|(xj, _)| xj == xi)
        {
            return Err(Error::DuplicateShareIndex);
        }
    }
    // Asking for a point we already have returns it unchanged.
    if let Some((_, value)) = points.iter().find(|(xi, _)| *xi == x) {
        return Ok(Zeroizing::new(value.to_vec()));
    }

    let mut result = Zeroizing::new(vec![0u8; length]);
    for (xi, yi) in points {
        // Lagrange basis: product over j != i of (x - xj) / (xi - xj).
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (xj, _) in points.iter().filter(|(xj, _)| xj != xi) {
            numerator = mul(numerator, x ^ xj);
            denominator = mul(denominator, xi ^ xj);
        }
        let basis = mul(numerator, inv(denominator));
        for (out, y) in result.iter_mut().zip(yi.iter()) {
            *out ^= mul(basis, *y);
        }
    }
    Ok(result)
}

/// `RecoverSecret` from SLIP-39: with threshold 1 the single share is the
/// secret; otherwise interpolate the secret at index 255 and the digest at
/// index 254, and accept the secret only if the digest matches.
///
/// The digest is 4 bytes of HMAC-SHA256(key = R, message = secret), stored
/// in front of R, a random string. A wrong combination of shares gives a
/// random-looking "secret" whose digest almost surely does not match.
pub(crate) fn recover_secret(
    threshold: u8,
    points: &[(u8, &[u8])],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Callers pass exactly `threshold` points; this guards the maths
    // against a caller bug.
    if points.len() != usize::from(threshold) {
        return Err(Error::WrongNumberOfShares);
    }
    if threshold == 1 {
        let (_, value) = points.first().ok_or(Error::WrongNumberOfShares)?;
        return Ok(Zeroizing::new(value.to_vec()));
    }
    let secret = interpolate(SECRET_INDEX, points)?;
    let digest_share = interpolate(DIGEST_INDEX, points)?;
    let (digest, random_part) = digest_share
        .split_at_checked(DIGEST_LENGTH)
        .ok_or(Error::InvalidLength)?;

    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(random_part).map_err(|_| Error::InvalidLength)?;
    mac.update(&secret);
    // Compares the first 4 bytes in constant time.
    mac.verify_truncated_left(digest)
        .map_err(|_| Error::DigestMismatch)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .filter_map(|i| hex.get(i..i.wrapping_add(2)))
            .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
            .collect()
    }

    // f(x) = 0x2a + 0x07 x. By hand: f(1) = 0x2a ^ 0x07 = 0x2d,
    // f(2) = 0x2a ^ (0x07 * 2) = 0x2a ^ 0x0e = 0x24. So f(0) = 0x2a.
    #[test]
    fn interpolates_a_line_through_two_points() -> Result<(), Error> {
        let at_zero = interpolate(0, &[(1, &[0x2d]), (2, &[0x24])])?;
        assert_eq!(*at_zero, vec![0x2a]);
        Ok(())
    }

    #[test]
    fn interpolating_at_a_known_point_returns_that_point() -> Result<(), Error> {
        let at_one = interpolate(1, &[(1, &[0x2d]), (2, &[0x24])])?;
        assert_eq!(*at_one, vec![0x2d]);
        Ok(())
    }

    // Vector 4's two member shares; expected value from Trezor's reference
    // shamir_mnemonic.shamir._recover_secret.
    const SHARE_X2: &str = "08fb14b66e692e25dfe2edf53289ed62";
    const SHARE_X0: &str = "06ab48fef4bedc8ce58baeef0a73f76e";

    #[test]
    fn recovers_vector_4_group_secret() -> Result<(), Error> {
        let (a, b) = (bytes(SHARE_X2), bytes(SHARE_X0));
        let secret = recover_secret(2, &[(2, &a), (0, &b)])?;
        assert_eq!(*secret, bytes("cdc017fddc829e791b1371780be0605a"));
        Ok(())
    }

    #[test]
    fn a_changed_share_fails_the_digest_check() {
        let (mut a, b) = (bytes(SHARE_X2), bytes(SHARE_X0));
        if let Some(first) = a.first_mut() {
            *first ^= 0x01;
        }
        assert_eq!(
            recover_secret(2, &[(2, &a), (0, &b)]),
            Err(Error::DigestMismatch)
        );
    }

    #[test]
    fn threshold_one_returns_the_share_itself() -> Result<(), Error> {
        let a = bytes(SHARE_X2);
        assert_eq!(*recover_secret(1, &[(0, &a)])?, a);
        Ok(())
    }

    // RecoverSecret is only ever called with exactly `threshold` points;
    // anything else is a caller bug that must not reach the maths.
    #[test]
    fn recovering_with_the_wrong_number_of_points_is_refused() {
        let (a, b) = (bytes(SHARE_X2), bytes(SHARE_X0));
        assert_eq!(
            recover_secret(2, &[(2, &a)]),
            Err(Error::WrongNumberOfShares)
        );
        assert_eq!(
            recover_secret(1, &[(2, &a), (0, &b)]),
            Err(Error::WrongNumberOfShares)
        );
    }

    // Two points with the same index would divide by zero in the Lagrange
    // formula; that must be an error, not a wrong answer.
    #[test]
    fn two_shares_with_the_same_index_are_rejected() {
        assert_eq!(
            interpolate(0, &[(1, &[0x2d]), (1, &[0x24])]),
            Err(Error::DuplicateShareIndex)
        );
    }

    #[test]
    fn shares_of_different_lengths_are_rejected() {
        assert_eq!(
            interpolate(0, &[(1, &[0x2d, 0x00]), (2, &[0x24])]),
            Err(Error::InvalidLength)
        );
    }
}
