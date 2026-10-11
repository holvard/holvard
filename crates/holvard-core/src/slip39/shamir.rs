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

/// One share: its index and its value, wiped when dropped.
pub(crate) type IndexedShare = (u8, Zeroizing<Vec<u8>>);

/// Smallest secret SLIP-39 allows: 128 bits.
const MIN_SECRET_LENGTH: usize = 16;
/// Most shares a set (or group) can have: indices are 4 bits.
const MAX_SHARE_COUNT: u8 = 16;

/// `count` bytes from the operating system's random generator.
fn random_bytes(count: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(vec![0u8; count]);
    getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
    Ok(bytes)
}

/// `SplitSecret` from SLIP-39: `count` shares with indices 0 to count - 1,
/// any `threshold` of which recover `secret`.
///
/// In plain words: the secret is placed at index 255 and a digest of it at
/// index 254 of a polynomial whose other `threshold - 2` points are random
/// (at indices 0 to threshold - 3). Each share is the polynomial's value at
/// its own index. Any `threshold` shares pin the polynomial down; fewer
/// leave the secret completely undetermined.
pub(crate) fn split_secret(
    threshold: u8,
    count: u8,
    secret: &[u8],
) -> Result<Vec<IndexedShare>, Error> {
    if threshold == 0 || threshold > count || count > MAX_SHARE_COUNT {
        return Err(Error::InvalidParameters);
    }
    if secret.len() < MIN_SECRET_LENGTH || !secret.len().is_multiple_of(2) {
        return Err(Error::InvalidSecretLength);
    }
    if threshold == 1 {
        return Ok((0..count)
            .map(|i| (i, Zeroizing::new(secret.to_vec())))
            .collect());
    }

    // Digest D = first 4 bytes of HMAC-SHA256(key = R, message = secret),
    // followed by R, a random string of the remaining length.
    let random_part = random_bytes(
        secret
            .len()
            .checked_sub(DIGEST_LENGTH)
            .ok_or(Error::InvalidLength)?,
    )?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&random_part)
        .map_err(|_| Error::InvalidLength)?;
    mac.update(secret);
    // The full tag is wiped too, though only 4 bytes are used.
    let tag: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());
    let mut digest = Zeroizing::new(Vec::with_capacity(secret.len()));
    digest.extend_from_slice(tag.get(..DIGEST_LENGTH).ok_or(Error::InvalidLength)?);
    digest.extend_from_slice(&random_part);

    // The first threshold - 2 shares are random and returned as they are.
    let random_count = threshold.saturating_sub(2);
    let mut shares = Vec::with_capacity(usize::from(count));
    for index in 0..random_count {
        shares.push((index, random_bytes(secret.len())?));
    }

    // The rest are computed from the polynomial through the random shares,
    // the digest and the secret.
    let mut points: Vec<(u8, &[u8])> = shares.iter().map(|(i, v)| (*i, v.as_slice())).collect();
    points.push((DIGEST_INDEX, &digest));
    points.push((SECRET_INDEX, secret));
    let mut computed = Vec::with_capacity(usize::from(count.saturating_sub(random_count)));
    for index in random_count..count {
        computed.push((index, interpolate(index, &points)?));
    }
    shares.extend(computed);
    Ok(shares)
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
    // The tag is computed into a wiped buffer (the library's own verify
    // leaves its copy unwiped), and its first 4 bytes are compared with the
    // stored digest in constant time.
    let tag: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());
    let expected = tag.get(..DIGEST_LENGTH).ok_or(Error::InvalidLength)?;
    if digest.len() != DIGEST_LENGTH {
        return Err(Error::InvalidLength);
    }
    let difference = expected
        .iter()
        .zip(digest.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if difference != 0 {
        return Err(Error::DigestMismatch);
    }
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

    /// Every way to choose `k` of the items, in order.
    fn choose<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
        match (k, items.split_first()) {
            (0, _) => vec![Vec::new()],
            (_, None) => Vec::new(),
            (_, Some((first, rest))) => {
                let mut with_first: Vec<Vec<T>> = choose(rest, k.saturating_sub(1))
                    .into_iter()
                    .map(|mut c| {
                        c.insert(0, first.clone());
                        c
                    })
                    .collect();
                with_first.extend(choose(rest, k));
                with_first
            }
        }
    }

    const SECRET_16: &str = "bb54aac4b89dc868ba37d9cc21b2cece";

    #[test]
    fn every_threshold_sized_subset_recovers_the_secret() -> Result<(), Error> {
        let secret = bytes(SECRET_16);
        for (threshold, count) in [(2u8, 3u8), (3, 5), (5, 5), (2, 16)] {
            let shares = split_secret(threshold, count, &secret)?;
            assert_eq!(shares.len(), usize::from(count));
            for subset in choose(&shares, usize::from(threshold)) {
                let points: Vec<(u8, &[u8])> =
                    subset.iter().map(|(i, v)| (*i, v.as_slice())).collect();
                assert_eq!(
                    *recover_secret(threshold, &points)?,
                    secret,
                    "{threshold}-of-{count}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn shares_have_indices_0_to_count_minus_1() -> Result<(), Error> {
        let indices: Vec<u8> = split_secret(3, 5, &bytes(SECRET_16))?
            .iter()
            .map(|(i, _)| *i)
            .collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn threshold_one_shares_are_copies_of_the_secret() -> Result<(), Error> {
        let secret = bytes(SECRET_16);
        for (_, value) in split_secret(1, 3, &secret)? {
            assert_eq!(*value, secret);
        }
        Ok(())
    }

    #[test]
    fn two_splits_of_one_secret_differ() -> Result<(), Error> {
        let secret = bytes(SECRET_16);
        let a = split_secret(2, 3, &secret)?;
        let b = split_secret(2, 3, &secret)?;
        assert!(a.iter().zip(b.iter()).any(|((_, x), (_, y))| x != y));
        Ok(())
    }

    #[test]
    fn invalid_split_settings_are_refused() {
        let secret = bytes(SECRET_16);
        assert_eq!(
            split_secret(0, 3, &secret).map(|_| ()),
            Err(Error::InvalidParameters)
        );
        assert_eq!(
            split_secret(4, 3, &secret).map(|_| ()),
            Err(Error::InvalidParameters)
        );
        assert_eq!(
            split_secret(2, 17, &secret).map(|_| ()),
            Err(Error::InvalidParameters)
        );
        let short = secret.get(..15).unwrap_or_default();
        assert_eq!(
            split_secret(2, 3, short).map(|_| ()),
            Err(Error::InvalidSecretLength)
        );
        assert_eq!(
            split_secret(2, 3, &[0u8; 17]).map(|_| ()),
            Err(Error::InvalidSecretLength)
        );
    }

    // SHA-256's internal state, and with it HMAC-SHA256's keyed state, is
    // wiped on drop only with the `zeroize` features of hmac and sha2
    // (crates/holvard-core/Cargo.toml). HMAC-SHA256 is two SHA-256 cores
    // (inner and outer pad) plus a block buffer, each wiping itself; `Hmac`
    // does not carry the ZeroizeOnDrop marker, but `Sha256` does, and the
    // digest crate grants it only when both its core and its buffer wipe
    // on drop. This fails to compile if the features are ever lost.
    #[test]
    fn sha256_state_is_wiped_on_drop() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<Sha256>();
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
