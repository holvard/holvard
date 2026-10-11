// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SLIP-39's encryption of the master secret: a four-round Feistel network
//! with PBKDF2-HMAC-SHA256 as the round function.
//!
//! In plain words: the secret is cut into a left and a right half. Each
//! round mixes one half into the other through PBKDF2, keyed by the round
//! number and the passphrase. Four rounds make a reversible scramble;
//! decryption runs the same rounds in reverse order. Holvard uses the empty
//! passphrase, so this layer adds no secrecy for Holvard; it is still run
//! because SLIP-39 cards always carry the encrypted form.

use sha2::Sha256;
use zeroize::Zeroizing;

use super::Error;

/// PBKDF2 iterations per round at exponent 0. Four rounds make the
/// 10000 x 2^e total from the spec.
const BASE_ITERATIONS: u32 = 2500;

/// Round function `F(i, R)` from "Encryption of the master secret":
/// PBKDF2-HMAC-SHA256 with password `i || passphrase` and salt
/// `salt_prefix || R`, producing as many bytes as one half.
fn round_function(
    round: u8,
    passphrase: &[u8],
    iterations: u32,
    salt_prefix: &[u8],
    half: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut password = Zeroizing::new(Vec::with_capacity(passphrase.len().saturating_add(1)));
    password.push(round);
    password.extend_from_slice(passphrase);
    // The salt contains the half R, which is as secret as the master
    // secret when the passphrase is empty, so it is wiped too.
    let mut salt = Zeroizing::new(Vec::with_capacity(
        salt_prefix.len().saturating_add(half.len()),
    ));
    salt.extend_from_slice(salt_prefix);
    salt.extend_from_slice(half);
    let mut out = Zeroizing::new(vec![0u8; half.len()]);
    pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salt, iterations, &mut out);
    out
}

/// Turns an encrypted master secret back into the master secret, following
/// "Decryption of the master secret".
pub(crate) fn decrypt(
    encrypted: &[u8],
    passphrase: &[u8],
    iteration_exponent: u8,
    identifier: u16,
    extendable: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !encrypted.len().is_multiple_of(2) {
        return Err(Error::InvalidLength);
    }
    let (left, right) = encrypted.split_at(encrypted.len() / 2);

    // Non-extendable shares salt each round with "shamir" and the
    // identifier, so they cannot be mixed with another set's shares.
    let salt_prefix: Vec<u8> = if extendable {
        Vec::new()
    } else {
        [b"shamir".as_slice(), &identifier.to_be_bytes()].concat()
    };
    // The exponent is a 4-bit field (at most 15), and 2500 << 15 fits in a
    // u32, so this only fails if a caller passes a value no card can hold.
    let iterations = BASE_ITERATIONS
        .checked_shl(u32::from(iteration_exponent))
        .filter(|_| iteration_exponent <= 15)
        .ok_or(Error::InvalidLength)?;

    let mut left = Zeroizing::new(left.to_vec());
    let mut right = Zeroizing::new(right.to_vec());
    for round in [3u8, 2, 1, 0] {
        let mixed = round_function(round, passphrase, iterations, &salt_prefix, &right);
        // (L, R) = (R, L xor F(i, R))
        let new_right: Zeroizing<Vec<u8>> =
            Zeroizing::new(left.iter().zip(mixed.iter()).map(|(l, f)| l ^ f).collect());
        left = core::mem::replace(&mut right, new_right);
    }

    // MS = R || L
    let mut secret = Zeroizing::new(Vec::with_capacity(encrypted.len()));
    secret.extend_from_slice(&right);
    secret.extend_from_slice(&left);
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

    const MASTER_SECRET: &str = "bb54aac4b89dc868ba37d9cc21b2cece";

    // Expected values from Trezor's reference shamir_mnemonic.cipher.encrypt.
    #[test]
    fn decrypts_non_extendable_with_identifier_in_salt() -> Result<(), Error> {
        let ms = decrypt(
            &bytes("11bc609d21747c49ba78c0701293e417"),
            b"TREZOR",
            0,
            7945,
            false,
        )?;
        assert_eq!(*ms, bytes(MASTER_SECRET));
        Ok(())
    }

    #[test]
    fn decrypts_extendable_without_identifier() -> Result<(), Error> {
        let ms = decrypt(
            &bytes("4ed5aafca6faf2cbf90519a4d6f41191"),
            b"TREZOR",
            0,
            7945,
            true,
        )?;
        assert_eq!(*ms, bytes(MASTER_SECRET));
        Ok(())
    }

    #[test]
    fn decrypts_with_empty_passphrase_and_exponent_1() -> Result<(), Error> {
        let ms = decrypt(&bytes("a140f2960e2782e9b6f5064f7308ddba"), b"", 1, 0, true)?;
        assert_eq!(*ms, bytes(MASTER_SECRET));
        Ok(())
    }

    #[test]
    fn rejects_an_odd_length() {
        assert_eq!(
            decrypt(&[0u8; 17], b"", 0, 0, true),
            Err(Error::InvalidLength)
        );
    }
}
