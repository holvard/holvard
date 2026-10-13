// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The vault test vector in `test-vectors/vault/`, made only with the
//! official tools (Trezor's `shamir create` and the `age` CLI): Holvard must
//! open it with any two of its three cards.

use std::error::Error;

use holvard_core::slip39::combine;
use holvard_core::vault::open_vault;

const CARDS: &str = include_str!("../../../test-vectors/vault/cards.txt");
const SECRET: &str = include_str!("../../../test-vectors/vault/secret.hex");
const CONTENTS: &[u8] = include_bytes!("../../../test-vectors/vault/contents.txt");
const VAULT: &[u8] = include_bytes!("../../../test-vectors/vault/vault.age");

fn cards() -> Result<[&'static str; 3], Box<dyn Error>> {
    let cards: Vec<&str> = CARDS.lines().collect();
    Ok(cards
        .try_into()
        .map_err(|_| "cards.txt must hold three cards")?)
}

#[test]
fn any_two_cards_open_the_vector() -> Result<(), Box<dyn Error>> {
    let [a, b, c] = cards()?;
    for pair in [[a, b], [a, c], [b, c]] {
        assert_eq!(open_vault(&pair, VAULT)?.as_slice(), CONTENTS);
    }
    Ok(())
}

#[test]
fn cards_recover_the_vector_secret() -> Result<(), Box<dyn Error>> {
    use core::fmt::Write as _;

    let [a, b, _] = cards()?;
    let secret = combine(&[a, b], "")?;
    let mut hex = String::new();
    for byte in secret.as_bytes() {
        write!(hex, "{byte:02x}")?;
    }
    assert_eq!(hex, SECRET.trim_end());
    Ok(())
}
