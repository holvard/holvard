// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cross-check with Trezor's reference implementation, in both directions:
//! cards Holvard creates must recover with Trezor's `shamir` CLI, and cards
//! `shamir` creates must recover with Holvard.
//!
//! Ignored by default, because it needs the `shamir` CLI:
//!
//! ```sh
//! pip install --require-hashes -r scripts/cross-check/requirements.txt
//! cargo test -p holvard-core --test slip39_cross_check -- --ignored
//! ```
//!
//! `scripts/cross-check.sh` runs it in CI. Set `SHAMIR` to use a `shamir`
//! binary that is not on `PATH`.

mod common;

use common::{Result, hex, random_bytes, trezor_create, trezor_recover};
use holvard_core::slip39::{Group, Mnemonic, combine, generate};

fn words(cards: &[&Mnemonic]) -> Vec<String> {
    cards.iter().map(|c| c.as_str().to_owned()).collect()
}

#[test]
#[ignore = "needs Trezor's shamir CLI; run by scripts/cross-check.sh"]
fn holvard_cards_recover_with_trezor() -> Result<()> {
    for length in [16, 32] {
        for _ in 0..3 {
            let secret = random_bytes(length)?;
            let sets = generate(
                1,
                &[Group {
                    threshold: 2,
                    count: 3,
                }],
                &secret,
                "",
                0,
            )?;
            let cards: Vec<&Mnemonic> = sets.iter().flatten().collect();
            let [a, b, c] = cards.as_slice() else {
                return Err("expected three cards".into());
            };
            for pair in [[*a, *b], [*a, *c], [*b, *c]] {
                let pair = words(&pair);
                let pair: Vec<&str> = pair.iter().map(String::as_str).collect();
                assert_eq!(trezor_recover(&pair)?, hex(&secret));
            }
        }
    }
    Ok(())
}

#[test]
#[ignore = "needs Trezor's shamir CLI; run by scripts/cross-check.sh"]
fn trezor_cards_recover_with_holvard() -> Result<()> {
    for bits in ["128", "256"] {
        for extendable in ["--extendable", "--no-extendable"] {
            let secret = random_bytes(if bits == "128" { 16 } else { 32 })?;
            let groups = trezor_create(&["2of3", "-s", bits, "-S", &hex(&secret), extendable])?;
            let [cards] = groups.as_slice() else {
                return Err("expected one group".into());
            };
            let [a, b, c] = cards.as_slice() else {
                return Err("expected three cards".into());
            };
            for pair in [[a, b], [a, c], [b, c]] {
                let pair: Vec<&str> = pair.iter().map(|s| s.as_str()).collect();
                assert_eq!(
                    hex(combine(&pair, "")?.as_bytes()),
                    hex(&secret),
                    "{bits} bits, {extendable}"
                );
            }
        }
    }
    Ok(())
}

// The group example from docs/design.md: heirs 2 of 3, Holvard 1 of 1,
// backup holder 1 of 1, any 2 of the 3 groups.
#[test]
#[ignore = "needs Trezor's shamir CLI; run by scripts/cross-check.sh"]
fn group_cards_cross_check_both_ways() -> Result<()> {
    let secret = random_bytes(32)?;

    // Holvard creates, Trezor recovers from two heirs + Holvard.
    let groups = [
        Group {
            threshold: 2,
            count: 3,
        },
        Group {
            threshold: 1,
            count: 1,
        },
        Group {
            threshold: 1,
            count: 1,
        },
    ];
    let sets = generate(2, &groups, &secret, "", 0)?;
    let [heirs, keeper, _backup] = sets.as_slice() else {
        return Err("expected three groups".into());
    };
    let ([h1, _, h3], [k]) = (heirs.as_slice(), keeper.as_slice()) else {
        return Err("unexpected group sizes".into());
    };
    let chosen = words(&[h1, h3, k]);
    let chosen: Vec<&str> = chosen.iter().map(String::as_str).collect();
    assert_eq!(trezor_recover(&chosen)?, hex(&secret));

    // Trezor creates, Holvard recovers from Holvard's card + the backup.
    let groups = trezor_create(&[
        "custom",
        "-t",
        "2",
        "-g",
        "2",
        "3",
        "-g",
        "1",
        "1",
        "-g",
        "1",
        "1",
        "-S",
        &hex(&secret),
    ])?;
    let [_, keeper, backup] = groups.as_slice() else {
        return Err("expected three groups".into());
    };
    let (Some(k), Some(b)) = (keeper.first(), backup.first()) else {
        return Err("empty group".into());
    };
    assert_eq!(
        hex(combine(&[k.as_str(), b.as_str()], "")?.as_bytes()),
        hex(&secret)
    );
    Ok(())
}
