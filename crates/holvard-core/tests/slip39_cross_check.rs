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

use std::error::Error;
use std::io::Write as _;
use std::process::{Command, Stdio};

use holvard_core::slip39::{Group, Mnemonic, combine, generate};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn shamir() -> Command {
    Command::new(std::env::var("SHAMIR").unwrap_or_else(|_| "shamir".to_owned()))
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn random_secret(length: usize) -> Result<Vec<u8>> {
    let mut secret = vec![0u8; length];
    getrandom::fill(&mut secret).map_err(|e| format!("random generator: {e}"))?;
    Ok(secret)
}

/// Runs `shamir recover` with `cards` typed in, and returns the master
/// secret it prints, as hex.
fn trezor_recover(cards: &[&str]) -> Result<String> {
    let mut child = shamir()
        .arg("recover")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child.stdin.as_mut().ok_or("no stdin")?;
        for card in cards {
            writeln!(stdin, "{card}")?;
        }
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    stdout
        .lines()
        .find_map(|line| line.split_once("Your master secret is: "))
        .map(|(_, secret)| secret.trim().to_owned())
        .ok_or_else(|| format!("shamir recover printed no secret:\n{stdout}").into())
}

/// Runs `shamir create` and returns its cards, group by group.
///
/// Cards are recognised as lines of 20 or more lowercase words after a
/// "Group" header. That depends on `shamir`'s output format, which cannot
/// change under us: `shamir-mnemonic` is pinned by hash in
/// `scripts/cross-check/requirements.txt`.
fn trezor_create(args: &[&str]) -> Result<Vec<Vec<String>>> {
    let output = shamir().arg("create").args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "shamir create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let mut groups: Vec<Vec<String>> = Vec::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        if line.starts_with("Group ") {
            groups.push(Vec::new());
        } else if line.split(' ').count() >= 20
            && line.chars().all(|c| c.is_ascii_lowercase() || c == ' ')
        {
            groups
                .last_mut()
                .ok_or("card before any group header")?
                .push(line.to_owned());
        }
    }
    Ok(groups)
}

fn words(cards: &[&Mnemonic]) -> Vec<String> {
    cards.iter().map(|c| c.as_str().to_owned()).collect()
}

#[test]
#[ignore = "needs Trezor's shamir CLI; run by scripts/cross-check.sh"]
fn holvard_cards_recover_with_trezor() -> Result<()> {
    for length in [16, 32] {
        for _ in 0..3 {
            let secret = random_secret(length)?;
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
            let secret = random_secret(if bits == "128" { 16 } else { 32 })?;
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
    let secret = random_secret(32)?;

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
