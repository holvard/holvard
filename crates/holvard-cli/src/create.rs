// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `holvard create`: pack a folder, encrypt it into a new vault, and hand
//! out the three cards.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use zeroize::Zeroizing;

use crate::Failure;
use crate::pack;
use crate::screen::{self, Tty};

/// Where the vault goes when `-o` is not given.
const DEFAULT_OUT: &str = "vault.age";
/// Above this much file data, say how much memory creating needs.
const BIG_NOTE: u64 = 100 * 1024 * 1024;
/// The vault is encrypted and meant to be copied; the cards file is not.
const VAULT_MODE: u32 = 0o644;
const CARDS_MODE: u32 = 0o600;

/// Where the cards go.
enum CardsTo<'a> {
    File(&'a Path),
    Screen(Tty),
}

/// Runs `holvard create`.
pub fn run(folder: &Path, out: Option<&Path>, cards_file: Option<&Path>) -> Result<(), Failure> {
    let out = out.unwrap_or(Path::new(DEFAULT_OUT));
    // Everything that can be checked before any work.
    refuse_existing(out)?;
    let cards_to = if let Some(path) = cards_file {
        refuse_existing(path)?;
        CardsTo::File(path)
    } else {
        if !screen::interactive() {
            return Err(Failure(
                "cards are shown only on a terminal; use --cards-file to write them to a file"
                    .into(),
            ));
        }
        CardsTo::Screen(Tty::open().map_err(|e| Failure(format!("cannot open the terminal: {e}")))?)
    };

    screen::set_stop_message(Some("stopped; no vault was saved".into()));
    // Scan first, so sizes are known before anything big is allocated.
    let scanned = pack::scan(folder, &pack::LIMITS).map_err(|e| Failure(e.to_string()))?;
    if scanned.bytes > BIG_NOTE {
        eprintln!(
            "holvard: note: {} MiB of files. Creating needs up to three times that in memory \
             (the zip, the largest file and the vault at once); recovering needs about twice \
             the vault's size.",
            scanned.bytes / (1024 * 1024)
        );
    }
    let zip = scanned.write().map_err(|e| Failure(e.to_string()))?;

    // Save the vault before showing any card: cards for a vault that was
    // never saved would be useless.
    let vault = holvard_core::vault::create_vault(&zip).map_err(|e| Failure(e.to_string()))?;
    write_new(out, &vault.encrypted, VAULT_MODE)?;
    screen::set_stop_message(Some(format!(
        "stopped before all cards were shown; {} was saved but its cards are incomplete. \
         Delete it and run create again.",
        out.display()
    )));

    let [a, b, c] = &vault.cards;
    let cards = [a.as_str(), b.as_str(), c.as_str()];
    match cards_to {
        CardsTo::File(path) => {
            write_new(path, cards_file_text(cards).as_bytes(), CARDS_MODE)?;
            eprintln!(
                "holvard: {} holds all three cards. Anyone with it can open the vault. \
                 Print it, then delete it.",
                path.display()
            );
        }
        CardsTo::Screen(mut tty) => show_cards(&mut tty, cards)
            .map_err(|e| Failure(format!("could not show the cards: {e}")))?,
    }
    screen::set_stop_message(None);
    println!("Saved {} ({}).", out.display(), crate::files(scanned.files));
    println!(
        "Any two cards open the vault. Give each card to a different person or place; \
         one card alone reveals nothing."
    );
    Ok(())
}

/// Refuses a path that exists in any form, a dangling link included.
pub fn refuse_existing(path: &Path) -> Result<(), Failure> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(Failure(format!(
            "{} already exists; choose another name",
            path.display()
        )));
    }
    Ok(())
}

/// Writes a new file; never overwrites, even one that appeared since the
/// check.
fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<(), Failure> {
    let failed = |e| Failure(format!("cannot write {}: {e}", path.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(failed)?;
    file.write_all(data).map_err(failed)
}

/// The cards file: `card-1: <words>` and so on, one per line, in a buffer
/// allocated once.
fn cards_file_text(cards: [&str; 3]) -> Zeroizing<String> {
    let length = cards
        .iter()
        .map(|card| card.len().saturating_add("card-N: \n".len()))
        .fold(0usize, usize::saturating_add);
    let mut text = Zeroizing::new(String::with_capacity(length));
    for (number, card) in ["1", "2", "3"].iter().zip(cards) {
        text.push_str("card-");
        text.push_str(number);
        text.push_str(": ");
        text.push_str(card);
        text.push('\n');
    }
    text
}

/// Shows each card alone on the alternate screen and waits for Enter.
fn show_cards(tty: &mut Tty, cards: [&str; 3]) -> std::io::Result<()> {
    let mut alternate = tty.alternate()?;
    for (number, card) in (1usize..).zip(cards) {
        alternate.clear()?;
        alternate.say(&screen::format_card(number, card))?;
        alternate.wait_enter()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_file_text_has_three_labelled_lines() {
        let text = cards_file_text(["a b", "c d", "e f"]);
        assert_eq!(text.as_str(), "card-1: a b\ncard-2: c d\ncard-3: e f\n");
        assert_eq!(text.capacity(), text.len()); // allocated once, exactly
    }
}
