// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `holvard create`: pack a folder, encrypt it into a new vault, and hand
//! out the three cards.

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::Failure;
use crate::disk::{self, NewFile};
use crate::pack;
use crate::screen::{self, Tty};

/// Where the vault goes when `-o` is not given.
const DEFAULT_OUT: &str = "vault.age";
/// Above this much file data, say how much memory creating needs.
const BIG_NOTE: u64 = 100 * 1024 * 1024;
/// The vault is encrypted and meant to be copied; the cards file is not.
const VAULT_MODE: u32 = 0o644;
const CARDS_MODE: u32 = 0o600;

/// Runs `holvard create`.
pub fn run(folder: &Path, out: Option<&Path>, cards_file: Option<&Path>) -> Result<(), Failure> {
    let out = out.unwrap_or(Path::new(DEFAULT_OUT));
    // Everything that can be checked before any work.
    refuse_existing(out)?;
    if let Some(path) = cards_file {
        refuse_existing(path)?;
    }
    let mut tty = if cards_file.is_some() {
        None
    } else {
        if !screen::interactive() {
            return Err(Failure(
                "cards are shown only on a terminal; use --cards-file to write them to a file"
                    .into(),
            ));
        }
        Some(Tty::open().map_err(|e| Failure(format!("cannot open the terminal: {e}")))?)
    };
    // Both outputs exist from here on, so a path that cannot be written
    // fails now, not after the work. Until `keep`, a failure removes them.
    let create = |path: &Path, mode| {
        NewFile::create(path, mode)
            .map_err(|e| Failure(format!("cannot write {}: {e}", path.display())))
    };
    let mut vault_file = create(out, VAULT_MODE)?;
    let mut cards_out = cards_file
        .map(|path| create(path, CARDS_MODE))
        .transpose()?;

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
    let failed = |path: &Path| {
        let shown = path.display().to_string();
        move |e| Failure(format!("cannot write {shown}: {e}; no vault was saved"))
    };
    vault_file
        .write_synced(&vault.encrypted)
        .map_err(failed(out))?;

    let [a, b, c] = &vault.cards;
    let cards = [a.as_str(), b.as_str(), c.as_str()];
    if let Some(file) = cards_out.as_mut() {
        let path = file.path().to_path_buf();
        file.write_synced(cards_file_text(cards).as_bytes())
            .map_err(failed(&path))?;
    }
    if let Some(tty) = tty.as_mut() {
        show_cards(tty, cards)
            .map_err(|e| Failure(format!("could not show the cards: {e}; no vault was saved")))?;
    }
    for path in std::iter::once(out).chain(cards_file) {
        disk::sync_folder(disk::parent_of(path)).map_err(failed(path))?;
    }
    // A stop (Ctrl-C) before this removes both files; after it, nothing.
    disk::keep_all(std::iter::once(vault_file).chain(cards_out), || {
        screen::set_stop_message(None);
    });
    if let Some(path) = cards_file {
        eprintln!(
            "holvard: {} holds all three cards. Anyone with it can open the vault. \
             Print it, then delete it.",
            path.display()
        );
    }
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
/// Input ending before the last card (Ctrl-D) is an error: a card the
/// owner never confirmed may not have been written down.
fn show_cards(tty: &mut Tty, cards: [&str; 3]) -> std::io::Result<()> {
    let mut alternate = tty.alternate()?;
    for (number, card) in (1usize..).zip(cards) {
        alternate.clear()?;
        alternate.say(&screen::format_card(number, card))?;
        if !alternate.wait_enter()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "input ended before all cards were shown",
            ));
        }
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
