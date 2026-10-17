// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `holvard recover`: read two cards, open the vault, and unpack it into a
//! new folder.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use holvard_core::vault::{self, Error};
use zeroize::Zeroizing;

use crate::Failure;
use crate::create::refuse_existing;
use crate::pack::{self, Unpacked};
use crate::screen::{self, Line, Tty};

/// A cards file holds two cards; more than this is not one.
const MAX_CARDS_FILE: usize = 4096;
const STAGING_MODE: u32 = 0o700;

/// Runs `holvard recover`.
pub fn run(vault: &Path, out: Option<&Path>, cards_file: Option<&Path>) -> Result<(), Failure> {
    // Rebuilt from its components so `out/` and `out` are the same path
    // and the staging folder `out.partial` sits next to it, not inside.
    let out: PathBuf = out
        .map_or_else(|| default_out(vault), Path::to_path_buf)
        .components()
        .collect();
    screen::set_stop_message(Some("stopped; nothing was recovered".into()));
    let encrypted =
        fs::read(vault).map_err(|e| Failure(format!("cannot read {}: {e}", vault.display())))?;
    refuse_existing(&out)?;
    refuse_existing(&staging_path(&out))?;
    let cards = if let Some(path) = cards_file {
        read_cards_file(path)?
    } else {
        if !screen::interactive() {
            return Err(Failure(
                "cards are typed on a terminal; use --cards-file to read them from a file".into(),
            ));
        }
        type_cards()?
    };
    let [a, b] = cards.as_slice() else {
        return Err(Failure("exactly two cards are needed".into()));
    };
    let contents =
        vault::open_vault(&[a.as_str(), b.as_str()], &encrypted).map_err(open_failure)?;

    let staging = Staging::create(&out)?;
    screen::set_stop_message(Some(format!(
        "stopped while unpacking; delete {} if it is still there",
        staging.path().display()
    )));
    let unpacked = pack::unpack(&contents, staging.path(), &pack::LIMITS)
        .map_err(|e| Failure(e.to_string()))?;
    staging.publish()?;
    screen::set_stop_message(None);
    match unpacked {
        Unpacked::Files(count) => {
            println!("Recovered {} into {}.", crate::files(count), out.display());
        }
        Unpacked::Contents => {
            println!(
                "Recovered the vault into {}.",
                out.join("contents").display()
            );
        }
    }
    println!("These files are not encrypted any more; keep them safe.");
    Ok(())
}

/// `<file name without .age>-recovered`, in the current folder. The vault
/// is often on a read-only USB stick, so not next to it.
fn default_out(vault: &Path) -> PathBuf {
    let name = vault.file_name().unwrap_or(vault.as_os_str());
    let stem = if Path::new(name).extension().is_some_and(|e| e == "age") {
        Path::new(name).file_stem().unwrap_or(name)
    } else {
        name
    };
    let mut out = OsString::from(stem);
    out.push("-recovered");
    PathBuf::from(out)
}

/// `<out>.partial`.
fn staging_path(out: &Path) -> PathBuf {
    let mut name = out.as_os_str().to_os_string();
    name.push(".partial");
    PathBuf::from(name)
}

fn open_failure(e: Error) -> Failure {
    Failure(match e {
        Error::WrongCardsOrDamaged => {
            "these two cards don't open this vault, or the vault file is damaged".into()
        }
        Error::NotAVault => "this is not a Holvard vault file".into(),
        Error::TooMuchWork => "this vault asks for more work than Holvard allows".into(),
        other => other.to_string(),
    })
}

/// A staging folder `<out>.partial` that this run created. It is removed
/// when dropped unless published, and never touches a folder this run did
/// not create.
struct Staging {
    path: PathBuf,
    out: PathBuf,
    published: bool,
}

impl Staging {
    /// Creates `<out>.partial`, mode 0700. Fails if anything is there;
    /// that failure removes nothing.
    fn create(out: &Path) -> Result<Self, Failure> {
        let path = staging_path(out);
        fs::DirBuilder::new()
            .mode(STAGING_MODE)
            .create(&path)
            .map_err(|e| Failure(format!("cannot create {}: {e}", path.display())))?;
        Ok(Self {
            path,
            out: out.to_path_buf(),
            published: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Renames the staging folder to `out`. On Unix a rename replaces only
    /// an empty folder; if `out` appeared meanwhile and is not empty, this
    /// fails and dropping `self` removes the staging folder.
    fn publish(mut self) -> Result<(), Failure> {
        fs::rename(&self.path, &self.out)
            .map_err(|e| Failure(format!("cannot create {}: {e}", self.out.display())))?;
        self.published = true;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Two cards from a file, read once into a buffer that never grows.
fn read_cards_file(path: &Path) -> Result<Vec<Zeroizing<String>>, Failure> {
    let failed = |e| Failure(format!("cannot read {}: {e}", path.display()));
    let mut file = File::open(path).map_err(failed)?;
    let mut buffer = Zeroizing::new(vec![0u8; MAX_CARDS_FILE.saturating_add(1)]);
    let mut length = 0usize;
    loop {
        let rest = buffer.get_mut(length..).unwrap_or_default();
        if rest.is_empty() {
            break;
        }
        let read = file.read(rest).map_err(failed)?;
        if read == 0 {
            break;
        }
        length = length.saturating_add(read);
    }
    if length > MAX_CARDS_FILE {
        return Err(Failure("the cards file is too big for two cards".into()));
    }
    parse_cards_file(buffer.get(..length).unwrap_or_default())
}

/// Blank lines are skipped, an optional `card-N:` prefix removed, and each
/// card's words completed from their first letters. Exactly two cards.
fn parse_cards_file(bytes: &[u8]) -> Result<Vec<Zeroizing<String>>, Failure> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| Failure("the cards file is not text".into()))?;
    let mut cards = Vec::with_capacity(2);
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if cards.len() == 2 {
            return Err(Failure("the cards file must hold exactly two cards".into()));
        }
        let card = vault::complete_card(strip_label(line))
            .map_err(|e| Failure(format!("card {}: {e}", cards.len().saturating_add(1))))?;
        cards.push(card);
    }
    if cards.len() == 2 {
        Ok(cards)
    } else {
        Err(Failure("the cards file must hold exactly two cards".into()))
    }
}

/// Removes a leading `card-<digits>:` label, as written by
/// `holvard create --cards-file`.
fn strip_label(line: &str) -> &str {
    let Some((label, rest)) = line.split_once(':') else {
        return line;
    };
    let is_label = label
        .get(..5)
        .is_some_and(|start| start.eq_ignore_ascii_case("card-"))
        && label
            .get(5..)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if is_label { rest.trim() } else { line }
}

/// Two cards typed on the alternate screen, each checked as it is entered.
fn type_cards() -> Result<Vec<Zeroizing<String>>, Failure> {
    let failed = |e: std::io::Error| Failure(format!("terminal error: {e}"));
    let mut tty = Tty::open().map_err(failed)?;
    let mut alternate = tty.alternate().map_err(failed)?;
    let mut cards: Vec<Zeroizing<String>> = Vec::with_capacity(2);
    while cards.len() < 2 {
        let number = cards.len().saturating_add(1);
        alternate
            .say(&format!(
                "Card {number}: type its 33 words (the first 4 letters of each are enough), then press Enter.\nTo stop, press Ctrl-C. If typing stops working, press Ctrl-U and type the card again."
            ))
            .map_err(failed)?;
        let typed = match alternate.read_card().map_err(failed)? {
            // An extra Enter just asks again; Ctrl-C is the way to stop.
            Line::Empty => continue,
            Line::End => return Err(Failure("stopped; nothing was recovered".into())),
            Line::TooLong => {
                alternate
                    .say("That line is too long for a card; type it again.")
                    .map_err(failed)?;
                continue;
            }
            Line::NotText => {
                alternate
                    .say("That line has characters that are not letters; type it again.")
                    .map_err(failed)?;
                continue;
            }
            Line::Card(text) => text,
        };
        match check_typed(&typed, cards.first()) {
            Ok(card) => {
                alternate
                    .say(&format!("Card {number} OK."))
                    .map_err(failed)?;
                cards.push(card);
            }
            Err(message) => {
                alternate
                    .say(&format!("{message}; type it again."))
                    .map_err(failed)?;
            }
        }
    }
    Ok(cards)
}

/// Completes and checks one typed card; for the second card, also that it
/// is not the first one again. The message never contains the card's words.
fn check_typed(
    typed: &str,
    first: Option<&Zeroizing<String>>,
) -> Result<Zeroizing<String>, String> {
    let card = vault::complete_card(typed).map_err(|e| e.to_string())?;
    vault::check_card(&card).map_err(|e| e.to_string())?;
    if let Some(first) = first
        && vault::same_card(first, &card).map_err(|e| e.to_string())?
    {
        return Err("that is the same card as card 1; use a different card".into());
    }
    Ok(card)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, TestResult};

    #[test]
    fn default_output_names() {
        assert_eq!(
            default_out(Path::new("/media/usb/vault.age")),
            PathBuf::from("vault-recovered")
        );
        assert_eq!(
            default_out(Path::new("backup.bin")),
            PathBuf::from("backup.bin-recovered")
        );
        assert_eq!(
            default_out(Path::new("dir/.age")),
            PathBuf::from(".age-recovered")
        );
        assert_eq!(
            default_out(Path::new("v.AGE")),
            PathBuf::from("v.AGE-recovered")
        );
    }

    #[test]
    fn cards_file_tolerates_crlf_and_spaces() -> Result<(), Failure> {
        let text = b"card-1:  academic acid acne\r\n\r\n  card-3: acquire\r\n";
        let cards = parse_cards_file(text)?;
        let [a, b] = cards.as_slice() else {
            return Err(Failure("not two cards".into()));
        };
        assert_eq!(a.as_str(), "academic acid acne");
        assert_eq!(b.as_str(), "acquire");
        Ok(())
    }

    #[test]
    fn cards_file_needs_exactly_two_cards() {
        assert!(parse_cards_file(b"academic\n").is_err());
        assert!(parse_cards_file(b"academic\nacid\nacne\n").is_err());
    }

    #[test]
    fn only_card_labels_are_stripped() {
        assert_eq!(strip_label("card-12: a b"), "a b");
        assert_eq!(strip_label("CARD-1:a"), "a");
        assert_eq!(strip_label("card-: a"), "card-: a");
        assert_eq!(strip_label("cardx1: a"), "cardx1: a");
        assert_eq!(strip_label("a b"), "a b");
    }

    #[test]
    fn staging_folder_is_ours_or_untouched() -> TestResult {
        let t = TempDir::new()?;
        let out = t.0.join("out");
        let partial = t.0.join("out.partial");
        // An existing staging folder is refused and left alone.
        fs::create_dir(&partial)?;
        fs::write(partial.join("keep"), b"x")?;
        assert!(Staging::create(&out).is_err());
        assert!(partial.join("keep").exists());
        fs::remove_dir_all(&partial)?;
        // A staging folder this run made is removed if not published.
        {
            let staging = Staging::create(&out)?;
            fs::write(staging.path().join("f"), b"x")?;
        }
        assert!(!partial.exists());
        // Publishing onto a non-empty `out` fails and cleans up.
        fs::create_dir(&out)?;
        fs::write(out.join("theirs"), b"x")?;
        let staging = Staging::create(&out)?;
        assert!(staging.publish().is_err());
        assert!(!partial.exists());
        assert!(out.join("theirs").exists());
        Ok(())
    }

    #[test]
    fn typed_card_problems_name_no_words() -> TestResult {
        let vault = holvard_core::vault::create_vault(b"x")?;
        let [a, b, _] = &vault.cards;
        assert!(check_typed(a.as_str(), None).is_ok());
        let again = check_typed(a.as_str(), Some(&Zeroizing::new(a.as_str().to_owned())));
        assert!(matches!(again, Err(m) if m.contains("same card")));
        let typo = a.as_str().replacen(' ', " zzzz ", 1);
        // Exact text: "check" and "spelling" are SLIP-39 words themselves,
        // so scanning the message for card words would be flaky.
        assert_eq!(
            check_typed(&typo, None).err().as_deref(),
            Some("word 2 is not in the SLIP-39 word list; check the spelling")
        );
        assert!(check_typed(b.as_str(), Some(&Zeroizing::new(a.as_str().to_owned()))).is_ok());
        Ok(())
    }
}
