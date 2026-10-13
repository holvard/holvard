// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Vaults: contents encrypted with age under a random secret, and that
//! secret split into three SLIP-39 cards, any two of which open the vault.
//!
//! The secret unlocks the vault as an age passphrase: the lowercase hex
//! encoding of the SLIP-39 master secret. Recovery therefore also works
//! with standard tools alone: Trezor's `shamir recover` prints the secret
//! as hex, and `age -d` takes it as the passphrase. See `spec/vault.md`.
//!
//! Known limitation: some copies made inside age and scrypt are freed
//! without being wiped. When encrypting, age's stream writer keeps the last
//! chunk of the contents (up to 64 KiB) in a buffer it clears but does not
//! wipe. On both sides, the key that scrypt derives from the passphrase is
//! left on the stack, and scrypt's working memory (about 256 MiB at work
//! factor 18) is freed unwiped. What Holvard holds itself (the secret, the
//! passphrase, the opened contents) is wiped. Closing these gaps ourselves
//! would break the rule against home-made cryptography. scrypt's buffers
//! are RustCrypto/password-hashes#938; the age buffers are to be reported
//! to str4d/rage.

use core::fmt::{self, Write as _};
use std::io::Read as _;
use std::iter;

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::slip39::share::Share;
use crate::slip39::{self, Group, Mnemonic};

/// Length of the vault secret: 256 bits from the operating system.
const SECRET_LEN: usize = 32;

/// SLIP-39 iteration exponent on the cards: 0, the default of Trezor's
/// `shamir create`. The SLIP-39 passphrase is always empty.
const ITERATION_EXPONENT: u8 = 0;

/// scrypt work factor for new vaults: age's default, 18.
const WORK_FACTOR: u8 = 18;

/// Highest scrypt work factor accepted when opening a vault: 20, the
/// highest the browser age library (typage) accepts.
const MAX_WORK_FACTOR: u8 = 20;

/// Longest age header accepted when opening a vault. A Holvard header (one
/// scrypt stanza) is about 150 bytes; age's header parsing slows down
/// quadratically with length, so longer files are refused unparsed.
const MAX_HEADER_LEN: usize = 1024;

/// A new vault: the encrypted file and the three cards that open it.
#[derive(Debug)]
pub struct Vault {
    /// The three cards. Any two of them open the vault; one alone never
    /// does.
    pub cards: [Mnemonic; 3],
    /// The encrypted vault, a binary age file (`vault.age`).
    pub encrypted: Vec<u8>,
}

/// Encrypts `contents` into a new vault under a fresh random secret, and
/// splits that secret into three cards.
///
/// # Errors
///
/// Returns an error if the random generator fails, if splitting the
/// secret into cards fails, or if encryption fails.
pub fn create_vault(contents: &[u8]) -> Result<Vault, Error> {
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    getrandom::fill(secret.as_mut()).map_err(|_| Error::RandomnessUnavailable)?;

    // One group of three cards, two of which are needed.
    let group = Group {
        threshold: 2,
        count: 3,
    };
    let sets = slip39::generate(1, &[group], secret.as_ref(), "", ITERATION_EXPONENT)
        .map_err(Error::Cards)?;
    let cards: [Mnemonic; 3] = sets
        .into_iter()
        .next()
        .and_then(|cards| cards.try_into().ok())
        // Cannot happen: one group of three was asked for.
        .ok_or(Error::Encryption)?;

    // `Recipient::new` picks a work factor by timing this machine; Holvard
    // always uses age's default instead, so every vault is the same.
    let mut recipient = age::scrypt::Recipient::new(passphrase(secret.as_ref()));
    recipient.set_work_factor(WORK_FACTOR);
    let encrypted = age::encrypt(&recipient, contents).map_err(|_| Error::Encryption)?;

    Ok(Vault { cards, encrypted })
}

/// Opens a vault with exactly two of its cards and returns the contents.
///
/// # Errors
///
/// Returns an error if the file is not a Holvard vault, if the cards are
/// not two different Holvard cards of one set, if they belong to a
/// different vault, or if the vault file is damaged.
pub fn open_vault(cards: &[&str], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Cheap checks first, so a crafted file or crafted cards cannot make
    // age or SLIP-39 do a lot of work.
    if !header_is_small(encrypted) {
        return Err(Error::NotAVault);
    }
    check_cards(cards)?;
    let secret = slip39::combine(cards, "").map_err(Error::Cards)?;

    // The vault's header says how much scrypt work it needs; refusing more
    // than MAX_WORK_FACTOR keeps a crafted file from using gigabytes of
    // memory.
    let mut identity = age::scrypt::Identity::new(passphrase(secret.as_bytes()));
    identity.set_max_work_factor(MAX_WORK_FACTOR);

    let decryptor = age::Decryptor::new_buffered(encrypted).map_err(|_| Error::NotAVault)?;
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::ExcessiveWork { .. } => Error::TooMuchWork,
            // NoMatchingKeys: the file has no scrypt stanza (for example
            // it was made for an X25519 key), so it is not a vault.
            age::DecryptError::InvalidHeader
            | age::DecryptError::UnknownFormat
            | age::DecryptError::NoMatchingKeys => Error::NotAVault,
            _ => Error::WrongCardsOrDamaged,
        })?;

    // The contents are never longer than the encrypted file, so this
    // buffer never grows and leaves no unwiped copies behind.
    let mut contents = Zeroizing::new(Vec::with_capacity(encrypted.len()));
    reader
        .read_to_end(&mut contents)
        .map_err(|_| Error::WrongCardsOrDamaged)?;
    Ok(contents)
}

/// Whether the age header, up to the newline ending its MAC line, fits in
/// `MAX_HEADER_LEN` bytes. age marks the header's end with a line starting
/// `---`; stanza lines cannot start that way. That line's own newline must
/// also be within the limit, or age would read on through the whole file
/// looking for it. This only finds where the header ends; age parses it.
fn header_is_small(encrypted: &[u8]) -> bool {
    let start = encrypted.get(..MAX_HEADER_LEN).unwrap_or(encrypted);
    start
        .windows(4)
        .position(|w| w == b"\n---")
        .and_then(|at| start.get(at.saturating_add(1)..))
        .is_some_and(|mac_line| mac_line.contains(&b'\n'))
}

/// spec/vault.md, reader rules: exactly two different cards, each from one
/// group of 2-of-n, iteration exponent 0 and a 256-bit secret. Checked
/// before combining, because combining runs PBKDF2 with the cost the cards
/// themselves ask for.
fn check_cards(cards: &[&str]) -> Result<(), Error> {
    let [first, second] = cards else {
        return Err(Error::Cards(slip39::Error::WrongNumberOfShares));
    };
    let first = Share::from_mnemonic(first).map_err(Error::Cards)?;
    let second = Share::from_mnemonic(second).map_err(Error::Cards)?;
    if first.is_same_card(&second) {
        return Err(Error::SameCardTwice);
    }
    let holvard = |s: &Share| {
        // One group (its threshold can then only be 1), two of its cards.
        s.iteration_exponent == ITERATION_EXPONENT
            && s.group_count == 1
            && s.member_threshold == 2
            && s.value.len() == SECRET_LEN
    };
    if holvard(&first) && holvard(&second) {
        Ok(())
    } else {
        Err(Error::NotHolvardCards)
    }
}

/// The age passphrase for a secret: its lowercase hex encoding.
fn passphrase(secret: &[u8]) -> SecretString {
    let mut hex = String::with_capacity(secret.len().saturating_mul(2));
    for byte in secret {
        // Writing to a String cannot fail, and the capacity is exact, so
        // the string never grows.
        let _ = write!(hex, "{byte:02x}");
    }
    SecretString::from(hex)
}

/// Why a vault could not be created or opened.
///
/// Variants may be added, so matching on it needs a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The cards could not be combined into a secret.
    Cards(slip39::Error),
    /// The same card was given twice.
    SameCardTwice,
    /// The cards are valid SLIP-39 but were not made for a Holvard vault:
    /// their settings differ from spec/vault.md.
    NotHolvardCards,
    /// The operating system's random generator failed.
    RandomnessUnavailable,
    /// Encryption failed.
    Encryption,
    /// The cards recover a secret, but it does not open this vault: they
    /// belong to another vault, or the vault file is damaged.
    WrongCardsOrDamaged,
    /// The vault file is not an age file.
    NotAVault,
    /// The vault asks for more key-derivation work than Holvard allows.
    TooMuchWork,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cards(e) => e.fmt(f),
            Error::SameCardTwice => f.write_str("the same card was entered twice; use two different cards"),
            Error::NotHolvardCards => f.write_str("these cards were not made for a Holvard vault"),
            Error::RandomnessUnavailable => f.write_str("the system's random number generator failed"),
            Error::Encryption => f.write_str("the vault could not be encrypted"),
            Error::WrongCardsOrDamaged => f.write_str(
                "these cards do not open this vault; they may belong to another vault, or the vault file is damaged",
            ),
            Error::NotAVault => f.write_str("this file is not a Holvard vault"),
            Error::TooMuchWork => {
                f.write_str("this vault asks for more work to open than Holvard allows")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use age::secrecy::SecretString;

    use super::*;

    type TestResult = Result<(), Box<dyn core::error::Error>>;

    const CONTENTS: &[u8] = b"The deed is in the blue folder, top drawer.";

    fn words(vault: &Vault) -> [&str; 3] {
        let [a, b, c] = &vault.cards;
        [a.as_str(), b.as_str(), c.as_str()]
    }

    #[test]
    fn any_two_cards_open_the_vault() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, c] = words(&vault);
        for pair in [[a, b], [a, c], [b, c], [c, a]] {
            assert_eq!(open_vault(&pair, &vault.encrypted)?.as_slice(), CONTENTS);
        }
        Ok(())
    }

    // SLIP-39 combines exactly the threshold number of cards, as Trezor's
    // reference does; the caller picks two.
    #[test]
    fn three_cards_are_refused_as_in_slip39() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        assert_eq!(
            open_vault(&words(&vault), &vault.encrypted),
            Err(Error::Cards(slip39::Error::WrongNumberOfShares))
        );
        Ok(())
    }

    #[test]
    fn one_card_never_opens_the_vault() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        for card in words(&vault) {
            assert!(matches!(
                open_vault(&[card], &vault.encrypted),
                Err(Error::Cards(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn empty_contents_round_trip() -> TestResult {
        let vault = create_vault(b"")?;
        let [a, b, _] = words(&vault);
        assert!(open_vault(&[a, b], &vault.encrypted)?.is_empty());
        Ok(())
    }

    #[test]
    fn cards_from_another_vault_are_rejected() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let other = create_vault(CONTENTS)?;
        let [a, b, _] = words(&other);
        assert_eq!(
            open_vault(&[a, b], &vault.encrypted),
            Err(Error::WrongCardsOrDamaged)
        );
        Ok(())
    }

    #[test]
    fn every_vault_has_a_new_secret() -> TestResult {
        let first = create_vault(CONTENTS)?;
        let second = create_vault(CONTENTS)?;
        let secret = |v: &Vault| -> Result<Vec<u8>, slip39::Error> {
            let [a, b, _] = words(v);
            Ok(slip39::combine(&[a, b], "")?.as_bytes().to_vec())
        };
        assert_ne!(secret(&first)?, secret(&second)?);
        Ok(())
    }

    #[test]
    fn damaged_vault_is_rejected() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        let mut damaged = vault.encrypted.clone();
        let last = damaged.last_mut().ok_or("empty vault")?;
        *last ^= 1;
        assert_eq!(
            open_vault(&[a, b], &damaged),
            Err(Error::WrongCardsOrDamaged)
        );
        Ok(())
    }

    #[test]
    fn a_file_that_is_not_age_is_rejected() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        assert_eq!(open_vault(&[a, b], b"not a vault"), Err(Error::NotAVault));
        Ok(())
    }

    // spec/vault.md, reader rules: vaults are binary age; an armored file
    // (`age -a`) is not a vault. Holds because the age crate is built
    // without its `armor` feature.
    #[test]
    fn armored_age_file_is_not_a_vault() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        let armored = b"-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n";
        assert_eq!(open_vault(&[a, b], armored), Err(Error::NotAVault));
        Ok(())
    }

    // An age file for another kind of recipient (here X25519) is not a
    // Holvard vault; it must not be blamed on the cards.
    #[test]
    fn age_file_without_a_passphrase_is_not_a_vault() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        let recipient = age::x25519::Identity::generate().to_public();
        let other = age::encrypt(&recipient, CONTENTS)?;
        assert_eq!(open_vault(&[a, b], &other), Err(Error::NotAVault));
        Ok(())
    }

    // age re-reads the header after every line, so a huge header costs
    // seconds. A Holvard header is about 150 bytes; anything past 1 KiB is
    // refused before age parses it. Without the limit this takes seconds
    // even in a release build.
    #[test]
    fn huge_header_is_refused_quickly() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        let mut file = String::from("age-encryption.org/v1\n-> scrypt AAAAAAAAAAAAAAAAAAAAAA 18\n");
        while file.len() < 512 * 1024 {
            file.push_str(&"A".repeat(64));
            file.push('\n');
        }
        file.push_str("AAAA\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        let start = std::time::Instant::now();
        assert_eq!(open_vault(&[a, b], file.as_bytes()), Err(Error::NotAVault));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        Ok(())
    }

    // The whole header, up to the newline that ends its MAC line, must fit
    // in 1 KiB. Finding only "\n---" early is not enough: an unterminated
    // MAC line after it makes age read and copy the entire file.
    #[test]
    fn header_must_end_with_its_mac_line_within_1_kib() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        assert!(header_is_small(&vault.encrypted));

        let start = "age-encryption.org/v1\n-> scrypt AAAAAAAAAAAAAAAAAAAAAA 18\nAAAA\n--- ";
        let mut unterminated = start.as_bytes().to_vec();
        unterminated.resize(1024 * 1024, b'A');
        assert!(!header_is_small(&unterminated));

        // The MAC line's newline as byte 1024 (the limit in spec/vault.md)
        // is accepted; one byte later is not.
        let mut at_limit = start.as_bytes().to_vec();
        at_limit.resize(1023, b'A');
        at_limit.push(b'\n');
        assert!(header_is_small(&at_limit));
        at_limit.insert(at_limit.len() - 1, b'A');
        assert!(!header_is_small(&at_limit));
        Ok(())
    }

    #[test]
    fn same_card_twice_is_refused() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        assert_eq!(
            open_vault(&[a, a], &vault.encrypted),
            Err(Error::SameCardTwice)
        );
        assert_eq!(
            open_vault(&[a, b, a], &vault.encrypted),
            Err(Error::Cards(slip39::Error::WrongNumberOfShares))
        );
        Ok(())
    }

    /// Cards for this vault's own secret, made with other SLIP-39 settings.
    fn resplit(
        vault: &Vault,
        groups: &[Group],
        secret_len: usize,
        exponent: u8,
    ) -> Result<Vec<Vec<Mnemonic>>, Box<dyn core::error::Error>> {
        let [a, b, _] = words(vault);
        let secret = slip39::combine(&[a, b], "")?;
        let secret = secret.as_bytes().get(..secret_len).ok_or("short secret")?;
        Ok(slip39::generate(1, groups, secret, "", exponent)?)
    }

    // spec/vault.md, reader rules: only cards with Holvard's own settings
    // are accepted, checked before any key derivation. A higher iteration
    // exponent would otherwise cost up to 2^15 times more PBKDF2 work.
    #[test]
    fn cards_with_other_settings_are_refused() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let two_of_three = Group {
            threshold: 2,
            count: 3,
        };
        let cases = [
            ("exponent 1", resplit(&vault, &[two_of_three], 32, 1)?),
            (
                "3-of-3",
                resplit(
                    &vault,
                    &[Group {
                        threshold: 3,
                        count: 3,
                    }],
                    32,
                    0,
                )?,
            ),
            ("128-bit secret", resplit(&vault, &[two_of_three], 16, 0)?),
        ];
        for (name, sets) in &cases {
            let cards: Vec<&str> = sets
                .iter()
                .flatten()
                .take(2)
                .map(Mnemonic::as_str)
                .collect();
            assert_eq!(
                open_vault(&cards, &vault.encrypted),
                Err(Error::NotHolvardCards),
                "{name}"
            );
        }

        // A 1-of-1 card of the same secret would open the vault on its
        // own in plain SLIP-39; Holvard always asks for two cards.
        let single = resplit(
            &vault,
            &[Group {
                threshold: 1,
                count: 1,
            }],
            32,
            0,
        )?;
        let single: Vec<&str> = single.iter().flatten().map(Mnemonic::as_str).collect();
        assert_eq!(
            open_vault(&single, &vault.encrypted),
            Err(Error::Cards(slip39::Error::WrongNumberOfShares)),
            "1-of-1"
        );

        // Two groups of 2-of-3, either group enough: two cards of the first
        // group would recover the secret in plain SLIP-39.
        let sets = resplit(&vault, &[two_of_three, two_of_three], 32, 0)?;
        let first_group: Vec<&str> = sets
            .first()
            .ok_or("no group")?
            .iter()
            .take(2)
            .map(Mnemonic::as_str)
            .collect();
        assert_eq!(
            open_vault(&first_group, &vault.encrypted),
            Err(Error::NotHolvardCards),
            "two groups"
        );

        // A real card next to one with other settings: both are checked.
        let [a, _, _] = words(&vault);
        let other = resplit(&vault, &[two_of_three], 32, 1)?;
        let other = other.first().and_then(|g| g.first()).ok_or("no card")?;
        for mixed in [[a, other.as_str()], [other.as_str(), a]] {
            assert_eq!(
                open_vault(&mixed, &vault.encrypted),
                Err(Error::NotHolvardCards),
                "mixed"
            );
        }
        Ok(())
    }

    // A vault may ask for at most work factor 20 (what the browser age
    // library accepts). 21 is refused before any scrypt work. 20 is
    // accepted: scrypt runs in full (about 1 GiB of memory for a moment)
    // and then fails on the edited header, as the change breaks its MAC.
    #[test]
    fn work_factor_above_20_is_refused() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        for (factor, expected) in [
            ("20", Error::WrongCardsOrDamaged),
            ("21", Error::TooMuchWork),
        ] {
            let header = String::from_utf8_lossy(vault.encrypted.get(..200).ok_or("short")?)
                .lines()
                .nth(1)
                .ok_or("no stanza")?
                .to_owned();
            let (stanza, _) = header.rsplit_once(' ').ok_or("no work factor")?;
            let changed = format!("{stanza} {factor}");
            let mut edited = vault.encrypted.clone();
            let at = edited
                .windows(header.len())
                .position(|w| w == header.as_bytes())
                .ok_or("stanza not found")?;
            edited.splice(at..at + header.len(), changed.bytes());
            assert_eq!(
                open_vault(&[a, b], &edited),
                Err(expected),
                "factor {factor}"
            );
        }
        Ok(())
    }

    // spec/vault.md: a 256-bit secret, split 2-of-3 in one group, with the
    // empty passphrase and iteration exponent 0 (the `shamir create`
    // default).
    #[test]
    fn cards_are_one_group_of_two_of_three_with_exponent_zero() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let mut members = Vec::new();
        for card in words(&vault) {
            let share = Share::from_mnemonic(card)?;
            assert_eq!(share.iteration_exponent, 0);
            assert_eq!(share.group_threshold, 1);
            assert_eq!(share.group_count, 1);
            assert_eq!(share.member_threshold, 2);
            assert!(share.extendable);
            members.push(share.member_index);
        }
        members.sort_unstable();
        assert_eq!(members, [0, 1, 2]);
        let [a, b, _] = words(&vault);
        assert_eq!(slip39::combine(&[a, b], "")?.as_bytes().len(), 32);
        Ok(())
    }

    // The age half of the format, checked through the age crate directly:
    // the passphrase is the secret in lowercase hex, and scrypt uses age's
    // default work factor, 18.
    #[test]
    fn vault_is_plain_age_with_hex_passphrase_and_work_factor_18() -> TestResult {
        let vault = create_vault(CONTENTS)?;
        let [a, b, _] = words(&vault);
        let secret = slip39::combine(&[a, b], "")?;
        let mut hex = String::new();
        for byte in secret.as_bytes() {
            write!(hex, "{byte:02x}")?;
        }
        assert_eq!(hex.len(), 64);

        let header = vault.encrypted.get(..200).ok_or("short vault")?;
        let header = String::from_utf8_lossy(header);
        let stanza = header.lines().nth(1).ok_or("no stanza")?;
        assert!(stanza.starts_with("-> scrypt "), "{stanza}");
        assert!(stanza.ends_with(" 18"), "{stanza}");

        let identity = age::scrypt::Identity::new(SecretString::from(hex));
        let decryptor = age::Decryptor::new_buffered(vault.encrypted.as_slice())?;
        let mut contents = Vec::new();
        decryptor
            .decrypt(core::iter::once(&identity as &dyn age::Identity))?
            .read_to_end(&mut contents)?;
        assert_eq!(contents, CONTENTS);
        Ok(())
    }
}
