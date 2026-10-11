// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SLIP-39: Shamir's secret sharing for mnemonic codes.
//!
//! Holvard's own port of [SLIP-0039], checked against Trezor's reference
//! test vectors in `test-vectors/slip39/`.
//!
//! [SLIP-0039]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md

use core::fmt;

use zeroize::Zeroizing;

use share::Share;

mod cipher;
mod gf256;
mod shamir;
mod share;
mod words;

/// A recovered master secret. Never printed, and wiped from memory when
/// dropped.
pub struct MasterSecret(Zeroizing<Vec<u8>>);

impl MasterSecret {
    /// The secret's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

/// One card's words. Wiped from memory when dropped, and never printed.
pub struct Mnemonic(Zeroizing<String>);

impl Mnemonic {
    /// The words, separated by single spaces.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mnemonic(<redacted>)")
    }
}

/// One group in a set of cards: how many of its `count` cards are needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Group {
    /// Cards needed from this group (1 to `count`).
    pub threshold: u8,
    /// Cards in this group (1 to 16).
    pub count: u8,
}

/// Creates a set of cards for `master_secret`, following "Generating the
/// shares" in SLIP-39: `group_threshold` of the `groups` are needed, and
/// within each group its own threshold of cards.
///
/// Returns the cards group by group. Holvard always passes the empty
/// passphrase; other values exist for the reference and other SLIP-39
/// software.
///
/// # Errors
///
/// Returns an error if the settings are outside what SLIP-39 allows, the
/// secret is not 128 bits or more in whole 16-bit steps, the passphrase is
/// not printable ASCII, or the random generator fails.
pub fn generate(
    group_threshold: u8,
    groups: &[Group],
    master_secret: &[u8],
    passphrase: &str,
    iteration_exponent: u8,
) -> Result<Vec<Vec<Mnemonic>>, Error> {
    if !is_valid_passphrase(passphrase) {
        return Err(Error::InvalidPassphrase);
    }
    if master_secret.len() < 16 || !master_secret.len().is_multiple_of(2) {
        return Err(Error::InvalidSecretLength);
    }
    let group_count = u8::try_from(groups.len()).map_err(|_| Error::InvalidParameters)?;
    let settings_valid = iteration_exponent <= 15
        && (1..=16).contains(&group_count)
        && (1..=group_count).contains(&group_threshold)
        && groups.iter().all(|g| {
            (1..=16).contains(&g.count)
                && (1..=g.count).contains(&g.threshold)
                // SLIP-39 step 1: a 1-of-N group with N > 1 would just be
                // N copies of the same card, so it is not allowed.
                && !(g.threshold == 1 && g.count > 1)
        });
    if !settings_valid {
        return Err(Error::InvalidParameters);
    }

    // A random 15-bit identifier; new sets are always extendable.
    let mut random = [0u8; 2];
    getrandom::fill(&mut random).map_err(|_| Error::RandomnessUnavailable)?;
    let identifier = u16::from_be_bytes(random) & 0x7fff;
    let extendable = true;

    let encrypted = cipher::encrypt(
        master_secret,
        passphrase.as_bytes(),
        iteration_exponent,
        identifier,
        extendable,
    )?;

    // First split into group shares, then each group share into cards.
    let group_shares = shamir::split_secret(group_threshold, group_count, &encrypted)?;
    let mut sets = Vec::with_capacity(groups.len());
    for (group, (group_index, group_share)) in groups.iter().zip(&group_shares) {
        let members = shamir::split_secret(group.threshold, group.count, group_share)?;
        let mut cards = Vec::with_capacity(members.len());
        for (member_index, value) in members {
            let share = Share {
                identifier,
                extendable,
                iteration_exponent,
                group_index: *group_index,
                group_threshold,
                group_count,
                member_index,
                member_threshold: group.threshold,
                value,
            };
            cards.push(Mnemonic(share.to_mnemonic()?));
        }
        sets.push(cards);
    }
    Ok(sets)
}

/// SLIP-39 "Passphrase": printable ASCII only (code points 32 to 126).
fn is_valid_passphrase(passphrase: &str) -> bool {
    passphrase.bytes().all(|b| (32..=126).contains(&b))
}

/// Why a set of mnemonics could not be combined.
///
/// Variants may be added, so matching on it needs a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// No mnemonics were given.
    NoShares,
    /// The passphrase contains characters other than printable ASCII.
    InvalidPassphrase,
    /// A word is not in the SLIP-39 wordlist.
    InvalidWord,
    /// A mnemonic has too few words to hold a 128-bit secret.
    TooShort,
    /// A mnemonic's last three words do not match the rest (a typo, or a
    /// word from another card).
    InvalidChecksum,
    /// A mnemonic's padding bits are not all zero.
    InvalidPadding,
    /// A mnemonic claims more groups are needed than exist.
    GroupThresholdExceedsCount,
    /// A mnemonic has an impossible number of words, the secret is not a
    /// whole, even number of bytes, or the shares differ in length.
    InvalidLength,
    /// The recovered secret does not match its digest: the cards do not
    /// belong together, or one was changed.
    DigestMismatch,
    /// Two shares have the same index.
    DuplicateShareIndex,
    /// The mnemonics come from different sets: their identifier, settings
    /// or lengths differ.
    SharesDoNotMatch,
    /// The mnemonics cover a different number of groups than the group
    /// threshold requires.
    WrongNumberOfGroups,
    /// A group has a different number of mnemonics than its member
    /// threshold requires.
    WrongNumberOfShares,
    /// Thresholds, counts, indices or the iteration exponent are outside
    /// what SLIP-39 allows.
    InvalidParameters,
    /// The secret is shorter than 16 bytes or not a whole number of 2-byte
    /// steps.
    InvalidSecretLength,
    /// The operating system's random generator failed.
    RandomnessUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::NoShares => "no cards were given",
            Error::InvalidPassphrase => "the passphrase may only use printable ASCII characters",
            Error::InvalidWord => "a word is not in the SLIP-39 word list; check the spelling",
            Error::TooShort => "a card has too few words",
            Error::InvalidChecksum => {
                "a card's words do not check out; look for a typo or a word from another card"
            }
            Error::InvalidPadding => "a card's words do not form a valid card",
            Error::GroupThresholdExceedsCount => "a card asks for more groups than exist",
            Error::InvalidLength => "a card has an impossible number of words",
            Error::DigestMismatch => "these cards do not belong together, or one was mistyped",
            Error::DuplicateShareIndex => "two different cards have the same number in one group",
            Error::SharesDoNotMatch => "these cards come from different sets",
            Error::WrongNumberOfGroups => "a different number of groups is needed",
            Error::WrongNumberOfShares => "a group needs a different number of cards",
            Error::InvalidParameters => "these settings are outside what SLIP-39 allows",
            Error::RandomnessUnavailable => "the system's random number generator failed",
            Error::InvalidSecretLength => {
                "the secret must be 16 bytes or more, in whole 2-byte steps"
            }
        })
    }
}

impl core::error::Error for Error {}

/// Combines SLIP-39 mnemonics into the master secret they were made from,
/// following "Combining the shares" in SLIP-39.
///
/// Holvard always uses the empty passphrase; other passphrases exist for
/// the reference test vectors and other SLIP-39 software.
///
/// # Errors
///
/// Returns an error if a mnemonic is malformed, if the mnemonics do not
/// belong to one set, if there are too few or too many of them, or if the
/// recovered secret fails its digest check.
pub fn combine(mnemonics: &[&str], passphrase: &str) -> Result<MasterSecret, Error> {
    if !is_valid_passphrase(passphrase) {
        return Err(Error::InvalidPassphrase);
    }
    let shares = mnemonics
        .iter()
        .map(|m| Share::from_mnemonic(m))
        .collect::<Result<Vec<Share>, Error>>()?;
    let first = shares.first().ok_or(Error::NoShares)?;

    // All shares must come from the same set.
    let same_set = |s: &Share| {
        s.identifier == first.identifier
            && s.extendable == first.extendable
            && s.iteration_exponent == first.iteration_exponent
            && s.group_threshold == first.group_threshold
            && s.group_count == first.group_count
            && s.value.len() == first.value.len()
    };
    if !shares.iter().all(same_set) {
        return Err(Error::SharesDoNotMatch);
    }

    // Sort into groups, in order of first appearance. The same card entered
    // twice counts once; two different cards with the same member index
    // are a mistake (SLIP-39: member indices MUST be pairwise distinct).
    let mut groups: Vec<(u8, Vec<&Share>)> = Vec::new();
    for share in &shares {
        match groups
            .iter_mut()
            .find(|(index, _)| *index == share.group_index)
        {
            Some((_, members)) => {
                match members
                    .iter()
                    .find(|m| m.member_index == share.member_index)
                {
                    Some(existing) if existing.is_same_card(share) => {}
                    Some(_) => return Err(Error::DuplicateShareIndex),
                    None => members.push(share),
                }
            }
            None => groups.push((share.group_index, vec![share])),
        }
    }
    if groups.len() != usize::from(first.group_threshold) {
        return Err(Error::WrongNumberOfGroups);
    }

    // Recover each group's share from its members.
    let mut group_secrets: Vec<(u8, Zeroizing<Vec<u8>>)> = Vec::with_capacity(groups.len());
    for (group_index, members) in &groups {
        let member_threshold = members.first().map_or(0, |m| m.member_threshold);
        if members
            .iter()
            .any(|m| m.member_threshold != member_threshold)
        {
            return Err(Error::SharesDoNotMatch);
        }
        if members.len() != usize::from(member_threshold) {
            return Err(Error::WrongNumberOfShares);
        }
        let points: Vec<(u8, &[u8])> = members
            .iter()
            .map(|m| (m.member_index, m.value.as_slice()))
            .collect();
        let group_secret = shamir::recover_secret(member_threshold, &points)?;
        group_secrets.push((*group_index, group_secret));
    }

    // Recover the encrypted master secret from the group shares.
    let points: Vec<(u8, &[u8])> = group_secrets
        .iter()
        .map(|(index, secret)| (*index, secret.as_slice()))
        .collect();
    let encrypted = shamir::recover_secret(first.group_threshold, &points)?;

    let secret = cipher::decrypt(
        &encrypted,
        passphrase.as_bytes(),
        first.iteration_exponent,
        first.identifier,
        first.extendable,
    )?;
    Ok(MasterSecret(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 2-of-3 set made with Trezor's reference tool (`shamir create 2of3
    // -s 256 -x`), empty passphrase, 256-bit master secret
    // 0844a06a5960e57cc19d2cc0c1eb33b4801e9d488838d5eaaf86a1bd3a1fd5e5.
    const CARD_1: &str = "grocery lilac academic acid alpha artist camera worthy listen veteran fiscal execute grasp involve blanket warmth pancake should ounce density branch starting loan puny numb priority alarm thorn ruin unusual duckling furl triumph";
    const CARD_2: &str = "grocery lilac academic agency armed coding human exotic puny physics shelter mandate withdraw speak slap birthday racism surprise uncover grasp medical pencil manual prospect safari modern package vampire boring thumb upstairs exotic building";
    const CARD_3: &str = "grocery lilac academic always adorn tactics webcam pacific freshman faint index science else remind rhythm cause lyrics together ivory nylon loan involve minister purchase dynamic firefly darkness payroll hospital wavy aquatic saver gesture";

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn any_two_of_three_cards_recover_the_secret() -> Result<(), Error> {
        let expected = "0844a06a5960e57cc19d2cc0c1eb33b4801e9d488838d5eaaf86a1bd3a1fd5e5";
        for pair in [
            [CARD_1, CARD_2],
            [CARD_1, CARD_3],
            [CARD_2, CARD_3],
            [CARD_3, CARD_1],
        ] {
            assert_eq!(hex(combine(&pair, "")?.as_bytes()), expected);
        }
        Ok(())
    }

    #[test]
    fn one_card_alone_is_refused() {
        for card in [CARD_1, CARD_2, CARD_3] {
            assert_eq!(
                combine(&[card], "").map(|_| ()),
                Err(Error::WrongNumberOfShares)
            );
        }
    }

    // SLIP-39 "Combining the shares": the count M of a group MUST equal its
    // threshold T, so three cards of a 2-of-3 set are refused too.
    #[test]
    fn three_cards_of_a_two_of_three_set_are_refused() {
        assert_eq!(
            combine(&[CARD_1, CARD_2, CARD_3], "").map(|_| ()),
            Err(Error::WrongNumberOfShares)
        );
    }

    #[test]
    fn the_same_card_twice_is_not_two_cards() {
        assert_eq!(
            combine(&[CARD_1, CARD_1], "").map(|_| ()),
            Err(Error::WrongNumberOfShares)
        );
    }

    // Vector 14: one group share where two groups are required.
    #[test]
    fn vector_14_too_few_groups_is_refused_for_that_reason() {
        let card = "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";
        assert_eq!(
            combine(&[card], "TREZOR").map(|_| ()),
            Err(Error::WrongNumberOfGroups)
        );
    }

    // Vector 40: 21 words leave 12 padding bits, more than the 8 allowed.
    #[test]
    fn vector_40_impossible_length_is_refused_for_that_reason() {
        let card = "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter";
        assert_eq!(
            combine(&[card], "TREZOR").map(|_| ()),
            Err(Error::InvalidLength)
        );
    }

    // Vector 6: two cards from different sets.
    #[test]
    fn vector_6_cards_from_different_sets_are_refused_for_that_reason() {
        let cards = [
            "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
            "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner",
        ];
        assert_eq!(
            combine(&cards, "TREZOR").map(|_| ()),
            Err(Error::SharesDoNotMatch)
        );
    }

    // Vector 11: two different cards with the same member index.
    #[test]
    fn vector_11_two_different_cards_with_one_index_are_refused_for_that_reason() {
        let cards = [
            "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
            "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps",
        ];
        assert_eq!(
            combine(&cards, "TREZOR").map(|_| ()),
            Err(Error::DuplicateShareIndex)
        );
    }

    #[test]
    fn a_non_ascii_passphrase_is_refused() {
        assert_eq!(
            combine(&[CARD_1, CARD_2], "ključ").map(|_| ()),
            Err(Error::InvalidPassphrase)
        );
    }

    #[test]
    fn no_cards_is_refused() {
        assert_eq!(combine(&[], "").map(|_| ()), Err(Error::NoShares));
    }

    const SECRET_32: &str = "0844a06a5960e57cc19d2cc0c1eb33b4801e9d488838d5eaaf86a1bd3a1fd5e5";

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .filter_map(|i| hex.get(i..i.wrapping_add(2)))
            .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
            .collect()
    }

    fn recover(cards: &[&Mnemonic], passphrase: &str) -> Result<String, Error> {
        let words: Vec<&str> = cards.iter().map(|c| c.as_str()).collect();
        Ok(hex(combine(&words, passphrase)?.as_bytes()))
    }

    fn group(threshold: u8, count: u8) -> Group {
        Group { threshold, count }
    }

    #[test]
    fn two_of_three_any_two_recover_and_one_never_does() -> Result<(), Error> {
        let sets = generate(1, &[group(2, 3)], &bytes(SECRET_32), "", 0)?;
        let [cards] = sets.as_slice() else {
            return Err(Error::InvalidParameters);
        };
        let [a, b, c] = cards.as_slice() else {
            return Err(Error::InvalidParameters);
        };
        for pair in [[a, b], [a, c], [b, c], [c, a]] {
            assert_eq!(recover(&pair, "")?, SECRET_32);
        }
        for single in [a, b, c] {
            assert_eq!(recover(&[single], ""), Err(Error::WrongNumberOfShares));
        }
        Ok(())
    }

    // The group example from docs/design.md: heirs 2 of 3, Holvard 1 of 1,
    // backup holder 1 of 1, any 2 of the 3 groups.
    #[test]
    fn the_family_example_opens_with_any_two_groups_only() -> Result<(), Error> {
        let secret = "bb54aac4b89dc868ba37d9cc21b2cece";
        let sets = generate(
            2,
            &[group(2, 3), group(1, 1), group(1, 1)],
            &bytes(secret),
            "",
            0,
        )?;
        let [heirs, keeper, backup] = sets.as_slice() else {
            return Err(Error::InvalidParameters);
        };
        let ([h1, h2, h3], [k], [b]) = (heirs.as_slice(), keeper.as_slice(), backup.as_slice())
        else {
            return Err(Error::InvalidParameters);
        };
        assert_eq!(recover(&[h1, h3, k], "")?, secret); // two heirs + Holvard
        assert_eq!(recover(&[h2, h3, b], "")?, secret); // two heirs + backup
        assert_eq!(recover(&[k, b], "")?, secret); // Holvard + backup
        assert_eq!(recover(&[h1, h2, h3], ""), Err(Error::WrongNumberOfGroups)); // heirs alone
        assert_eq!(recover(&[h1, k], ""), Err(Error::WrongNumberOfShares)); // one heir + Holvard
        Ok(())
    }

    #[test]
    fn a_passphrase_and_a_128_bit_secret_round_trip() -> Result<(), Error> {
        let secret = "bb54aac4b89dc868ba37d9cc21b2cece";
        let sets = generate(1, &[group(2, 2)], &bytes(secret), "TREZOR", 1)?;
        let cards: Vec<&Mnemonic> = sets.iter().flatten().collect();
        assert_eq!(recover(&cards, "TREZOR")?, secret);
        Ok(())
    }

    // SLIP-39: the identifier and exponent are the first two words, so all
    // cards of a set share them; cards of one group share the first three.
    #[test]
    fn cards_of_a_set_share_their_first_words() -> Result<(), Error> {
        let sets = generate(2, &[group(2, 3), group(3, 5)], &bytes(SECRET_32), "", 0)?;
        let first_words = |m: &Mnemonic, n: usize| -> String {
            m.as_str().split(' ').take(n).collect::<Vec<_>>().join(" ")
        };
        let all: Vec<&Mnemonic> = sets.iter().flatten().collect();
        assert_eq!(all.len(), 8);
        let set_prefix = all.first().map(|m| first_words(m, 2));
        assert!(all.iter().all(|m| Some(first_words(m, 2)) == set_prefix));
        for cards in &sets {
            let group_prefix = cards.first().map(|m| first_words(m, 3));
            assert!(
                cards
                    .iter()
                    .all(|m| Some(first_words(m, 3)) == group_prefix)
            );
        }
        Ok(())
    }

    // SLIP-39 "Generating the shares", step 3: new sets are extendable.
    #[test]
    fn new_sets_are_extendable() -> Result<(), Error> {
        let sets = generate(1, &[group(2, 3)], &bytes(SECRET_32), "", 0)?;
        for card in sets.iter().flatten() {
            assert!(Share::from_mnemonic(card.as_str())?.extendable);
        }
        Ok(())
    }

    #[test]
    fn each_new_set_gets_its_own_identifier() -> Result<(), Error> {
        let first_two = |sets: &[Vec<Mnemonic>]| -> Option<String> {
            let card = sets.first()?.first()?;
            Some(
                card.as_str()
                    .split(' ')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        };
        // The identifier is 15 random bits; 5 equal pairs in a row would
        // happen by chance about once in 10^22 runs.
        let mut differ = false;
        for _ in 0..5 {
            let a = generate(1, &[group(2, 3)], &bytes(SECRET_32), "", 0)?;
            let b = generate(1, &[group(2, 3)], &bytes(SECRET_32), "", 0)?;
            differ |= first_two(&a) != first_two(&b);
        }
        assert!(differ);
        Ok(())
    }

    #[test]
    fn settings_outside_slip_39_are_refused() {
        let secret = bytes(SECRET_32);
        let refuse = |gt: u8, groups: &[Group], ms: &[u8], p: &str, e: u8| {
            generate(gt, groups, ms, p, e).map(|_| ()).err()
        };
        let invalid = Some(Error::InvalidParameters);
        assert_eq!(refuse(1, &[group(1, 2)], &secret, "", 0), invalid); // 1-of-2 not allowed
        assert_eq!(refuse(0, &[group(2, 3)], &secret, "", 0), invalid); // no groups needed
        assert_eq!(refuse(2, &[group(2, 3)], &secret, "", 0), invalid); // more than exist
        assert_eq!(refuse(1, &[], &secret, "", 0), invalid); // no groups at all
        assert_eq!(refuse(1, &[group(1, 1); 17], &secret, "", 0), invalid); // 17 groups
        assert_eq!(refuse(1, &[group(4, 3)], &secret, "", 0), invalid); // threshold > count
        assert_eq!(refuse(1, &[group(2, 17)], &secret, "", 0), invalid); // 17 cards
        assert_eq!(refuse(1, &[group(2, 3)], &secret, "", 16), invalid); // exponent > 15
        let short = secret.get(..15).unwrap_or_default();
        assert_eq!(
            refuse(1, &[group(2, 3)], short, "", 0),
            Some(Error::InvalidSecretLength)
        );
        assert_eq!(
            refuse(1, &[group(2, 3)], &[0u8; 17], "", 0),
            Some(Error::InvalidSecretLength)
        );
        assert_eq!(
            refuse(1, &[group(2, 3)], &secret, "ključ", 0),
            Some(Error::InvalidPassphrase)
        );
    }

    #[test]
    fn cards_are_never_printed() -> Result<(), Error> {
        let sets = generate(1, &[group(2, 3)], &bytes(SECRET_32), "", 0)?;
        let printed = format!("{sets:?}");
        assert!(printed.contains("Mnemonic(<redacted>)"));
        assert!(!printed.contains("academic"));
        Ok(())
    }

    #[test]
    fn the_secret_is_never_printed() -> Result<(), Error> {
        let secret = combine(&[CARD_1, CARD_2], "")?;
        assert_eq!(format!("{secret:?}"), "MasterSecret(<redacted>)");
        Ok(())
    }
}
