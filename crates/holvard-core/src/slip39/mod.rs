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

/// Why a set of mnemonics could not be combined.
///
/// More variants will be added (for creating shares), so matching on it
/// needs a wildcard arm.
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
}

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
    // SLIP-39 "Passphrase": printable ASCII only (code points 32 to 126).
    if !passphrase.bytes().all(|b| (32..=126).contains(&b)) {
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

    #[test]
    fn the_secret_is_never_printed() -> Result<(), Error> {
        let secret = combine(&[CARD_1, CARD_2], "")?;
        assert_eq!(format!("{secret:?}"), "MasterSecret(<redacted>)");
        Ok(())
    }
}
