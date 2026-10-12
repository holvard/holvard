// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The SLIP-39 wordlist and the RS1024 checksum over word indices.

use zeroize::Zeroizing;

/// The 1024 words, one per line, in alphabetical order. The file is checked
/// against its upstream copies by `scripts/check-upstream.sh`.
const WORDLIST: &str = include_str!("../../../../test-vectors/slip39/wordlist.txt");

/// No SLIP-39 word is longer than this.
pub(crate) const MAX_WORD_LENGTH: usize = 8;

/// `word`'s bytes, zero-padded to `MAX_WORD_LENGTH`, or `None` if longer.
fn padded(word: &str) -> Option<[u8; MAX_WORD_LENGTH]> {
    let mut out = [0u8; MAX_WORD_LENGTH];
    if word.len() > MAX_WORD_LENGTH {
        return None;
    }
    for (slot, byte) in out.iter_mut().zip(word.bytes()) {
        *slot = byte;
    }
    Some(out)
}

/// Index of `word` in the SLIP-39 wordlist, or `None` if it is not a word.
///
/// The words on a card are secret, so the lookup compares `word` with all
/// 1024 entries every time, without stopping at a match and without
/// branching on the bytes, so the time taken does not reveal which word
/// it was. Only "longer than any SLIP-39 word" returns early.
pub(crate) fn index_of(word: &str) -> Option<u16> {
    let wanted = padded(word)?;
    let mut found = 0u16;
    let mut matches = 0u16;
    for (index, entry) in (0u16..).zip(WORDLIST.lines()) {
        // Never taken for the vendored list: every entry is at most 8
        // letters (checked by `scripts/check-upstream.sh` and the test
        // `the_wordlist_has_1024_words_of_at_most_8_letters`). Even if it
        // were, 0xff never occurs in UTF-8, so no input could match it.
        let candidate = padded(entry).unwrap_or([0xff; MAX_WORD_LENGTH]);
        // Lengths are compared too, so zero padding cannot hide a NUL byte.
        let mut difference = u8::from(entry.len() != word.len());
        for (a, b) in candidate.iter().zip(wanted.iter()) {
            difference |= a ^ b;
        }
        let is_match = u16::from(difference == 0);
        found |= index & 0u16.wrapping_sub(is_match); // keep index if matched
        matches |= is_match;
    }
    (matches == 1).then_some(found)
}

/// Number of words in the SLIP-39 wordlist.
const WORD_COUNT: u16 = 1024;

/// The word at `index` in the SLIP-39 wordlist, or `None` past the end.
///
/// Like [`index_of`], it visits all 1024 entries and keeps the wanted one
/// through a mask, so the time taken does not reveal the index. The result
/// is wiped when dropped, since it is part of a card.
pub(crate) fn word_at(index: u16) -> Option<Zeroizing<String>> {
    if index >= WORD_COUNT {
        return None;
    }
    let mut bytes = Zeroizing::new([0u8; MAX_WORD_LENGTH]);
    let mut length = 0usize;
    for (position, entry) in (0u16..).zip(WORDLIST.lines()) {
        let selected = position == index;
        let keep = 0u8.wrapping_sub(u8::from(selected)); // 0xff or 0
        let keep_length = 0usize.wrapping_sub(usize::from(selected)); // all ones or 0
        // Entries are at most 8 bytes (tested), so padding always succeeds.
        let candidate = padded(entry).unwrap_or([0; MAX_WORD_LENGTH]);
        for (out, byte) in bytes.iter_mut().zip(candidate) {
            *out |= byte & keep;
        }
        length |= entry.len() & keep_length;
    }
    let word = bytes.get(..length)?;
    String::from_utf8(word.to_vec()).ok().map(Zeroizing::new)
}

/// Generator of the RS1024 code, from SLIP-39 section "Checksum".
const GEN: [u32; 10] = [
    0x00e0_e040,
    0x01c1_c080,
    0x0383_8100,
    0x0707_0200,
    0x0e0e_0009,
    0x1c0c_2412,
    0x3808_6c24,
    0x3090_fc48,
    0x21b1_f890,
    0x03f3_f120,
];

/// RS1024 polymod over the customization string followed by `values`,
/// a direct translation of `rs1024_polymod` in the SLIP-39 spec. Each value
/// is a 10-bit word index; `chk` holds 30 bits.
fn polymod(customization: &[u8], values: &[u16]) -> u32 {
    let inputs = customization
        .iter()
        .map(|&c| u32::from(c))
        .chain(values.iter().map(|&v| u32::from(v)));
    let mut chk: u32 = 1;
    for value in inputs {
        let top = chk.wrapping_shr(20);
        chk = (chk & 0x000f_ffff).wrapping_shl(10) ^ value;
        for (i, generator) in (0u32..).zip(GEN) {
            // XOR the generator in when bit i of `top` is set; a mask
            // instead of a branch, since the words are secret.
            chk ^= generator & 0u32.wrapping_sub(top.wrapping_shr(i) & 1);
        }
    }
    chk
}

/// The three checksum words for `data` (word indices without checksum),
/// following `rs1024_create_checksum` in the SLIP-39 spec: run the polymod
/// over the data followed by three zero words, XOR with 1, and split the
/// 30-bit result into three 10-bit words.
pub(crate) fn create_checksum(customization: &[u8], data: &[u16]) -> [u16; 3] {
    // The data words are secret, so the working copy is wiped when dropped,
    // and allocated once at its final size so it never reallocates.
    let mut values = Zeroizing::new(Vec::with_capacity(data.len().saturating_add(3)));
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0]);
    let residue = polymod(customization, &values) ^ 1;
    let word = |shift: u32| -> u16 {
        // Masked to 10 bits, so the conversion cannot fail.
        u16::try_from(residue.wrapping_shr(shift) & 0x3ff).unwrap_or(0)
    };
    [word(20), word(10), word(0)]
}

/// Whether `values` (word indices, checksum included) carry a valid RS1024
/// checksum for the customization string `customization`.
pub(crate) fn checksum_is_valid(customization: &[u8], values: &[u16]) -> bool {
    polymod(customization, values) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indices(mnemonic: &str) -> Vec<u16> {
        mnemonic.split(' ').filter_map(index_of).collect()
    }

    // Vector 4 (extendable flag 0) and vector 43 (extendable flag 1).
    const VECTOR_4: &str = "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed";
    const VECTOR_43: &str = "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish";
    // Vector 2: vector 1 with the last word changed, so the checksum fails.
    const VECTOR_2: &str = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney";

    #[test]
    fn words_map_to_their_position_in_the_list() {
        assert_eq!(index_of("academic"), Some(0));
        assert_eq!(index_of("western"), Some(1002));
        assert_eq!(index_of("zero"), Some(1023));
        assert_eq!(index_of("bitcoin"), None);
        assert_eq!(index_of(""), None);
        assert_eq!(index_of("Academic"), None);
    }

    #[test]
    fn the_wordlist_has_1024_words_of_at_most_8_letters() {
        assert_eq!(WORDLIST.lines().count(), 1024);
        assert!(
            WORDLIST
                .lines()
                .all(|w| (4..=MAX_WORD_LENGTH).contains(&w.len()))
        );
    }

    #[test]
    fn indices_map_back_to_their_words() {
        let word = |i| word_at(i).map(|w| w.as_str().to_owned());
        assert_eq!(word(0).as_deref(), Some("academic"));
        assert_eq!(word(1).as_deref(), Some("acid"));
        assert_eq!(word(1002).as_deref(), Some("western"));
        assert_eq!(word(1023).as_deref(), Some("zero"));
        assert_eq!(word(1024), None);
    }

    #[test]
    fn near_misses_are_not_words() {
        assert_eq!(index_of("academi"), None); // a prefix
        assert_eq!(index_of("academics"), None); // a word plus a letter
        assert_eq!(index_of("acid\0"), None); // padding must not hide a NUL
        assert_eq!(index_of("acid\0\0\0\0"), None);
        assert_eq!(index_of("zerozerozero"), None); // longer than any word
        assert_eq!(index_of("acid"), Some(1));
    }

    #[test]
    fn valid_checksums_verify_with_their_customization_string() {
        assert!(checksum_is_valid(b"shamir", &indices(VECTOR_4)));
        assert!(checksum_is_valid(b"shamir_extendable", &indices(VECTOR_43)));
    }

    #[test]
    fn created_checksum_equals_the_cards_last_three_words() {
        for (customization, card) in [
            (b"shamir".as_slice(), VECTOR_4),
            (b"shamir_extendable".as_slice(), VECTOR_43),
        ] {
            let words = indices(card);
            let (data, checksum) = words.split_at(words.len().saturating_sub(3));
            assert_eq!(create_checksum(customization, data).as_slice(), checksum);
        }
    }

    #[test]
    fn a_changed_word_breaks_the_checksum() {
        assert!(!checksum_is_valid(b"shamir", &indices(VECTOR_2)));
    }

    #[test]
    fn the_wrong_customization_string_breaks_the_checksum() {
        assert!(!checksum_is_valid(b"shamir_extendable", &indices(VECTOR_4)));
        assert!(!checksum_is_valid(b"shamir", &indices(VECTOR_43)));
    }
}
