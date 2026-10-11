// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The SLIP-39 wordlist and the RS1024 checksum over word indices.

/// The 1024 words, one per line, in alphabetical order. The file is checked
/// against its upstream copies by `scripts/check-upstream.sh`.
const WORDLIST: &str = include_str!("../../../../test-vectors/slip39/wordlist.txt");

/// No SLIP-39 word is longer than this.
const MAX_WORD_LENGTH: usize = 8;

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
    fn a_changed_word_breaks_the_checksum() {
        assert!(!checksum_is_valid(b"shamir", &indices(VECTOR_2)));
    }

    #[test]
    fn the_wrong_customization_string_breaks_the_checksum() {
        assert!(!checksum_is_valid(b"shamir_extendable", &indices(VECTOR_4)));
        assert!(!checksum_is_valid(b"shamir", &indices(VECTOR_43)));
    }
}
