// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decoding one SLIP-39 mnemonic into its fields.

use core::fmt;

use zeroize::Zeroizing;

use super::Error;
use super::words::{MAX_WORD_LENGTH, checksum_is_valid, create_checksum, index_of, word_at};

/// Bits per word: each word is an index into the 1024-word list.
const BITS_PER_WORD: usize = 10;
/// Words that are not share value: 2 for identifier, extendable flag and
/// iteration exponent, 2 for group and member fields, 3 for the checksum.
const METADATA_WORDS: usize = 7;
const CHECKSUM_WORDS: usize = 3;
/// 7 metadata words plus 13 words (130 bits) for a 128-bit secret.
const MIN_WORDS: usize = 20;

/// One decoded mnemonic. Thresholds and counts hold their real values
/// (1-16); indices hold the raw x coordinate (0-15).
///
/// Deliberately not `PartialEq`: comparing two shares compares secret
/// bytes, which must go through [`Share::is_same_card`].
pub(crate) struct Share {
    pub identifier: u16,
    pub extendable: bool,
    pub iteration_exponent: u8,
    pub group_index: u8,
    pub group_threshold: u8,
    pub group_count: u8,
    pub member_index: u8,
    pub member_threshold: u8,
    /// The share value, wiped from memory when dropped.
    pub value: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("identifier", &self.identifier)
            .field("extendable", &self.extendable)
            .field("group_index", &self.group_index)
            .field("member_index", &self.member_index)
            .field("value", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The low `bits` bits of `value`, as a `u8`.
fn field(value: u32, shift: u32, bits: u32) -> u8 {
    let mask = 1u32.wrapping_shl(bits).wrapping_sub(1);
    // The mask keeps at most 15 bits, and callers ask for at most 4 here.
    u8::try_from(value.wrapping_shr(shift) & mask).unwrap_or(u8::MAX)
}

impl Share {
    /// Whether `other` is this very card, entered again. The public fields
    /// are compared normally; the secret value in constant time.
    pub(crate) fn is_same_card(&self, other: &Share) -> bool {
        let public_fields_equal = self.identifier == other.identifier
            && self.extendable == other.extendable
            && self.iteration_exponent == other.iteration_exponent
            && self.group_index == other.group_index
            && self.group_threshold == other.group_threshold
            && self.group_count == other.group_count
            && self.member_index == other.member_index
            && self.member_threshold == other.member_threshold
            && self.value.len() == other.value.len();
        let value_difference = self
            .value
            .iter()
            .zip(other.value.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        public_fields_equal && value_difference == 0
    }

    /// Encodes this share as a mnemonic, the reverse of
    /// [`Share::from_mnemonic`].
    pub(crate) fn to_mnemonic(&self) -> Result<Zeroizing<String>, Error> {
        let in_range = self.identifier < 1 << 15
            && self.iteration_exponent <= 15
            && self.group_index <= 15
            && self.member_index <= 15
            && (1..=16).contains(&self.group_threshold)
            && (1..=16).contains(&self.group_count)
            && (1..=16).contains(&self.member_threshold);
        if !in_range {
            return Err(Error::InvalidParameters);
        }
        // The same rule as split_secret: at least 128 bits, in 16-bit steps.
        if self.value.len() < 16 || !self.value.len().is_multiple_of(2) {
            return Err(Error::InvalidSecretLength);
        }

        // Words 0-1: identifier (15 bits), extendable flag (1), exponent (4).
        let w0 = self.identifier.wrapping_shr(5);
        let w1 = (self.identifier & 0x1f).wrapping_shl(5)
            | u16::from(self.extendable).wrapping_shl(4)
            | u16::from(self.iteration_exponent);
        // Words 2-3: five 4-bit fields; thresholds and count are stored minus 1.
        let groups = u32::from(self.group_index).wrapping_shl(16)
            | u32::from(self.group_threshold.wrapping_sub(1)).wrapping_shl(12)
            | u32::from(self.group_count.wrapping_sub(1)).wrapping_shl(8)
            | u32::from(self.member_index).wrapping_shl(4)
            | u32::from(self.member_threshold.wrapping_sub(1));
        let w2 = u16::try_from(groups.wrapping_shr(10)).map_err(|_| Error::InvalidParameters)?;
        let w3 = u16::try_from(groups & 0x3ff).map_err(|_| Error::InvalidParameters)?;

        // Every wiped buffer below is allocated once at its final size:
        // growing a Vec reallocates and frees the old buffer unwiped.
        let value_words = encode_value(&self.value)?;
        let mut data = Zeroizing::new(Vec::with_capacity(value_words.len().saturating_add(4)));
        data.extend_from_slice(&[w0, w1, w2, w3]);
        data.extend_from_slice(&value_words);

        let customization: &[u8] = if self.extendable {
            b"shamir_extendable"
        } else {
            b"shamir"
        };
        let checksum = create_checksum(customization, &data);

        // At most 8 letters and a space per word.
        let word_count = data.len().saturating_add(checksum.len());
        let mut mnemonic = Zeroizing::new(String::with_capacity(
            word_count.saturating_mul(MAX_WORD_LENGTH.saturating_add(1)),
        ));
        for (position, &index) in data.iter().chain(checksum.iter()).enumerate() {
            if position > 0 {
                mnemonic.push(' ');
            }
            mnemonic.push_str(&word_at(index).ok_or(Error::InvalidParameters)?);
        }
        Ok(mnemonic)
    }

    /// Decodes one mnemonic, following "Format of the share mnemonic" in
    /// SLIP-39.
    pub(crate) fn from_mnemonic(mnemonic: &str) -> Result<Share, Error> {
        // The word numbers are as secret as the words, so wipe them too.
        // Count the words first so the buffer never has to grow.
        let mut indices: Zeroizing<Vec<u16>> =
            Zeroizing::new(Vec::with_capacity(mnemonic.split_whitespace().count()));
        for (position, word) in (1usize..).zip(mnemonic.split_whitespace()) {
            indices.push(index_of(word).ok_or(Error::InvalidWord { position })?);
        }
        if indices.len() < MIN_WORDS {
            return Err(Error::TooShort);
        }

        // The share value is left-padded with zero bits to a multiple of 10
        // bits. Padding of more than 8 bits means the length is impossible.
        let value_word_count = indices
            .len()
            .checked_sub(METADATA_WORDS)
            .ok_or(Error::TooShort)?;
        let value_bit_count = value_word_count
            .checked_mul(BITS_PER_WORD)
            .ok_or(Error::InvalidLength)?;
        let padding = value_bit_count
            .checked_rem(16)
            .ok_or(Error::InvalidLength)?;
        if padding > 8 {
            return Err(Error::InvalidLength);
        }

        let [w0, w1, w2, w3, rest @ ..] = indices.as_slice() else {
            return Err(Error::TooShort);
        };

        // Words 0-1: identifier (15 bits), extendable flag (1), exponent (4).
        // The identifier is all 10 bits of w0 and the top 5 bits of w1; w0
        // is at most 1023, so shifting it left by 5 stays within 16 bits.
        let identifier = w0.wrapping_shl(5) | w1.wrapping_shr(5);
        let extendable = w1.wrapping_shr(4) & 1 == 1;
        let iteration_exponent = field(u32::from(*w1), 0, 4);

        let customization: &[u8] = if extendable {
            b"shamir_extendable"
        } else {
            b"shamir"
        };
        if !checksum_is_valid(customization, &indices) {
            return Err(Error::InvalidChecksum);
        }

        // Words 2-3: group index, group threshold - 1, group count - 1,
        // member index, member threshold - 1 (4 bits each).
        let groups = u32::from(*w2).wrapping_shl(10) | u32::from(*w3);
        let group_threshold = field(groups, 12, 4).wrapping_add(1);
        let group_count = field(groups, 8, 4).wrapping_add(1);
        if group_threshold > group_count {
            return Err(Error::GroupThresholdExceedsCount);
        }

        let value_words = rest
            .get(
                ..rest
                    .len()
                    .checked_sub(CHECKSUM_WORDS)
                    .ok_or(Error::TooShort)?,
            )
            .ok_or(Error::TooShort)?;
        let value = decode_value(value_words, padding)?;

        Ok(Share {
            identifier,
            extendable,
            iteration_exponent,
            group_index: field(groups, 16, 4),
            group_threshold,
            group_count,
            member_index: field(groups, 4, 4),
            member_threshold: field(groups, 0, 4).wrapping_add(1),
            value,
        })
    }
}

/// Turns bytes into 10-bit words: left-pads with zero bits to a multiple
/// of 10, then reads 10 bits at a time, most significant first. The
/// reverse of [`decode_value`].
fn encode_value(value: &[u8]) -> Result<Zeroizing<Vec<u16>>, Error> {
    let bit_count = value.len().checked_mul(8).ok_or(Error::InvalidLength)?;
    let padding = BITS_PER_WORD
        .checked_sub(
            bit_count
                .checked_rem(BITS_PER_WORD)
                .ok_or(Error::InvalidLength)?,
        )
        .ok_or(Error::InvalidLength)?
        .checked_rem(BITS_PER_WORD)
        .ok_or(Error::InvalidLength)?;
    let bits = core::iter::repeat_n(0u16, padding).chain(value.iter().flat_map(|&byte| {
        (0..8u32)
            .rev()
            .map(move |i| u16::from(byte.wrapping_shr(i) & 1))
    }));
    let word_count = bit_count
        .checked_add(padding)
        .and_then(|bits| bits.checked_div(BITS_PER_WORD))
        .ok_or(Error::InvalidLength)?;
    let mut words = Zeroizing::new(Vec::with_capacity(word_count));
    let mut word = 0u16;
    for (count, bit) in (1usize..).zip(bits) {
        word = word.wrapping_shl(1) | bit;
        if count.checked_rem(BITS_PER_WORD) == Some(0) {
            words.push(word);
            word = 0;
        }
    }
    Ok(words)
}

/// Turns 10-bit words into bytes: drops `padding` leading bits, which must
/// all be zero, then packs the rest 8 bits at a time, most significant
/// first.
fn decode_value(words: &[u16], padding: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bits = words.iter().flat_map(|&word| {
        (0..10u32)
            .rev()
            .map(move |i| u8::from(word.wrapping_shr(i) & 1 == 1))
    });
    if bits.by_ref().take(padding).any(|bit| bit != 0) {
        return Err(Error::InvalidPadding);
    }
    let byte_count = words
        .len()
        .checked_mul(BITS_PER_WORD)
        .and_then(|bits| bits.checked_sub(padding))
        .and_then(|bits| bits.checked_div(8))
        .ok_or(Error::InvalidLength)?;
    let mut value = Zeroizing::new(Vec::with_capacity(byte_count));
    let mut byte = 0u8;
    for (count, bit) in (1usize..).zip(bits) {
        byte = byte.wrapping_shl(1) | bit;
        if count.checked_rem(8) == Some(0) {
            value.push(byte);
            byte = 0;
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    // Expected fields from Trezor's reference decoder (shamir_mnemonic.Share).
    #[test]
    fn decodes_vector_4_fields() -> Result<(), Error> {
        let share = Share::from_mnemonic(
            "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
        )?;
        assert_eq!(share.identifier, 25653);
        assert!(!share.extendable);
        assert_eq!(share.iteration_exponent, 2);
        assert_eq!(share.group_index, 0);
        assert_eq!(share.group_threshold, 1);
        assert_eq!(share.group_count, 1);
        assert_eq!(share.member_index, 2);
        assert_eq!(share.member_threshold, 2);
        assert_eq!(hex(&share.value), "08fb14b66e692e25dfe2edf53289ed62");
        Ok(())
    }

    #[test]
    fn decodes_vector_43_extendable_fields() -> Result<(), Error> {
        let share = Share::from_mnemonic(
            "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish",
        )?;
        assert_eq!(share.identifier, 9066);
        assert!(share.extendable);
        assert_eq!(share.iteration_exponent, 0);
        assert_eq!(share.member_index, 0);
        assert_eq!(share.member_threshold, 2);
        assert_eq!(hex(&share.value), "a5a69aa82af0f8068a01d8e8c095ddf3");
        Ok(())
    }

    // Decoding a card and encoding it again must give back every word:
    // vector 4 (128 bits, not extendable, exponent 2), vector 43 (128 bits,
    // extendable) and a 256-bit card made with Trezor's `shamir` tool.
    #[test]
    fn encoding_a_decoded_card_gives_back_the_same_words() -> Result<(), Error> {
        for card in [
            "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
            "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish",
            "grocery lilac academic acid alpha artist camera worthy listen veteran fiscal execute grasp involve blanket warmth pancake should ounce density branch starting loan puny numb priority alarm thorn ruin unusual duckling furl triumph",
        ] {
            assert_eq!(Share::from_mnemonic(card)?.to_mnemonic()?.as_str(), card);
        }
        Ok(())
    }

    fn share_with_value(length: usize) -> Share {
        Share {
            identifier: 1,
            extendable: true,
            iteration_exponent: 0,
            group_index: 0,
            group_threshold: 1,
            group_count: 1,
            member_index: 0,
            member_threshold: 1,
            value: Zeroizing::new(vec![0u8; length]),
        }
    }

    // The encoder applies the same length rule as split_secret: at least
    // 16 bytes, in whole 2-byte steps.
    #[test]
    fn a_share_value_of_the_wrong_length_cannot_be_encoded() {
        for length in [0, 15, 17] {
            assert_eq!(
                share_with_value(length).to_mnemonic().err(),
                Some(Error::InvalidSecretLength),
                "length {length}"
            );
        }
        assert!(share_with_value(16).to_mnemonic().is_ok());
    }

    // A growing Vec reallocates and frees its old buffer unwiped, so wiped
    // buffers must be allocated once at their final size.
    #[test]
    fn encoded_value_words_are_allocated_once_at_their_final_size() -> Result<(), Error> {
        for length in [16, 32] {
            let words = encode_value(&vec![0xa5; length])?;
            assert_eq!(words.capacity(), words.len(), "{length}-byte value");
        }
        Ok(())
    }

    #[test]
    fn rejects_an_unknown_word_and_says_which() {
        assert_eq!(
            Share::from_mnemonic(
                "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding bitcoin"
            ).err(),
            Some(Error::InvalidWord { position: 20 })
        );
        // The first unknown word is reported, counting from 1.
        assert_eq!(
            Share::from_mnemonic("nonsense academic").err(),
            Some(Error::InvalidWord { position: 1 })
        );
    }

    #[test]
    fn rejects_vector_2_invalid_checksum() {
        assert_eq!(
            Share::from_mnemonic(
                "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
            ).err(),
            Some(Error::InvalidChecksum)
        );
    }

    #[test]
    fn rejects_vector_3_invalid_padding() {
        assert_eq!(
            Share::from_mnemonic(
                "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
            ).err(),
            Some(Error::InvalidPadding)
        );
    }

    #[test]
    fn rejects_vector_39_insufficient_length() {
        assert_eq!(
            Share::from_mnemonic(
                "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
            ).err(),
            Some(Error::TooShort)
        );
    }

    #[test]
    fn rejects_vector_10_group_threshold_above_group_count() {
        assert_eq!(
            Share::from_mnemonic(
                "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome"
            ).err(),
            Some(Error::GroupThresholdExceedsCount)
        );
    }
}
