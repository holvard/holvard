// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Holvard core: key generation, vault encryption with age, SLIP-39 split and
//! combine, and card encoding.
//!
//! This crate does no network access and contains no `unsafe` code. It holds
//! glue around established libraries only; it implements no cryptographic
//! primitives itself.

// "No panics on bad input" (AGENTS.md): out-of-bounds indexing and integer
// overflow must be handled explicitly, with `get`, `checked_*` and the like.
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// Version of the Holvard card and vault format this crate implements.
///
/// Version 1 is frozen once the spec is published; later versions only add.
pub const FORMAT_VERSION: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_version_is_one() {
        assert_eq!(FORMAT_VERSION, 1);
    }
}
