#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Cross-checks Holvard against independent implementations:
#   - every vault Holvard encrypts must decrypt with the official `age` tool
#   - every card set must recover with Trezor's reference SLIP-39
#     implementation (`shamir` from python-shamir-mnemonic), and back
#
# Requires: age and age-plugin-batchpass (age 1.3 or later), shamir
# (pip install --require-hashes -r scripts/cross-check/requirements.txt),
# a built `holvard`.

set -eu
cd "$(git rev-parse --show-toplevel)"

command -v age >/dev/null || { echo "age not found" >&2; exit 1; }
command -v age-plugin-batchpass >/dev/null || { echo "age-plugin-batchpass not found" >&2; exit 1; }
command -v shamir >/dev/null || { echo "shamir not found" >&2; exit 1; }
age --version
shamir --help >/dev/null

HOLVARD=${HOLVARD:-target/release/holvard}
[ -x "$HOLVARD" ] || { echo "$HOLVARD not built" >&2; exit 1; }
"$HOLVARD" --version

# SLIP-39, both directions: cards Holvard creates recover with `shamir`,
# and cards `shamir` creates recover with Holvard. These tests are ignored
# by plain `cargo test` because they need the `shamir` CLI.
echo "Cross-check: SLIP-39 against Trezor's shamir"
cargo test --locked -p holvard-core --test slip39_cross_check -- --ignored

# Whole vaults, both directions: a vault Holvard creates opens with
# `shamir recover` and `age -d` alone, and a vault made with `shamir create`
# and `age -e` opens with Holvard.
echo "Cross-check: vaults against shamir and age"
cargo test --locked -p holvard-core --test vault_cross_check -- --ignored

# The CLI, both directions: a folder packed by `holvard create` comes back
# with `shamir recover`, `age -d` and `unzip`; a folder zipped with `zip`
# and encrypted with `age` comes back with `holvard recover`.
echo "Cross-check: holvard create/recover against shamir, age and zip"
command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
command -v unzip >/dev/null || { echo "unzip not found" >&2; exit 1; }
cargo test --locked -p holvard --test cli_cross_check -- --ignored
