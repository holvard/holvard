#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Cross-checks Holvard against independent implementations:
#   - every vault Holvard encrypts must decrypt with the official `age` tool
#   - every card set must recover with Trezor's reference SLIP-39
#     implementation (`shamir` from python-shamir-mnemonic), and back
#
# Requires: age, shamir (pip install --require-hashes -r
# scripts/cross-check/requirements.txt), a built `holvard`.

set -eu
cd "$(git rev-parse --show-toplevel)"

command -v age >/dev/null || { echo "age not found" >&2; exit 1; }
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

# age: added with the vault code (secret -> cards -> age passphrase).
echo "Cross-check: age not checked yet (no vault code)"
