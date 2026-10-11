#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Checks the vendored SLIP-39 files in test-vectors/slip39/ against the
# hashes recorded in test-vectors/slip39/SOURCE.
#
#   scripts/check-upstream.sh           local files match SOURCE (offline)
#   scripts/check-upstream.sh --remote  upstream's current master still
#                                       matches SOURCE (needs network)
#
# A --remote failure means upstream changed a file: review the change, copy
# the new file, and update SOURCE in the same pull request.

set -eu
cd "$(git rev-parse --show-toplevel)/test-vectors/slip39"

repo=$(sed -n 's/^# repository: *https:\/\/github.com\///p' SOURCE)
status=0

sha256() { shasum -a 256 | cut -d' ' -f1; }

while read -r local upstream expected; do
    case "$local" in '' | '#'*) continue ;; esac
    if [ "${1:-}" = "--remote" ]; then
        url="https://raw.githubusercontent.com/$repo/master/$upstream"
        actual=$(curl -fsSL "$url" | sha256)
        where="upstream $upstream"
    else
        actual=$(sha256 <"$local")
        where="test-vectors/slip39/$local"
    fi
    if [ "$actual" = "$expected" ]; then
        echo "ok      $where"
    else
        echo "CHANGED $where: sha256 $actual, SOURCE records $expected" >&2
        status=1
    fi
done <SOURCE

exit "$status"
