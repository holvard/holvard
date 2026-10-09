#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Fails if any commit in RANGE (default origin/main..HEAD) lacks a
# Signed-off-by line matching its author. Commits by bots (Dependabot) are
# exempt; they can't certify the DCO. See CONTRIBUTING.md.

set -eu
range=${1:-origin/main..HEAD}
status=0

for sha in $(git rev-list --no-merges "$range"); do
    author=$(git show -s --format='%an <%ae>' "$sha")
    case "$author" in
        *"[bot] <"*) continue ;;
    esac
    if ! git show -s --format='%B' "$sha" | grep -qF "Signed-off-by: $author"; then
        echo "Commit $(git show -s --format='%h %s' "$sha")" >&2
        echo "  lacks: Signed-off-by: $author" >&2
        status=1
    fi
done

[ "$status" -eq 0 ] && echo "DCO sign-off OK for $range"
exit "$status"
