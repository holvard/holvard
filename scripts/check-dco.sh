#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Fails if any commit in RANGE (default origin/main..HEAD) lacks a
# Signed-off-by line matching its author. Commits by Dependabot are exempt;
# it can't certify the DCO. See CONTRIBUTING.md.

set -eu
range=${1:-origin/main..HEAD}
status=0

# Listed first, so a range git cannot resolve stops the script here
# (set -e does not apply inside a for loop's word list). Needs the full
# history: in a shallow clone a merge commit's parents are missing, so it
# is checked as an ordinary commit.
shas=$(git rev-list --no-merges "$range")

for sha in $shas; do
    author=$(git show -s --format='%an <%ae>' "$sha")
    # Only Dependabot, by its exact author line.
    if [ "$author" = "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>" ]; then
        continue
    fi
    if ! git show -s --format='%B' "$sha" | grep -qF "Signed-off-by: $author"; then
        echo "Commit $(git show -s --format='%h %s' "$sha")" >&2
        echo "  lacks: Signed-off-by: $author" >&2
        status=1
    fi
done

[ "$status" -eq 0 ] && echo "DCO sign-off OK for $range"
exit "$status"
