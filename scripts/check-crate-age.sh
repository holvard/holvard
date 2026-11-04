#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Usage: check-crate-age.sh [BASE] HEAD
#
# Fails if a crates.io package that Cargo.lock at HEAD adds or changes
# (compared with BASE; without BASE, every package) was published less than
# 7 days ago. This enforces the cooldown in .github/dependabot.yml, which
# Dependabot skips for Cargo.lock-only updates: it names the right version in
# the title but runs `cargo update` without `--precise`, so the lock gets the
# newest release (dependabot-core#16428). The week gives others time to
# notice a compromised release before we take it.
#
# An exception (an urgent security fix, say) goes in .github/crate-age-allow
# at HEAD, one `name@version reason` per line. Crates from git or a path are
# left to cargo deny, which decides which sources are allowed.
#
# Asks crates.io, so it needs network access, and fails if it can't get an
# answer. CRATES_API and CRATE_AGE_NOW (seconds since 1970) are for the
# tests in test-crate-age.sh.

set -eu
min_days=7
api=${CRATES_API:-https://crates.io/api/v1/crates}
now=${CRATE_AGE_NOW:-$(date +%s)}
agent="holvard-ci (https://codeberg.org/holvard/holvard)"

case $# in
    1) base='' head=$1 ;;
    2) base=$1 head=$2 ;;
    *) echo "usage: $0 [BASE] HEAD" >&2; exit 2 ;;
esac
for rev in $base $head; do
    if ! git rev-parse --verify --quiet "$rev^{commit}" >/dev/null; then
        echo "cannot resolve revision: $rev" >&2
        exit 1
    fi
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# packages REV: the crates.io packages in Cargo.lock at REV, one
# name@version per line, sorted.
packages() {
    git show "$1:Cargo.lock" | awk '
        function emit() {
            if (name != "" && (source ~ /^"registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index"$/ \
                || source ~ /^"sparse\+https:\/\/index\.crates\.io\/"$/))
                print name "@" version
            name = version = source = ""
        }
        /^\[\[package\]\]/ { emit() }
        $1 == "name" { name = $3; gsub(/"/, "", name) }
        $1 == "version" { version = $3; gsub(/"/, "", version) }
        $1 == "source" { source = $3 }
        END { emit() }' | LC_ALL=C sort -u
}

packages "$head" >"$tmp/head"
if [ -n "$base" ]; then
    # A base without Cargo.lock has no packages; every one at HEAD is new.
    if git cat-file -e "$base:Cargo.lock" 2>/dev/null; then
        packages "$base" >"$tmp/base"
    else
        : >"$tmp/base"
    fi
else
    : >"$tmp/base"
fi
LC_ALL=C comm -13 "$tmp/base" "$tmp/head" >"$tmp/new"

# The exceptions, from HEAD so they are reviewed with the change.
status=0
: >"$tmp/allowed"
if git cat-file -e "$head:.github/crate-age-allow" 2>/dev/null; then
    git show "$head:.github/crate-age-allow" >"$tmp/allow-file"
    while read -r entry reason; do
        case $entry in '' | '#'*) continue ;; esac
        if [ -z "$reason" ]; then
            echo ".github/crate-age-allow: $entry needs a reason" >&2
            status=1
        fi
        echo "$entry" >>"$tmp/allowed"
    done <"$tmp/allow-file"
fi

checked=0
first=1
while read -r package; do
    name=${package%@*}
    version=${package##*@}
    if grep -qxF "$package" "$tmp/allowed"; then
        echo "allowed by .github/crate-age-allow: $package"
        continue
    fi
    # crates.io asks crawlers for at most one request per second.
    case $api in
        file://*) ;;
        *) [ "$first" -eq 1 ] || sleep 1 ;;
    esac
    first=0
    if ! curl -fsS -A "$agent" "$api/$name/$version" >"$tmp/answer" 2>"$tmp/error"; then
        echo "$package: crates.io gave no answer: $(cat "$tmp/error")" >&2
        status=1
        continue
    fi
    if ! published=$(jq -er '.version.created_at' "$tmp/answer" 2>/dev/null) ||
        ! age=$(jq -nr --arg t "$published" --argjson now "$now" \
            '$now - ($t | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601)' 2>/dev/null); then
        echo "$package: cannot read its publish date from crates.io" >&2
        status=1
        continue
    fi
    if [ "$age" -lt $((min_days * 86400)) ]; then
        echo "$package was published $published, less than $min_days days ago." >&2
        echo "  Wait until it is $min_days days old, or list it in" >&2
        echo "  .github/crate-age-allow with a reason." >&2
        status=1
    fi
    checked=$((checked + 1))
done <"$tmp/new"

[ "$status" -eq 0 ] && echo "crate age OK: $checked new or changed crates are at least $min_days days old"
exit "$status"
