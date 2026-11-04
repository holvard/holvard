#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Tests for check-crate-age.sh. Each case builds a two-commit repository in a
# temporary folder and answers the crates.io questions from fixture files
# (CRATES_API=file://...), with the clock fixed (CRATE_AGE_NOW).

set -eu
check=$(cd "$(dirname "$0")" && pwd)/check-crate-age.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Fixed clock: 2026-11-04T00:00:00Z.
CRATE_AGE_NOW=1793750400
CRATES_API="file://$tmp/api"
export CRATE_AGE_NOW CRATES_API

# published NAME VERSION DATE: the API answer for NAME@VERSION.
published() {
    mkdir -p "$tmp/api/$1"
    printf '{"version":{"num":"%s","created_at":"%s"}}\n' "$2" "$3" \
        >"$tmp/api/$1/$2"
}
published old 1.0.0 2026-01-01T00:00:00.000000Z
published old 1.1.0 2026-10-20T12:00:00.123456Z
published fresh 2.0.0 2026-11-01T00:00:00.000000Z
published edge 1.0.0 2026-10-28T00:00:00Z
published justunder 1.0.0 2026-10-28T00:00:01Z
mkdir -p "$tmp/api/garbage"
printf 'not json\n' >"$tmp/api/garbage/1.0.0"

# registry NAME VERSION / git NAME VERSION: Cargo.lock package entries.
registry() {
    printf '[[package]]\nname = "%s"\nversion = "%s"\n' "$1" "$2"
    printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    printf 'checksum = "00"\n\n'
}
git_source() {
    printf '[[package]]\nname = "%s"\nversion = "%s"\n' "$1" "$2"
    printf 'source = "git+https://example.org/%s#abc"\n\n' "$1"
}
local_crate() {
    printf '[[package]]\nname = "%s"\nversion = "%s"\n\n' "$1" "$2"
}

# repo NAME: a fresh repository whose first commit (tag "base") has
# Cargo.lock with `old 1.0.0` and the local crate `holvard 0.0.0`.
repo() {
    dir="$tmp/$1"
    git init -q "$dir"
    git -C "$dir" config user.email t@example.org
    git -C "$dir" config user.name t
    git -C "$dir" config commit.gpgsign false
    { local_crate holvard 0.0.0; registry old 1.0.0; } >"$dir/Cargo.lock"
    git -C "$dir" add Cargo.lock
    git -C "$dir" commit -q -m base
    git -C "$dir" tag base
}

# commit_lock: commits the Cargo.lock read from stdin as the head.
commit_lock() {
    cat >"$dir/Cargo.lock"
    git -C "$dir" add Cargo.lock
    git -C "$dir" commit -q --allow-empty -m head
}

# REUSE-IgnoreStart (the sample header below is test data)
# allow LINES: commits .github/crate-age-allow with LINES.
allow() {
    mkdir -p "$dir/.github"
    printf '# SPDX-License-Identifier: Apache-2.0 OR MIT\n%s\n' "$1" \
        >"$dir/.github/crate-age-allow"
    git -C "$dir" add .github/crate-age-allow
    git -C "$dir" commit -q -m allow
}
# REUSE-IgnoreEnd

failures=0
# expect pass|fail NAME [ARGS...]: runs the check in $dir; for fail, the
# output must also contain $want.
expect() {
    outcome=$1
    name=$2
    shift 2
    if out=$(cd "$dir" && "$check" "$@" 2>&1); then got=pass; else got=fail; fi
    if [ "$got" != "$outcome" ]; then
        echo "FAIL $name: expected $outcome, got $got" >&2
        echo "$out" | sed 's/^/    /' >&2
        failures=$((failures + 1))
    elif [ "$outcome" = fail ] && ! printf '%s' "$out" | grep -qF "$want"; then
        echo "FAIL $name: output lacks \"$want\"" >&2
        echo "$out" | sed 's/^/    /' >&2
        failures=$((failures + 1))
    else
        echo "ok   $name"
    fi
}

repo old-update
{ local_crate holvard 0.0.0; registry old 1.1.0; } | commit_lock
expect pass "a version older than 7 days passes" base HEAD

repo fresh
{ local_crate holvard 0.0.0; registry old 1.0.0; registry fresh 2.0.0; } | commit_lock
want="fresh@2.0.0"
expect fail "a 3-day-old crate fails and is named" base HEAD

repo edge
{ local_crate holvard 0.0.0; registry old 1.0.0; registry edge 1.0.0; } | commit_lock
expect pass "exactly 7 days old passes" base HEAD

repo justunder
{ local_crate holvard 0.0.0; registry old 1.0.0; registry justunder 1.0.0; } | commit_lock
want="justunder@1.0.0"
expect fail "one second under 7 days fails" base HEAD

repo missing
{ local_crate holvard 0.0.0; registry old 1.0.0; registry nowhere 1.0.0; } | commit_lock
want="nowhere@1.0.0"
expect fail "a version the API cannot find fails" base HEAD

repo garbage
{ local_crate holvard 0.0.0; registry old 1.0.0; registry garbage 1.0.0; } | commit_lock
want="garbage@1.0.0"
expect fail "an unreadable API answer fails" base HEAD

repo unchanged
{ local_crate holvard 0.0.0; registry old 1.0.0; } | commit_lock
expect pass "an unchanged lock passes" base HEAD

repo inbase
{ local_crate holvard 0.0.0; registry old 1.0.0; registry fresh 2.0.0; } | commit_lock
git -C "$dir" tag -f base >/dev/null
{ local_crate holvard 0.0.0; registry old 1.1.0; registry fresh 2.0.0; } | commit_lock
expect pass "a crate already in the base is not checked again" base HEAD

repo removed
local_crate holvard 0.0.0 | commit_lock
expect pass "a removed crate passes" base HEAD

repo gitsrc
{ local_crate holvard 0.0.0; registry old 1.0.0; git_source forked 9.9.9; } | commit_lock
expect pass "a crate from git is left to cargo deny" base HEAD

repo badrev
want="no-such-revision"
expect fail "a revision git cannot resolve fails" no-such-revision HEAD

repo whole
{ local_crate holvard 0.0.0; registry old 1.0.0; registry fresh 2.0.0; } | commit_lock
want="fresh@2.0.0"
expect fail "with no base, every crate in the lock is checked" HEAD

repo allowed
{ local_crate holvard 0.0.0; registry old 1.0.0; registry fresh 2.0.0; } | commit_lock
allow "fresh@2.0.0 RUSTSEC-2026-9999: fix needed today"
expect pass "an allowed version passes" base HEAD

repo noreason
{ local_crate holvard 0.0.0; registry old 1.0.0; registry fresh 2.0.0; } | commit_lock
allow "fresh@2.0.0"
want="needs a reason"
expect fail "an allow entry without a reason fails" base HEAD

repo otherversion
{ local_crate holvard 0.0.0; registry old 1.0.0; registry fresh 2.0.0; } | commit_lock
allow "fresh@1.9.0 an older exception"
want="fresh@2.0.0"
expect fail "allowing another version does not allow this one" base HEAD

if [ "$failures" -ne 0 ]; then
    echo "$failures test(s) failed" >&2
    exit 1
fi
echo "all crate-age tests passed"
