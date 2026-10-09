#!/bin/sh
# SPDX-FileCopyrightText: 2026 Holvard contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Checks that every SPDX-License-Identifier header line in a tracked file
# (after a comment marker, or alone inside a block comment) matches the
# license of its directory:
#   test-vectors/    CC0-1.0
#   spec/, docs/     CC-BY-4.0
#   other *.md       CC-BY-4.0 (prose)
#   everything else  Apache-2.0 OR MIT
# Whether every file has license information at all is `reuse lint`'s job.

set -eu
cd "$(git rev-parse --show-toplevel)"

expected_for() {
    case "$1" in
        test-vectors/*) echo "CC0-1.0" ;;
        spec/* | docs/* | *.md) echo "CC-BY-4.0" ;;
        *) echo "Apache-2.0 OR MIT" ;;
    esac
}

# REUSE-IgnoreStart (the patterns below are not license declarations)
status=0
# NUL-separated so file names with spaces or newlines are handled safely.
# REUSE.toml and the license texts are skipped: they name licenses as data.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
# Lines inside REUSE ignore blocks are skipped, as reuse lint skips them
# (for example, a sample header in documentation). The markers are written
# as REUSE-Ignore(Start) and REUSE-Ignore(End) so this script stays readable
# to reuse itself.
# shellcheck disable=SC2016 # $0 and friends are awk's, not the shell's.
git ls-files -z -- ':!:REUSE.toml' ':!:LICENSES/' ':!:LICENSE-*' \
    | xargs -0 awk '
        FNR == 1 { skip = 0 }
        /REUSE-Ignore(Start)/ { skip = 1 }
        /REUSE-Ignore(End)/ { skip = 0; next }
        !skip && /^[[:space:]]*((#|\/\/|\/\*|\*|<!--)[[:space:]]*)?SPDX-License-Identifier:/ {
            print FILENAME ":" $0
        }' >"$tmp"

while IFS= read -r line; do
    file=${line%%:*}
    # Keep only the expression: drop the comment prefix and any closing
    # `*/` or `-->` and trailing whitespace.
    found=$(printf '%s\n' "${line#*SPDX-License-Identifier:}" \
        | sed -E 's/[[:space:]]*(\*\/|-->)?[[:space:]]*$//; s/^[[:space:]]+//')
    expected=$(expected_for "$file")
    # SPDX `OR` is commutative: accept "MIT OR Apache-2.0" as well.
    [ "$found" = "MIT OR Apache-2.0" ] && found="Apache-2.0 OR MIT"
    if [ "$found" != "$expected" ]; then
        echo "$file: SPDX-License-Identifier is '$found', expected '$expected'" >&2
        status=1
    fi
done <"$tmp"
# REUSE-IgnoreEnd

[ "$status" -eq 0 ] && echo "SPDX headers match their directories"
exit "$status"
