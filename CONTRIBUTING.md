# Contributing to Holvard

## Developer Certificate of Origin

Holvard uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a CLA. By adding a `Signed-off-by` line to a commit you certify that
you wrote it, or otherwise have the right to submit it under the project's
licenses:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it for you. The name and email must match the commit
author. CI rejects pull requests and pushes to `main` with unsigned commits
(`scripts/check-dco.sh`). Bot commits, such as Dependabot updates, are exempt.

## AI-assisted contributions

If an AI model helped write a commit, name it in a trailer:

```
Co-Authored-By: <Model name> <address>
```

Your sign-off still means you have reviewed the change, understand it and can
explain it. See "How AI is used" in the [README](README.md).

## License headers

Every source file starts with an SPDX header:

<!-- REUSE-IgnoreStart -->
```rust
// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
```
<!-- REUSE-IgnoreEnd -->

Files under `spec/` and `docs/`, and Markdown files elsewhere, are CC-BY-4.0;
files under `test-vectors/` are CC0-1.0. Files that can't carry a header
(Markdown, lock files) are covered by
`REUSE.toml`. CI runs `reuse lint` (every file has a license) and
`scripts/check-spdx.sh` (each header matches its directory).

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
scripts/check-spdx.sh
pip install --require-hashes -r scripts/reuse/requirements.txt && reuse lint
```

Keep changes small. Changes to `holvard-core` need tests a non-Rust expert can
read: round trips, "any 2 of 3 cards recover, any 1 never does", corrupted and
mixed-up cards rejected. Do not add cryptographic primitives, network access or
`unsafe` code to the core.
