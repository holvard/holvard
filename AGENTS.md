<!--
SPDX-FileCopyrightText: 2026 Holvard contributors
SPDX-License-Identifier: CC-BY-4.0
-->

# Holvard: instructions for AI assistants

This file is the single source of instructions for any AI assistant working
in this repository. CLAUDE.md only imports it.

## Project

Holvard makes sure the right people can reach your important information
when you no longer can. A vault is encrypted locally with age; the key is
split 2-of-3 with SLIP-39 (Holvard Cloud, beneficiary, backup holder).
Holvard alone can never open a vault; any two holders together can, so
Holvard takes part only through the owner's release policy: missed
check-ins, a waiting period with veto, and verification.
Design: docs/design.md.

## Hard rules (security)

- No home-made cryptography. Use only age (the `age` crate), RustCrypto
  crates and OS randomness (`getrandom`). Never write primitives yourself.
- SLIP-39 lives in crates/holvard-core/src/slip39/, is our own port, supports the
  2024 "extendable backup" flag, and must pass Trezor's vectors.json.
- Every format change is cross-checked both ways: vaults open with the
  official `age` CLI; shares recover with Trezor's `shamir-mnemonic` CLI.
- No `unsafe`, no network access in holvard-core, no panics on bad input.
- Never log, print or persist secrets; wipe them from memory (`zeroize`).
- Never describe the design as "nobody can open it early": any two holders
  can. The guarantee is that Holvard alone cannot.
- Owner-side encryption runs in the CLI. Any browser app is served only as
  signed static releases, never by holvard-server.
- No hosted recovery page at launch. The recovery page combines share 1
  with an heir's card, so code Holvard serves could capture the card and
  give Holvard two shares. It ships only in the kit and as signed downloads
  (GitHub and Codeberg releases, holvard.dev), never served by
  holvard-server or any Holvard Cloud origin. Practice drills use only the
  kit copy. Recovery must also work with standard tools alone: Trezor's
  `shamir` CLI and the official `age` tool.
- New shares of the same secret do not revoke old ones. Revocation means a
  new secret and re-encryption; never claim otherwise in code or docs.
- Don't add dependencies without asking me first.
- Never weaken lints or CI checks to make something pass. An `#[allow]`
  needs a comment explaining why, and my approval.

## Spec first

- Changes to card, share or vault formats update spec/ and test-vectors/
  in the same change.
- Format version 1 is frozen once published; later versions only add.

## How we work

- Small changes. Explain any crypto-related code in plain language in the
  commit body; I review every change.
- Every bug fix comes with a test. Prefer tests I can read: round trips,
  "any 2 of 3 recover, any 1 never does", corrupted cards rejected.
- Ask before architectural decisions or anything touching formats.
- The Rust toolchain is pinned in rust-toolchain.toml. Bump it only in its
  own commit, and only when I ask.
- Diagrams in Markdown use Mermaid code blocks, so they survive exports and
  render on GitHub.

## Voice in user-facing text

Applies to the CLI's messages, README, website, cards and kits:

- Calm and practical, never morbid. Avoid "death", "die", "dead" and
  "after you're gone". Say "when you can't", "pass on", "your people",
  "if something happens to you".
- Exception: legal and precise contexts (terms, the release policy, the
  spec), where exact words matter more than comfort.
- Plain words, short sentences. Heirs may be non-technical and grieving.

## Licensing

- Code: Apache-2.0 OR MIT. spec/, docs/ and Markdown files elsewhere:
  CC-BY-4.0. test-vectors/: CC0-1.0 (Markdown there too).
- Every new file starts with its SPDX header. Never edit the license texts.

## Naming

- The product is "Holvard"; the hosted service is "Holvard Cloud".
- "keeper" is a lowercase role word only. Never "Holvard Keeper" (trademark).

## Commits

- Every commit is signed off with `git commit -s` (DCO). Commits are also
  signed with my SSH key through git config; don't bypass it.
- Every commit you help write ends with this trailer, exactly:
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  If the model changes, use the current model name and version.
- The commit body includes one line on how AI was used, e.g.
  "AI use: CI workflow drafted by Claude from my instructions; reviewed by me."
- Keep AI-generated changes in their own commits, separate from my manual edits.
- Never commit secrets or private keys (for example the minisign secret key).
- Never commit CLAUDE.local.md or private planning documents.
- Don't commit or push unless I ask; show me the diff first.

