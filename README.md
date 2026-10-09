# Holvard

Holvard makes sure the right people can reach your important information when
you no longer can. Holvard alone can never open a vault. The owner encrypts
a vault on their own device with [age](https://age-encryption.org), and its key
is split with [SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
so that any two of three holders can open it: Holvard Cloud, a
beneficiary and an independent backup holder such as a notary.

**Status:** early development. Nothing here is ready to protect real data.

## Repository layout

| Path | What | License |
| --- | --- | --- |
| `spec/` | Card format, vault file format, step-by-step recovery | CC BY 4.0 |
| `test-vectors/` | Sample cards and vaults with expected results | CC0 1.0 |
| `crates/holvard-core` | Key generation, age encryption, SLIP-39 split and combine, card encoding | Apache-2.0 OR MIT |
| `crates/holvard-cli` | The `holvard` command: `init`, `split`, `cards`, `recover`, `seal` | Apache-2.0 OR MIT |
| `scripts/` | SPDX, DCO and cross-check scripts used by CI | Apache-2.0 OR MIT |
| `docs/` | Design, release signing and reproducible builds | CC BY 4.0 |

## Building

```sh
cargo build --release --locked
cargo test --locked
```

The toolchain is pinned in `rust-toolchain.toml`.

## How we check the code

- No home-made cryptography: established libraries only (the Rust age
  implementation, RustCrypto crates, the OS random generator). SLIP-39 is a
  small port checked against Trezor's reference implementation and vectors.
- Other implementations are the acceptance test: every vault Holvard encrypts
  must open with the official `age` tool, and every card set must recover with
  Trezor's reference SLIP-39 implementation. CI runs both directions
  (`scripts/cross-check.sh`).
- The core has no network access and no `unsafe`. Warnings are denied;
  `clippy`, `cargo deny` and `cargo audit` run on every change.
- Outside security reviews: of the threat model and spec before format
  version 1 is frozen, and of `holvard-core` and the release process before
  the hosted service accepts its first paying user.

## How AI is used

Much of Holvard's code is written with the help of AI models. We treat that
code as untrusted until independent checks pass:

- Every AI-assisted commit names the model in its message, with a
  `Co-Authored-By:` trailer (for example `Co-Authored-By: Claude Opus 5.5
  <noreply@anthropic.com>`).
- AI writes glue code, tests and tooling, never cryptographic primitives.
- A human maintainer reviews and understands every change before it merges,
  and signs it off under the DCO.
- Correctness is established by cross-checks against age and the SLIP-39
  reference, published test vectors and an outside security review, not by
  trusting the author, human or AI.

## Contributing

AI assistants working here follow [AGENTS.md](AGENTS.md).

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/): sign off
every commit with `git commit -s`. There is no CLA.

Report security issues privately, as described in [SECURITY.md](SECURITY.md).

## License

Code is licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option. The format spec, docs and other prose
(Markdown files) are [CC BY 4.0](LICENSES/CC-BY-4.0.txt); test vectors are
[CC0 1.0](LICENSES/CC0-1.0.txt). The project follows the
[REUSE](https://reuse.software) specification: every file's license is
declared in its SPDX header or in `REUSE.toml`, with full texts in `LICENSES/`.
The future `holvard-server` will be AGPL-3.0-only.

The design is described in [docs/design.md](docs/design.md).

"Holvard" is a trademark; see [TRADEMARKS.md](TRADEMARKS.md).
