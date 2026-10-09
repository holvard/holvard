# Releases: signing and reproducible builds

## Release signing key

Releases are signed with [minisign](https://jedisct1.github.io/minisign/).

One-time setup, by a maintainer, on an offline or otherwise trusted machine:

```sh
minisign -G -p holvard.pub -s holvard.key -c "Holvard release signing key"
```

- Keep `holvard.key` offline, encrypted with a strong password, with a backup
  in a second location. It never goes into CI or this repository.
- Publish `holvard.pub` in this file, in the README and on holvard.dev, so
  users can check it from more than one place.
- If the key is lost or compromised, publish a signed (if possible) notice and
  a new key in all of those places.

Public key: _not generated yet_.

Signing a release:

```sh
sha256sum holvard-* > SHA256SUMS
minisign -S -s holvard.key -m SHA256SUMS
```

Verifying:

```sh
minisign -V -p holvard.pub -m SHA256SUMS
sha256sum -c SHA256SUMS
```

## Reproducing a build

A release binary must be byte-for-byte reproducible from its tag.

What makes that possible:

- the Rust toolchain is pinned in `rust-toolchain.toml`
- `Cargo.lock` is committed and builds use `--locked`
- the release profile uses `codegen-units = 1`, `lto = true` and strips symbols

To reproduce a Linux release:

```sh
git checkout vX.Y.Z
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo"
cargo build --release --locked --target x86_64-unknown-linux-gnu
sha256sum target/x86_64-unknown-linux-gnu/release/holvard
```

Compare the hash with the one in the signed `SHA256SUMS`. Release builds are
made with the same commands, so differences point to the build environment or
a tampered binary; please report them as described in `SECURITY.md`.
