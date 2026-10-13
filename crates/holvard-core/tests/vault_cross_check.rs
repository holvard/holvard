// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cross-check of whole vaults with the standard tools, in both directions:
//! a vault Holvard creates opens with Trezor's `shamir` CLI and the official
//! `age` CLI alone, and a vault made with those tools opens with Holvard.
//!
//! Ignored by default, because it needs `shamir`, `age` and
//! `age-plugin-batchpass` (part of age since 1.3):
//!
//! ```sh
//! cargo test -p holvard-core --test vault_cross_check -- --ignored
//! ```
//!
//! `scripts/cross-check.sh` runs it in CI. Set `SHAMIR` or `AGE` to use
//! binaries that are not on `PATH`.

use std::io::Write as _;
use std::process::{Command, Stdio};

mod common;

use common::{Result, hex, random_bytes, trezor_create, trezor_recover};
use holvard_core::vault::{create_vault, open_vault};

/// Runs `command` with `input` on stdin and returns its stdout, failing if
/// it exits with an error.
fn run(mut command: Command, input: &[u8]) -> Result<Vec<u8>> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "{command:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

/// The `age` CLI with a passphrase given through `age-plugin-batchpass`.
///
/// The passphrase goes in `AGE_PASSPHRASE`, not `AGE_PASSPHRASE_FD` as in
/// spec/vault.md: the secrets here are throwaway, no shell history sees the
/// variable, and passing an extra file descriptor would need `unsafe`.
fn age(passphrase: &str, args: &[&str]) -> Command {
    let mut command = Command::new(std::env::var("AGE").unwrap_or_else(|_| "age".to_owned()));
    command
        .env("AGE_PASSPHRASE", passphrase)
        .args(["-j", "batchpass"])
        .args(args);
    command
}

#[test]
#[ignore = "needs the shamir and age CLIs; run by scripts/cross-check.sh"]
fn holvard_vaults_open_with_shamir_and_age() -> Result<()> {
    for length in [0, 1, 1000, 70_000] {
        let contents = random_bytes(length)?;
        let vault = create_vault(&contents)?;
        let [a, b, c] = &vault.cards;
        for pair in [[a, b], [a, c], [b, c]] {
            let secret = trezor_recover(&[pair[0].as_str(), pair[1].as_str()])?;
            let opened = run(age(&secret, &["-d"]), &vault.encrypted)?;
            assert_eq!(opened, contents, "{length} bytes");
        }
    }
    Ok(())
}

#[test]
#[ignore = "needs the shamir and age CLIs; run by scripts/cross-check.sh"]
fn shamir_and_age_vaults_open_with_holvard() -> Result<()> {
    for length in [0, 1, 1000, 70_000] {
        let secret = hex(&random_bytes(32)?);
        let groups = trezor_create(&["2of3", "-S", &secret])?;
        let [cards] = groups.as_slice() else {
            return Err("expected one group".into());
        };
        let [a, b, c] = cards.as_slice() else {
            return Err("expected three cards".into());
        };
        let contents = random_bytes(length)?;
        let encrypted = run(age(&secret, &["-e"]), &contents)?;
        for pair in [[a, b], [a, c], [b, c]] {
            let opened = open_vault(&[pair[0].as_str(), pair[1].as_str()], &encrypted)?;
            assert_eq!(opened.as_slice(), contents, "{length} bytes");
        }
    }
    Ok(())
}
