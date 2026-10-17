// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Cross-check of the `holvard` command with standard tools, in both
//! directions: a folder packed by `holvard create` comes back with Trezor's
//! `shamir recover`, the `age` CLI and `unzip`; a folder zipped with `zip`
//! and encrypted with `age` comes back with `holvard recover`.
//!
//! Ignored by default, because it needs `shamir`, `age`,
//! `age-plugin-batchpass`, `zip` and `unzip`:
//!
//! ```sh
//! cargo test -p holvard --test cli_cross_check -- --ignored
//! ```
//!
//! `scripts/cross-check.sh` runs it in CI. Set `SHAMIR` or `AGE` to use
//! binaries that are not on `PATH`.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

mod common;

use common::{Result, TempDir, TestResult, holvard, pair_file, s, sample, tree};

fn tool(variable: &str, default: &str) -> Command {
    Command::new(std::env::var(variable).unwrap_or_else(|_| default.to_owned()))
}

/// Runs `command` in `cwd` with `input` on stdin; fails unless it succeeds.
fn run(mut command: Command, cwd: &Path, input: &[u8]) -> Result<Vec<u8>> {
    let mut child = command
        .current_dir(cwd)
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
    let mut command = tool("AGE", "age");
    command
        .env("AGE_PASSPHRASE", passphrase)
        .args(["-j", "batchpass"])
        .args(args);
    command
}

/// `shamir recover` with two cards typed in; returns the secret as hex.
fn shamir_recover(cards: &[&str], cwd: &Path) -> Result<String> {
    let input = format!("{}\n", cards.join("\n"));
    let mut command = tool("SHAMIR", "shamir");
    command.arg("recover");
    let stdout = String::from_utf8(run(command, cwd, input.as_bytes())?)?;
    stdout
        .lines()
        .find_map(|line| line.split_once("Your master secret is: "))
        .map(|(_, secret)| secret.trim().to_owned())
        .ok_or_else(|| format!("shamir recover printed no secret:\n{stdout}").into())
}

/// `shamir create 2of3 -S <hex>`; returns the three cards. Cards are lines
/// of 20 or more lowercase words (shamir-mnemonic is pinned by hash in
/// scripts/cross-check/requirements.txt, so its output format is fixed).
fn shamir_create(secret: &str, cwd: &Path) -> Result<Vec<String>> {
    let mut command = tool("SHAMIR", "shamir");
    command.args(["create", "2of3", "-S", secret]);
    let stdout = String::from_utf8(run(command, cwd, b"")?)?;
    Ok(stdout
        .lines()
        .filter(|line| {
            line.split(' ').count() >= 20
                && line.chars().all(|c| c.is_ascii_lowercase() || c == ' ')
        })
        .map(str::to_owned)
        .collect())
}

fn random_hex() -> Result<String> {
    use core::fmt::Write as _;
    let mut secret = [0u8; 32];
    os_random(&mut secret)?;
    let mut hex = String::new();
    for byte in secret {
        write!(hex, "{byte:02x}")?;
    }
    Ok(hex)
}

/// 32 random bytes from the OS, read from /dev/urandom so the test needs
/// no extra dependency.
fn os_random(buffer: &mut [u8]) -> Result<()> {
    use std::io::Read as _;
    fs::File::open("/dev/urandom")?.read_exact(buffer)?;
    Ok(())
}

#[test]
#[ignore = "needs shamir, age, zip and unzip; run by scripts/cross-check.sh"]
fn holvard_vault_opens_with_standard_tools() -> TestResult {
    let t = TempDir::new()?;
    let docs = sample(&t.0)?;
    let created = holvard(&["create", "docs", "--cards-file", "cards.txt"], &t.0)?;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let pair = pair_file(&t.0.join("cards.txt"), 1, 3, &t.0.join("pair.txt"))?;
    let text = fs::read_to_string(&pair)?;
    let cards: Vec<&str> = text
        .lines()
        .map(|line| line.split_once(": ").map_or(line, |(_, card)| card))
        .collect();
    let secret = shamir_recover(&cards, &t.0)?;
    let zip = run(age(&secret, &["-d", "vault.age"]), &t.0, b"")?;
    fs::write(t.0.join("x.zip"), zip)?;
    let mut unzip = Command::new("unzip");
    unzip.args(["-q", "x.zip", "-d", "unzipped"]);
    run(unzip, &t.0, b"")?;
    assert_eq!(tree(&t.0.join("unzipped/docs"))?, tree(&docs)?);
    Ok(())
}

#[test]
#[ignore = "needs shamir, age, zip and unzip; run by scripts/cross-check.sh"]
fn standard_tools_vault_recovers_with_holvard() -> TestResult {
    let t = TempDir::new()?;
    let docs = sample(&t.0)?;
    let mut zip = Command::new("zip");
    zip.args(["-q", "-X", "-r", "folder.zip", "docs"]);
    run(zip, &t.0, b"")?;
    let secret = random_hex()?;
    let cards = shamir_create(&secret, &t.0)?;
    let [a, _, c] = cards.as_slice() else {
        return Err("expected three cards".into());
    };
    run(
        age(&secret, &["-e", "-o", "vault.age", "folder.zip"]),
        &t.0,
        b"",
    )?;
    fs::write(t.0.join("pair.txt"), format!("{a}\n{c}\n"))?;
    let out = t.0.join("out");
    let recovered = holvard(
        &[
            "recover",
            "vault.age",
            "-o",
            s(&out)?,
            "--cards-file",
            "pair.txt",
        ],
        &t.0,
    )?;
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(tree(&out.join("docs"))?, tree(&docs)?);
    Ok(())
}
