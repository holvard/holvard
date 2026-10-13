// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Helpers shared by the cross-check tests: random input, hex, and Trezor's
//! `shamir` CLI (set `SHAMIR` to use a binary that is not on `PATH`).

use std::error::Error;
use std::io::Write as _;
use std::process::{Command, Stdio};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn shamir() -> Command {
    Command::new(std::env::var("SHAMIR").unwrap_or_else(|_| "shamir".to_owned()))
}

pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut secret = vec![0u8; length];
    getrandom::fill(&mut secret).map_err(|e| format!("random generator: {e}"))?;
    Ok(secret)
}

/// Runs `shamir recover` with `cards` typed in, and returns the master
/// secret it prints, as hex.
pub fn trezor_recover(cards: &[&str]) -> Result<String> {
    let mut child = shamir()
        .arg("recover")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child.stdin.as_mut().ok_or("no stdin")?;
        for card in cards {
            writeln!(stdin, "{card}")?;
        }
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    stdout
        .lines()
        .find_map(|line| line.split_once("Your master secret is: "))
        .map(|(_, secret)| secret.trim().to_owned())
        .ok_or_else(|| format!("shamir recover printed no secret:\n{stdout}").into())
}

/// Runs `shamir create` and returns its cards, group by group.
///
/// Cards are recognised as lines of 20 or more lowercase words after a
/// "Group" header. That depends on `shamir`'s output format, which cannot
/// change under us: `shamir-mnemonic` is pinned by hash in
/// `scripts/cross-check/requirements.txt`.
pub fn trezor_create(args: &[&str]) -> Result<Vec<Vec<String>>> {
    let output = shamir().arg("create").args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "shamir create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let mut groups: Vec<Vec<String>> = Vec::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        if line.starts_with("Group ") {
            groups.push(Vec::new());
        } else if line.split(' ').count() >= 20
            && line.chars().all(|c| c.is_ascii_lowercase() || c == ' ')
        {
            groups
                .last_mut()
                .ok_or("card before any group header")?
                .push(line.to_owned());
        }
    }
    Ok(groups)
}
