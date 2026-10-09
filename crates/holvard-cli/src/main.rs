// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `holvard` command-line tool.

use std::process::ExitCode;

const USAGE: &str = "\
Usage: holvard <command>

Commands (not implemented yet):
  init     Create a new vault and its key
  split    Split the vault key into holder cards
  cards    Print holder cards as PDF
  recover  Recover the vault key from cards
  seal     Package the vault for a backup holder

Options:
  -h, --help     Print this help
  -V, --version  Print version";

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        None | Some("-h" | "--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!(
                "holvard {} (format v{})",
                env!("CARGO_PKG_VERSION"),
                holvard_core::FORMAT_VERSION
            );
            ExitCode::SUCCESS
        }
        Some(cmd @ ("init" | "split" | "cards" | "recover" | "seal")) => {
            eprintln!("holvard: `{cmd}` is not implemented yet");
            ExitCode::FAILURE
        }
        Some(other) => {
            eprintln!("holvard: unknown command `{other}`\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
