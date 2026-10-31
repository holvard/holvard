// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `holvard` command-line tool.

// "No panics on bad input" (AGENTS.md), as in holvard-core.
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[cfg(not(unix))]
compile_error!("the holvard command supports macOS and Linux for now");

mod args;
mod create;
mod disk;
mod pack;
mod recover;
mod screen;
#[cfg(test)]
mod testutil;

use std::process::ExitCode;

/// A failed operation; the message is shown after "holvard: ".
#[derive(Debug)]
pub struct Failure(pub String);

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Failure {}

/// "1 file", "2 files".
fn files(count: usize) -> String {
    if count == 1 {
        "1 file".to_owned()
    } else {
        format!("{count} files")
    }
}

const USAGE: &str = "\
Usage:
  holvard create <folder> [-o <vault.age>] [--cards-file <file>]
  holvard recover <vault.age> [-o <folder>] [--cards-file <file>]

create   Packs <folder> into a new encrypted vault (default ./vault.age)
         and shows its three cards, one at a time. Any two cards open the
         vault; one card alone reveals nothing. Don't change the folder
         while this runs.
recover  Opens a vault with two of its cards and puts the files in a new
         folder (default ./<vault name>-recovered).

Options:
  -o <path>            Where to write the vault or the recovered folder
  --cards-file <file>  Write the cards to (create) or read them from
                       (recover) this file instead of the screen. The file
                       holds secrets: print it, then delete it.
  -h, --help           Show this help (also: holvard create --help)
  -V, --version        Show the version

Cards are shown on the terminal's second screen, so they don't stay in its
history. Ctrl-C stops at any time and puts the screen back.
Memory: create needs up to three times the folder's size, recover about
twice the vault's size.";

const CREATE_HELP: &str = "\
Usage: holvard create <folder> [-o <vault.age>] [--cards-file <file>]

Packs <folder> into a new encrypted vault (default ./vault.age) and shows
its three cards, one at a time, on the terminal's second screen. Write each
one down. Any two cards open the vault; one card alone reveals nothing.

  -o <path>            Where to write the vault (never overwrites)
  --cards-file <file>  Write the three cards to this new file instead of
                       the screen. Print it, then delete it.

Only plain files and folders are packed; links inside the folder are
refused. Don't change the folder while this runs.
Memory: creating needs up to three times the folder's size.";

const RECOVER_HELP: &str = "\
Usage: holvard recover <vault.age> [-o <folder>] [--cards-file <file>]

Asks for two of the vault's cards, opens it, and puts the files in a new
folder (default ./<vault name>-recovered, in the current folder). You can
type just the first four letters of each word.

  -o <path>            Where to put the files (must not exist yet)
  --cards-file <file>  Read the two cards from this file, one per line

Memory: recovering needs about twice the vault's size.";

fn main() -> ExitCode {
    let command = match args::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(args::UsageError(message)) => {
            eprintln!("holvard: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if matches!(
        command,
        args::Command::Create { .. } | args::Command::Recover { .. }
    ) && let Err(e) = screen::handle_interrupts()
    {
        // Still usable; only Ctrl-C on a card screen would be less tidy.
        eprintln!("holvard: note: cannot watch for Ctrl-C: {e}");
    }
    let result = match command {
        args::Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        args::Command::CreateHelp => {
            println!("{CREATE_HELP}");
            Ok(())
        }
        args::Command::RecoverHelp => {
            println!("{RECOVER_HELP}");
            Ok(())
        }
        args::Command::Version => {
            println!(
                "holvard {} (format v{})",
                env!("CARGO_PKG_VERSION"),
                holvard_core::FORMAT_VERSION
            );
            Ok(())
        }
        args::Command::Create {
            folder,
            out,
            cards_file,
        } => create::run(&folder, out.as_deref(), cards_file.as_deref()),
        args::Command::Recover {
            vault,
            out,
            cards_file,
        } => recover::run(&vault, out.as_deref(), cards_file.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure(message)) => {
            eprintln!("holvard: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_counts_read_naturally() {
        assert_eq!(files(0), "0 files");
        assert_eq!(files(1), "1 file");
        assert_eq!(files(4), "4 files");
    }
}
