// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Command-line parsing, by hand: two commands and three options do not
//! need a library, and every message stays under our control.

use std::ffi::OsString;
use std::path::PathBuf;

/// What to do, parsed from the command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Print the help text.
    Help,
    /// Print the help for `create` (`holvard create --help`).
    CreateHelp,
    /// Print the help for `recover`.
    RecoverHelp,
    /// Print the version.
    Version,
    /// Pack a folder into a new vault and hand out its cards.
    Create {
        folder: PathBuf,
        out: Option<PathBuf>,
        cards_file: Option<PathBuf>,
    },
    /// Open a vault with two cards and unpack it.
    Recover {
        vault: PathBuf,
        out: Option<PathBuf>,
        cards_file: Option<PathBuf>,
    },
}

/// A mistake on the command line; the message is shown as is.
#[derive(Debug, PartialEq, Eq)]
pub struct UsageError(pub String);

/// Parses the arguments after the program name.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };
    let rest: Vec<OsString> = args.collect();
    match first.to_str() {
        Some("-h" | "--help") => no_more(&rest).map(|()| Command::Help),
        Some("-V" | "--version") => no_more(&rest).map(|()| Command::Version),
        // `-h` or `--help` before any `--` asks for that command's help.
        Some("create") if wants_help(&rest) => Ok(Command::CreateHelp),
        Some("recover") if wants_help(&rest) => Ok(Command::RecoverHelp),
        Some("create") => {
            let (folder, out, cards_file) = options(rest, "folder")?;
            Ok(Command::Create {
                folder,
                out,
                cards_file,
            })
        }
        Some("recover") => {
            let (vault, out, cards_file) = options(rest, "vault file")?;
            Ok(Command::Recover {
                vault,
                out,
                cards_file,
            })
        }
        Some(command @ ("split" | "cards" | "seal")) => {
            Err(UsageError(format!("`{command}` is not available yet")))
        }
        _ => Err(UsageError(format!(
            "unknown command `{}`",
            first.to_string_lossy()
        ))),
    }
}

fn wants_help(rest: &[OsString]) -> bool {
    rest.iter()
        .map(|arg| arg.to_str())
        .take_while(|arg| *arg != Some("--"))
        .any(|arg| matches!(arg, Some("-h" | "--help")))
}

fn no_more(rest: &[OsString]) -> Result<(), UsageError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(UsageError("unexpected extra arguments".into()))
    }
}

/// One path plus `-o` and `--cards-file`, in any order. `--` ends the
/// options, so a path may start with `-`.
fn options(
    rest: Vec<OsString>,
    what: &str,
) -> Result<(PathBuf, Option<PathBuf>, Option<PathBuf>), UsageError> {
    let mut path = None;
    let mut out = None;
    let mut cards_file = None;
    let mut only_paths = false;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        let (name, slot) = match arg.to_str() {
            Some("--") if !only_paths => {
                only_paths = true;
                continue;
            }
            Some("-o") if !only_paths => ("-o", &mut out),
            Some("--cards-file") if !only_paths => ("--cards-file", &mut cards_file),
            Some(option) if !only_paths && option.starts_with('-') => {
                return Err(UsageError(format!("unknown option `{option}`")));
            }
            _ => {
                if path.replace(PathBuf::from(arg)).is_some() {
                    return Err(UsageError(format!("give only one {what}")));
                }
                continue;
            }
        };
        let value = args
            .next()
            .ok_or_else(|| UsageError(format!("`{name}` needs a value")))?;
        if slot.replace(PathBuf::from(value)).is_some() {
            return Err(UsageError(format!("`{name}` was given twice")));
        }
    }
    let path = path.ok_or_else(|| UsageError(format!("missing the {what}")))?;
    Ok((path, out, cards_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn valid_forms() -> Result<(), UsageError> {
        assert_eq!(p(&[])?, Command::Help);
        assert_eq!(p(&["-h"])?, Command::Help);
        assert_eq!(p(&["--help"])?, Command::Help);
        assert_eq!(p(&["-V"])?, Command::Version);
        assert_eq!(p(&["--version"])?, Command::Version);
        assert_eq!(p(&["create", "--help"])?, Command::CreateHelp);
        assert_eq!(p(&["create", "docs", "-h"])?, Command::CreateHelp);
        assert_eq!(p(&["recover", "--help"])?, Command::RecoverHelp);
        assert_eq!(
            p(&["create", "docs"])?,
            Command::Create {
                folder: "docs".into(),
                out: None,
                cards_file: None
            }
        );
        assert_eq!(
            p(&["create", "-o", "v.age", "docs", "--cards-file", "c.txt"])?,
            Command::Create {
                folder: "docs".into(),
                out: Some("v.age".into()),
                cards_file: Some("c.txt".into()),
            }
        );
        assert_eq!(
            p(&["recover", "v.age", "-o", "out"])?,
            Command::Recover {
                vault: "v.age".into(),
                out: Some("out".into()),
                cards_file: None
            }
        );
        // `--` ends the options, so a folder may start with `-`; a `-h`
        // after it is a name, not a request for help.
        assert_eq!(
            p(&["create", "--", "-odd-name"])?,
            Command::Create {
                folder: "-odd-name".into(),
                out: None,
                cards_file: None
            }
        );
        assert_eq!(
            p(&["create", "--", "-h"])?,
            Command::Create {
                folder: "-h".into(),
                out: None,
                cards_file: None
            }
        );
        Ok(())
    }

    #[test]
    fn usage_errors() {
        for bad in [
            &["frobnicate"][..],
            &["init", "docs"], // renamed to create
            &["split"],
            &["cards"],
            &["seal"], // not available yet
            &["create"],
            &["create", "a", "b"],
            &["create", "docs", "-o"],
            &["create", "docs", "-o", "a", "-o", "b"],
            &["create", "docs", "--bogus"],
            &["recover"],
            &["--help", "extra"], // deliberate: extras after a top-level --help are a mistake
            &["-V", "extra"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }
}
