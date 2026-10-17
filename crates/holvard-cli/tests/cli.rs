// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! End-to-end tests of the `holvard` binary. Cards go through
//! `--cards-file`, since the tests have no terminal.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

mod common;

use common::{TempDir, TestResult, holvard, pair_file, s, sample, tree};

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn create_then_recover_with_every_pair() -> TestResult {
    let t = TempDir::new()?;
    let docs = sample(&t.0)?;
    let created = holvard(
        &["create", "docs", "-o", "v.age", "--cards-file", "cards.txt"],
        &t.0,
    )?;
    assert!(created.status.success(), "{}", stderr(&created));
    // The cards file holds secrets: owner only.
    let mode = fs::metadata(t.0.join("cards.txt"))?.permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    for (i, j) in [(1, 2), (1, 3), (2, 3)] {
        let pair = pair_file(
            &t.0.join("cards.txt"),
            i,
            j,
            &t.0.join(format!("p{i}{j}.txt")),
        )?;
        let out = format!("out{i}{j}");
        let recovered = holvard(
            &["recover", "v.age", "-o", &out, "--cards-file", s(&pair)?],
            &t.0,
        )?;
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert_eq!(tree(&t.0.join(&out).join("docs"))?, tree(&docs)?);
    }
    Ok(())
}

#[test]
fn recover_defaults_to_the_current_folder() -> TestResult {
    let t = TempDir::new()?;
    let docs = sample(&t.0)?;
    let usb = t.0.join("usb");
    fs::create_dir(&usb)?;
    let created = holvard(
        &[
            "create",
            "docs",
            "-o",
            "usb/v.age",
            "--cards-file",
            "cards.txt",
        ],
        &t.0,
    )?;
    assert!(created.status.success(), "{}", stderr(&created));
    let pair = pair_file(&t.0.join("cards.txt"), 1, 2, &t.0.join("pair.txt"))?;
    let here = t.0.join("here");
    fs::create_dir(&here)?;
    let recovered = holvard(
        &["recover", "../usb/v.age", "--cards-file", s(&pair)?],
        &here,
    )?;
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert_eq!(tree(&here.join("v-recovered").join("docs"))?, tree(&docs)?);
    assert!(!usb.join("v-recovered").exists());
    Ok(())
}

#[test]
fn empty_folder_round_trip() -> TestResult {
    let t = TempDir::new()?;
    fs::create_dir(t.0.join("empty"))?;
    let created = holvard(&["create", "empty", "--cards-file", "cards.txt"], &t.0)?;
    assert!(created.status.success(), "{}", stderr(&created));
    let pair = pair_file(&t.0.join("cards.txt"), 2, 3, &t.0.join("pair.txt"))?;
    let recovered = holvard(
        &[
            "recover",
            "vault.age",
            "-o",
            "out",
            "--cards-file",
            s(&pair)?,
        ],
        &t.0,
    )?;
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert!(t.0.join("out/empty").is_dir());
    assert_eq!(fs::read_dir(t.0.join("out/empty"))?.count(), 0);
    Ok(())
}

#[test]
fn create_refuses_without_a_terminal_or_cards_file() -> TestResult {
    // cargo test pipes stdout, so it is never a terminal here.
    let t = TempDir::new()?;
    sample(&t.0)?;
    let refused = holvard(&["create", "docs"], &t.0)?;
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("--cards-file"),
        "{}",
        stderr(&refused)
    );
    assert!(!t.0.join("vault.age").exists());
    Ok(())
}

#[test]
fn nothing_is_overwritten() -> TestResult {
    let t = TempDir::new()?;
    sample(&t.0)?;
    fs::write(t.0.join("v.age"), b"old vault")?;
    let refused = holvard(
        &["create", "docs", "-o", "v.age", "--cards-file", "cards.txt"],
        &t.0,
    )?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(fs::read(t.0.join("v.age"))?, b"old vault");
    assert!(!t.0.join("cards.txt").exists());

    fs::write(t.0.join("cards.txt"), b"old cards")?;
    let refused = holvard(
        &[
            "create",
            "docs",
            "-o",
            "new.age",
            "--cards-file",
            "cards.txt",
        ],
        &t.0,
    )?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(fs::read(t.0.join("cards.txt"))?, b"old cards");
    assert!(!t.0.join("new.age").exists());

    fs::remove_file(t.0.join("cards.txt"))?;
    let created = holvard(
        &[
            "create",
            "docs",
            "-o",
            "good.age",
            "--cards-file",
            "cards.txt",
        ],
        &t.0,
    )?;
    assert!(created.status.success(), "{}", stderr(&created));
    let pair = pair_file(&t.0.join("cards.txt"), 1, 2, &t.0.join("pair.txt"))?;
    for existing in ["out", "out.partial"] {
        fs::create_dir(t.0.join(existing))?;
        fs::write(t.0.join(existing).join("mine"), b"keep")?;
        let refused = holvard(
            &[
                "recover",
                "good.age",
                "-o",
                "out",
                "--cards-file",
                s(&pair)?,
            ],
            &t.0,
        )?;
        assert_eq!(refused.status.code(), Some(1), "{existing}");
        assert_eq!(fs::read(t.0.join(existing).join("mine"))?, b"keep");
        fs::remove_dir_all(t.0.join(existing))?;
    }
    Ok(())
}

#[test]
fn damaged_vault_leaves_nothing_behind() -> TestResult {
    let t = TempDir::new()?;
    sample(&t.0)?;
    let created = holvard(
        &["create", "docs", "-o", "v.age", "--cards-file", "cards.txt"],
        &t.0,
    )?;
    assert!(created.status.success(), "{}", stderr(&created));
    let mut vault = fs::read(t.0.join("v.age"))?;
    let last = vault.last_mut().ok_or("empty vault")?;
    *last ^= 1;
    fs::write(t.0.join("v.age"), &vault)?;
    let pair = pair_file(&t.0.join("cards.txt"), 1, 2, &t.0.join("pair.txt"))?;
    let refused = holvard(
        &["recover", "v.age", "-o", "out", "--cards-file", s(&pair)?],
        &t.0,
    )?;
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("damaged"), "{}", stderr(&refused));
    assert!(!t.0.join("out").exists());
    assert!(!t.0.join("out.partial").exists());
    Ok(())
}

#[test]
fn wrong_pair_is_explained() -> TestResult {
    let t = TempDir::new()?;
    sample(&t.0)?;
    assert!(
        holvard(
            &["create", "docs", "-o", "a.age", "--cards-file", "a.txt"],
            &t.0
        )?
        .status
        .success()
    );
    assert!(
        holvard(
            &["create", "docs", "-o", "b.age", "--cards-file", "b.txt"],
            &t.0
        )?
        .status
        .success()
    );
    let pair = pair_file(&t.0.join("b.txt"), 1, 2, &t.0.join("pair.txt"))?;
    let refused = holvard(
        &["recover", "a.age", "-o", "out", "--cards-file", s(&pair)?],
        &t.0,
    )?;
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("don't open this vault"),
        "{}",
        stderr(&refused)
    );
    Ok(())
}

#[test]
fn messages_never_contain_card_words() -> TestResult {
    // Exact output, not a scan for card words: "cards", "memory" and
    // "twice" are SLIP-39 words and appear in normal messages.
    let t = TempDir::new()?;
    sample(&t.0)?;
    let created = holvard(
        &["create", "docs", "-o", "a.age", "--cards-file", "a.txt"],
        &t.0,
    )?;
    assert_eq!(
        String::from_utf8(created.stdout)?,
        "Saved a.age (4 files).\nAny two cards open the vault. Give each card to a different person or place; one card alone reveals nothing.\n"
    );
    assert_eq!(
        String::from_utf8(created.stderr)?,
        "holvard: a.txt holds all three cards. Anyone with it can open the vault. Print it, then delete it.\n"
    );
    // Fixed cards (the plain test vector's) against a vault they don't open.
    let vector = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/vault/cards.txt");
    let cards = fs::read_to_string(vector)?;
    let mut lines = cards.lines();
    let (a, b) = (lines.next().ok_or("card")?, lines.next().ok_or("card")?);
    fs::write(t.0.join("pair.txt"), format!("{a}\n{b}\n"))?;
    let wrong = holvard(&["recover", "a.age", "--cards-file", "pair.txt"], &t.0)?;
    assert_eq!(String::from_utf8(wrong.stdout)?, "");
    assert_eq!(
        String::from_utf8(wrong.stderr)?,
        "holvard: these two cards don't open this vault, or the vault file is damaged\n"
    );
    Ok(())
}

#[test]
fn plain_vector_recovers_as_contents() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/vault");
    let t = TempDir::new()?;
    let cards = fs::read_to_string(root.join("cards.txt"))?;
    let mut lines = cards.lines();
    let first = lines.next().ok_or("card")?;
    let third = lines.nth(1).ok_or("card")?;
    fs::write(t.0.join("pair.txt"), format!("{first}\n{third}\n"))?;
    let vault = root.join("vault.age");
    let recovered = holvard(
        &[
            "recover",
            s(&vault)?,
            "-o",
            "out",
            "--cards-file",
            "pair.txt",
        ],
        &t.0,
    )?;
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert_eq!(
        fs::read(t.0.join("out/contents"))?,
        fs::read(root.join("contents.txt"))?
    );
    Ok(())
}

#[test]
fn help_and_usage_errors() -> TestResult {
    let t = TempDir::new()?;
    for args in [
        &["--help"][..],
        &["create", "--help"],
        &["recover", "-h"],
        &["-V"],
    ] {
        assert_eq!(holvard(args, &t.0)?.status.code(), Some(0), "{args:?}");
    }
    for args in [
        &["init", "x"][..],
        &["create"],
        &["--bogus"],
        &["recover", "a", "b"],
    ] {
        assert_eq!(holvard(args, &t.0)?.status.code(), Some(2), "{args:?}");
    }
    Ok(())
}

#[test]
fn zip_vector_recovers_the_folder() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/vault-zip");
    let t = TempDir::new()?;
    let cards = fs::read_to_string(root.join("cards.txt"))?;
    let mut lines = cards.lines();
    let first = lines.next().ok_or("card")?;
    let third = lines.nth(1).ok_or("card")?;
    fs::write(t.0.join("pair.txt"), format!("{first}\n{third}\n"))?;
    let vault = root.join("vault.age");
    let recovered = holvard(
        &[
            "recover",
            s(&vault)?,
            "-o",
            "out",
            "--cards-file",
            "pair.txt",
        ],
        &t.0,
    )?;
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert_eq!(
        fs::read(t.0.join("out/letters/read-me-first.txt"))?,
        b"For my people.\n"
    );
    assert_eq!(
        fs::read(t.0.join("out/letters/notes/keys.txt"))?,
        b"The spare key is with the neighbour.\n"
    );
    Ok(())
}

#[test]
fn output_folder_with_a_trailing_slash() -> TestResult {
    let t = TempDir::new()?;
    let docs = sample(&t.0)?;
    let created = holvard(&["create", "docs", "--cards-file", "cards.txt"], &t.0)?;
    assert!(created.status.success(), "{}", stderr(&created));
    let pair = pair_file(&t.0.join("cards.txt"), 1, 2, &t.0.join("pair.txt"))?;
    let recovered = holvard(
        &[
            "recover",
            "vault.age",
            "-o",
            "out/",
            "--cards-file",
            s(&pair)?,
        ],
        &t.0,
    )?;
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert_eq!(tree(&t.0.join("out/docs"))?, tree(&docs)?);
    Ok(())
}

/// Runs `holvard <args>` in a pseudo-terminal through script(1), presses
/// Ctrl-C once the alternate screen is showing, and returns everything the
/// terminal received.
fn ctrl_c_on_card_screen(args: &[&str], cwd: &Path) -> common::Result<String> {
    type_on_card_screen(args, cwd, &[b"\x03"])
}

/// Runs `holvard <args>` in a pseudo-terminal through script(1), types
/// each of `keys` (half a second apart) once the alternate screen is
/// showing, and returns everything the terminal received.
fn type_on_card_screen(args: &[&str], cwd: &Path, keys: &[&[u8]]) -> common::Result<String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let log = cwd.join("terminal.log");
    let binary = env!("CARGO_BIN_EXE_holvard");
    let mut command = Command::new("script");
    if cfg!(target_os = "macos") {
        // -F: write the log as output arrives, so the test can watch it.
        command.args(["-q", "-F"]).arg(&log).arg(binary).args(args);
    } else {
        // util-linux: the command is one shell string.
        let line = std::iter::once(binary)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        command.args(["-q", "-f", "-e", "-c", &line]).arg(&log);
    }
    let mut child = command
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    // Wait for the alternate screen (at most 10 s), then press Ctrl-C.
    let mut waited = 0;
    while !fs::read(&log)
        .unwrap_or_default()
        .windows(8)
        .any(|w| w == b"\x1b[?1049h")
    {
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 1;
        if waited > 100 {
            let _ = child.kill();
            return Err("the alternate screen never showed".into());
        }
    }
    for key in keys {
        stdin.write_all(key)?;
        stdin.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // Give it up to 10 s to stop; then make sure it does.
    for _ in 0..100 {
        if child.try_wait()?.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    drop(stdin);
    child.wait()?;
    Ok(String::from_utf8_lossy(&fs::read(&log)?).into_owned())
}

/// What the terminal shows after the alternate screen was entered.
fn after_alternate(log: &str) -> Option<&str> {
    log.find("\x1b[?1049h").and_then(|at| log.get(at..))
}

#[test]
fn ctrl_c_on_a_card_restores_the_terminal() -> TestResult {
    let t = TempDir::new()?;
    sample(&t.0)?;
    let log = ctrl_c_on_card_screen(&["create", "docs"], &t.0)?;
    let after = after_alternate(&log).ok_or("no alternate screen")?;
    assert!(
        after.contains("\x1b[?1049l"),
        "terminal left on the alternate screen"
    );
    assert!(
        after.contains("\x1b[?1049lholvard: stopped before all cards were shown"),
        "{after:?}"
    );
    Ok(())
}

#[test]
fn ctrl_c_while_typing_a_card_restores_the_terminal() -> TestResult {
    let t = TempDir::new()?;
    sample(&t.0)?;
    let created = holvard(&["create", "docs", "--cards-file", "cards.txt"], &t.0)?;
    assert!(created.status.success(), "{}", stderr(&created));
    let log = ctrl_c_on_card_screen(&["recover", "vault.age"], &t.0)?;
    let after = after_alternate(&log).ok_or("no alternate screen")?;
    assert!(
        after.contains("\x1b[?1049l"),
        "terminal left on the alternate screen"
    );
    assert!(
        after.contains("\x1b[?1049lholvard: stopped; nothing was recovered"),
        "{after:?}"
    );
    assert!(!t.0.join("vault-recovered").exists());
    Ok(())
}

#[test]
fn an_empty_line_asks_again_instead_of_stopping() -> TestResult {
    let t = TempDir::new()?;
    let docs = sample(&t.0)?;
    let created = holvard(&["create", "docs", "--cards-file", "cards.txt"], &t.0)?;
    assert!(created.status.success(), "{}", stderr(&created));
    let cards = fs::read_to_string(t.0.join("cards.txt"))?;
    let card = |n: usize| -> common::Result<String> {
        let line = cards.lines().nth(n).ok_or("no such card")?;
        let (_, words) = line.split_once(": ").ok_or("no label")?;
        Ok(format!("{words}\n"))
    };
    let (first, second) = (card(0)?, card(1)?);
    let log = type_on_card_screen(
        &["recover", "vault.age"],
        &t.0,
        &[b"\n", first.as_bytes(), second.as_bytes()],
    )?;
    assert!(log.contains("To stop, press Ctrl-C."), "{log:?}");
    // macOS terminals drop a line over 1,024 characters, Enter included,
    // so the prompt says how to get out of that.
    assert!(
        log.contains("If typing stops working, press Ctrl-U and type the card again."),
        "{log:?}"
    );
    assert!(!log.contains("nothing was recovered"), "{log:?}");
    assert_eq!(tree(&t.0.join("vault-recovered/docs"))?, tree(&docs)?);
    Ok(())
}

#[test]
fn each_command_help_mentions_memory() -> TestResult {
    let t = TempDir::new()?;
    for (command, expected) in [
        ("create", "up to three times the folder's size"),
        ("recover", "about twice the vault's size"),
    ] {
        let help = holvard(&[command, "--help"], &t.0)?;
        let text = String::from_utf8(help.stdout)?;
        assert!(text.contains(expected), "{command}: {text}");
    }
    Ok(())
}
