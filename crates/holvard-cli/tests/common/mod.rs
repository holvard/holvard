// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Helpers for the tests that run the `holvard` binary.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type TestResult = Result<()>;

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A fresh empty folder under the system temp folder, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> io::Result<Self> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("holvard-cli-{}-{n}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs the built `holvard` binary in `cwd`.
pub fn holvard(args: &[&str], cwd: &Path) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_holvard"))
        .args(args)
        .current_dir(cwd)
        .output()
}

/// `docs/` with a nested folder, an empty folder, a hidden file, an empty
/// file and binary data: four files.
pub fn sample(root: &Path) -> io::Result<PathBuf> {
    let docs = root.join("docs");
    fs::create_dir_all(docs.join("sub/deeper"))?;
    fs::create_dir(docs.join("empty"))?;
    fs::write(docs.join("a.txt"), b"hello")?;
    fs::write(docs.join(".hidden"), b"secret-ish")?;
    fs::write(docs.join("zero"), b"")?;
    fs::write(docs.join("sub/deeper/bin"), (0u8..=255).collect::<Vec<_>>())?;
    Ok(docs)
}

/// Every path under `root` (relative) with its bytes, `None` for folders,
/// sorted.
pub fn tree(root: &Path) -> io::Result<Vec<(PathBuf, Option<Vec<u8>>)>> {
    let mut found = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder)? {
            let path = entry?.path();
            let relative = path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_path_buf();
            if fs::symlink_metadata(&path)?.is_dir() {
                found.push((relative, None));
                folders.push(path);
            } else {
                found.push((relative, Some(fs::read(&path)?)));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Writes cards `i` and `j` (counted from 1) of a cards file made by
/// `holvard create --cards-file` into a new file `dest`.
pub fn pair_file(cards: &Path, i: usize, j: usize, dest: &Path) -> Result<PathBuf> {
    let text = fs::read_to_string(cards)?;
    let lines: Vec<&str> = text.lines().collect();
    let pick = |n: usize| -> Result<&str> {
        Ok(*lines
            .get(n.checked_sub(1).ok_or("cards count from 1")?)
            .ok_or("no such card")?)
    };
    fs::write(dest, format!("{}\n{}\n", pick(i)?, pick(j)?))?;
    Ok(dest.to_path_buf())
}

/// The path as a `&str`, for command lines.
pub fn s(path: &Path) -> Result<&str> {
    Ok(path.to_str().ok_or("path is not UTF-8")?)
}
