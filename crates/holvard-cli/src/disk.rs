// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Files and folders on disk: new files that clean up after a failed or
//! stopped run, and syncing, so "Saved" and "Recovered" mean on disk.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use rustix::io::Errno;

/// Files this run created and has not kept, for `remove_unkept` when the
/// program is stopped (Ctrl-C and the like), which skips every `Drop`.
static RESERVED: Mutex<Vec<Reserved>> = Mutex::new(Vec::new());

/// A file this run created: where it is and which file it is.
#[derive(Clone, PartialEq, Eq)]
struct Reserved {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Reserved {
    /// Removes the file, but only while its path still names it: a file
    /// someone else put there meanwhile is left alone.
    fn remove(&self) {
        let ours = fs::symlink_metadata(&self.path)
            .is_ok_and(|m| (m.dev(), m.ino()) == (self.dev, self.ino));
        if ours {
            // Nothing more can be done if this fails.
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A file this run created. Dropped without being kept, it is removed
/// (see `Reserved::remove`); if the program is stopped instead,
/// `remove_unkept` does the same.
pub struct NewFile {
    file: File,
    reserved: Reserved,
    kept: bool,
}

impl NewFile {
    /// Creates `path` with `mode`; fails if anything is there.
    pub fn create(path: &Path, mode: u32) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        let meta = file.metadata()?;
        let reserved = Reserved {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
        };
        let file = Self {
            file,
            reserved,
            kept: false,
        };
        list().push(file.reserved.clone());
        Ok(file)
    }

    /// Writes all of `data`, then waits until it is on disk.
    pub fn write_synced(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)?;
        self.file.sync_all()
    }

    pub fn path(&self) -> &Path {
        &self.reserved.path
    }
}

impl Drop for NewFile {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        let mut list = list();
        list.retain(|r| *r != self.reserved);
        self.reserved.remove();
    }
}

/// The list of reserved files, locked.
fn list() -> std::sync::MutexGuard<'static, Vec<Reserved>> {
    RESERVED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The run succeeded: keeps all of `files`, then runs `then` (clearing the
/// stop message), both under the lock `remove_unkept` takes. So a stop
/// sees either nothing kept, and removes everything, or all kept and
/// nothing left to say; never one file kept and the other removed.
pub fn keep_all(files: impl IntoIterator<Item = NewFile>, then: impl FnOnce()) {
    let mut list = list();
    let files: Vec<NewFile> = files
        .into_iter()
        .map(|mut file| {
            file.kept = true;
            list.retain(|r| *r != file.reserved);
            file
        })
        .collect();
    then();
    drop(list);
    // Dropped after the lock is released: kept files don't take it.
    drop(files);
}

/// The program is being stopped: removes every file this run created and
/// has not kept. Hold the returned lock until the program ends, so the
/// main thread cannot keep a file after this.
#[must_use]
pub fn remove_unkept() -> impl Sized {
    let mut list = list();
    for reserved in list.drain(..) {
        reserved.remove();
    }
    list
}

/// Syncs a folder, so files created or renamed in it are still there
/// after a crash. Some file systems (FAT on USB sticks, for one) cannot
/// sync folders and say so with EINVAL or ENOTSUP; that is not an error.
pub fn sync_folder(path: &Path) -> io::Result<()> {
    match File::open(path)?.sync_all() {
        Err(e)
            if Errno::from_io_error(&e)
                .is_some_and(|n| n == Errno::INVAL || n == Errno::NOTSUP) =>
        {
            Ok(())
        }
        other => other,
    }
}

/// The folder `path` is in: `.` for a bare file name.
pub fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, TestResult};
    use std::fs;
    use std::path::Path;

    #[test]
    fn a_new_file_not_kept_is_removed() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("v.age");
        let mut file = NewFile::create(&path, 0o600)?;
        file.write_synced(b"data")?;
        assert_eq!(fs::read(&path)?, b"data");
        drop(file);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn a_kept_file_stays() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("v.age");
        let mut file = NewFile::create(&path, 0o600)?;
        file.write_synced(b"data")?;
        keep_all([file], || ());
        assert_eq!(fs::read(&path)?, b"data");
        Ok(())
    }

    #[test]
    fn a_file_put_in_its_place_is_left_alone() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("v.age");
        let file = NewFile::create(&path, 0o600)?;
        fs::remove_file(&path)?;
        fs::write(&path, b"someone else's")?;
        drop(file);
        assert_eq!(fs::read(&path)?, b"someone else's");
        Ok(())
    }

    /// Whether `path` is on the list Ctrl-C cleans up.
    fn reserved(path: &Path) -> bool {
        RESERVED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|r| r.path == path)
    }

    #[test]
    fn a_new_file_is_reserved_until_dropped() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("v.age");
        let file = NewFile::create(&path, 0o600)?;
        assert!(reserved(&path));
        drop(file);
        assert!(!reserved(&path));
        Ok(())
    }

    #[test]
    fn kept_files_are_no_longer_reserved() -> TestResult {
        let t = TempDir::new()?;
        let (a, b) = (t.0.join("a"), t.0.join("b"));
        let files = [NewFile::create(&a, 0o600)?, NewFile::create(&b, 0o600)?];
        let mut ran = false;
        keep_all(files, || ran = true);
        assert!(ran);
        assert!(!reserved(&a) && !reserved(&b));
        assert!(a.exists() && b.exists());
        Ok(())
    }

    #[test]
    fn removing_a_reserved_file_spares_a_replacement() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("v.age");
        fs::write(&path, b"ours")?;
        let meta = fs::symlink_metadata(&path)?;
        let ours = Reserved {
            path: path.clone(),
            dev: meta.dev(),
            ino: meta.ino(),
        };
        // Moved aside, not removed, so the replacement gets a new inode.
        fs::rename(&path, t.0.join("moved"))?;
        fs::write(&path, b"someone else's")?;
        ours.remove();
        assert_eq!(fs::read(&path)?, b"someone else's");
        fs::rename(t.0.join("moved"), &path)?;
        ours.remove();
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn create_never_overwrites() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("v.age");
        fs::write(&path, b"old")?;
        assert!(NewFile::create(&path, 0o600).is_err());
        assert_eq!(fs::read(&path)?, b"old");
        Ok(())
    }

    #[test]
    fn folders_sync_and_missing_ones_fail() -> TestResult {
        let t = TempDir::new()?;
        sync_folder(&t.0)?;
        assert!(sync_folder(&t.0.join("missing")).is_err());
        Ok(())
    }

    #[test]
    fn parent_of_a_bare_name_is_the_current_folder() {
        assert_eq!(parent_of(Path::new("vault.age")), Path::new("."));
        assert_eq!(parent_of(Path::new("out/vault.age")), Path::new("out"));
        assert_eq!(parent_of(Path::new("/vault.age")), Path::new("/"));
    }
}
