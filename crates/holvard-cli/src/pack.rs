// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Packing a folder into a zip and unpacking it again, with the guards from
//! spec/vault.md: only plain files and folders, safe names, fixed limits,
//! and no growth of buffers that hold the contents.

use core::fmt;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Cursor, Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use zeroize::{Zeroize as _, Zeroizing};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// How much a vault may hold. The same values apply when creating and when
/// recovering, so every vault `create` makes can be recovered.
pub struct Limits {
    /// Files and folders, the top folder included.
    pub max_entries: usize,
    /// Bytes of file data, counted as read or as decompressed.
    pub max_bytes: u64,
}

/// spec/vault.md: at most 10 000 entries and 4 GiB of file data.
pub const LIMITS: Limits = Limits {
    max_entries: 10_000,
    max_bytes: 4 * 1024 * 1024 * 1024,
};

/// Why a folder could not be packed or a zip unpacked.
#[derive(Debug)]
pub enum PackError {
    /// Reading or writing a path failed.
    Io(PathBuf, io::Error),
    /// The folder holds a symbolic link.
    Symlink(PathBuf),
    /// The folder holds a device, socket or pipe.
    Special(PathBuf),
    /// A name that would not come back the same (not UTF-8, `\`, control
    /// characters), or an unsafe name in a zip.
    BadName(PathBuf),
    /// More entries than the limit.
    TooManyEntries,
    /// More file data than the limit.
    TooBig,
    /// A file changed while it was being packed.
    Changed(PathBuf),
    /// The path to pack is not a folder.
    NotAFolder(PathBuf),
    /// Writing the zip failed.
    Zip(String),
    /// The zip could not be read.
    BadArchive(String),
    /// Two entries would create the same file.
    Duplicate(PathBuf),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Io(path, e) => write!(f, "{}: {e}", path.display()),
            PackError::Symlink(path) => write!(
                f,
                "{} is a link; only plain files and folders can go in a vault",
                path.display()
            ),
            PackError::Special(path) => write!(
                f,
                "{} is not a plain file or folder; only those can go in a vault",
                path.display()
            ),
            PackError::BadName(path) => write!(
                f,
                "the name {} can't go in a vault (no backslashes or control characters)",
                path.display()
            ),
            PackError::TooManyEntries => write!(
                f,
                "too many files and folders; a vault holds at most {}",
                LIMITS.max_entries
            ),
            PackError::TooBig => f.write_str("too much data; a vault holds at most 4 GiB of files"),
            PackError::Changed(path) => write!(
                f,
                "{} changed while it was being packed; try again when nothing is changing the folder",
                path.display()
            ),
            PackError::NotAFolder(path) => write!(f, "{} is not a folder", path.display()),
            PackError::Zip(e) => write!(f, "could not pack the folder: {e}"),
            PackError::BadArchive(e) => write!(f, "the vault's contents are damaged: {e}"),
            PackError::Duplicate(path) => write!(
                f,
                "the vault holds {} twice; nothing was overwritten",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PackError {}

/// File modes inside the zip and on disk: owner only.
const FILE_MODE: u32 = 0o600;
const FOLDER_MODE: u32 = 0o700;

/// A thing to put in the zip, found by `walk`.
struct Entry {
    /// Name inside the zip: top folder first, `/`-separated; folders end
    /// in `/`.
    name: String,
    /// Where it is on disk.
    path: PathBuf,
    kind: Kind,
}

enum Kind {
    Folder,
    /// Size and identity as seen by `symlink_metadata`, checked again when
    /// the file is opened.
    File {
        size: u64,
        dev: u64,
        ino: u64,
    },
}

/// What `scan` found. Nothing has been read yet, so a caller can warn
/// about size before `write` allocates anything big.
pub struct Scan {
    entries: Vec<Entry>,
    /// Number of files (not folders).
    pub files: usize,
    /// Total bytes of file data.
    pub bytes: u64,
}

/// Lists `folder` for packing. The folder itself may be a link (it is
/// resolved, and the zip's top folder takes the real folder's name); links
/// inside it are refused.
pub fn scan(folder: &Path, limits: &Limits) -> Result<Scan, PackError> {
    let entries = walk(folder, limits)?;
    let mut files = 0usize;
    let mut bytes = 0u64;
    for entry in &entries {
        if let Kind::File { size, .. } = entry.kind {
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(size);
        }
    }
    Ok(Scan {
        entries,
        files,
        bytes,
    })
}

impl Scan {
    /// Reads the files and writes the zip into one buffer, allocated once.
    pub fn write(&self) -> Result<Zeroizing<Vec<u8>>, PackError> {
        write_zip(&self.entries, bound(&self.entries)?)
    }
}

/// Whether a name can go in a vault and come back the same: no `\` (zip
/// readers take it as a folder separator) and no control characters.
fn check_name(name: &str, path: &Path) -> Result<(), PackError> {
    if name.is_empty() || name.contains('\\') || name.chars().any(char::is_control) {
        return Err(PackError::BadName(path.to_path_buf()));
    }
    Ok(())
}

/// Lists the folder (top folder included) without following links,
/// sorted by zip name so the same folder always gives the same zip. Walks
/// with a list instead of recursion, so deep trees cannot overflow the
/// stack.
fn walk(folder: &Path, limits: &Limits) -> Result<Vec<Entry>, PackError> {
    let io_error = |path: &Path| {
        let path = path.to_path_buf();
        move |e| PackError::Io(path, e)
    };
    let root = fs::canonicalize(folder).map_err(io_error(folder))?;
    if !fs::metadata(&root).map_err(io_error(&root))?.is_dir() {
        return Err(PackError::NotAFolder(folder.to_path_buf()));
    }
    let top = root
        .file_name()
        .ok_or_else(|| PackError::NotAFolder(folder.to_path_buf()))?
        .to_str()
        .ok_or_else(|| PackError::BadName(root.clone()))?;
    check_name(top, &root)?;

    let mut entries = vec![Entry {
        name: format!("{top}/"),
        path: root.clone(),
        kind: Kind::Folder,
    }];
    let mut bytes = 0u64;
    let mut folders = vec![(root.clone(), format!("{top}/"))];
    while let Some((folder, prefix)) = folders.pop() {
        for item in fs::read_dir(&folder).map_err(io_error(&folder))? {
            let path = item.map_err(io_error(&folder))?.path();
            let meta = fs::symlink_metadata(&path).map_err(io_error(&path))?;
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| PackError::BadName(path.clone()))?;
            check_name(name, &path)?;
            let kind = meta.file_type();
            let entry = if kind.is_symlink() {
                return Err(PackError::Symlink(path));
            } else if kind.is_dir() {
                let name = format!("{prefix}{name}/");
                folders.push((path.clone(), name.clone()));
                Entry {
                    name,
                    path,
                    kind: Kind::Folder,
                }
            } else if kind.is_file() {
                bytes = bytes.checked_add(meta.len()).ok_or(PackError::TooBig)?;
                if bytes > limits.max_bytes {
                    return Err(PackError::TooBig);
                }
                Entry {
                    name: format!("{prefix}{name}"),
                    path,
                    kind: Kind::File {
                        size: meta.len(),
                        dev: meta.dev(),
                        ino: meta.ino(),
                    },
                }
            } else {
                return Err(PackError::Special(path));
            };
            entries.push(entry);
            if entries.len() > limits.max_entries {
                return Err(PackError::TooManyEntries);
            }
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Opens the file, checks it is still the one `walk` saw (same device and
/// inode, so a path swapped for a link is caught), and reads exactly
/// `size` bytes into a buffer allocated once. One more byte means the
/// file grew; fewer means it shrank.
fn read_file(path: &Path, size: u64, dev: u64, ino: u64) -> Result<Zeroizing<Vec<u8>>, PackError> {
    let changed = || PackError::Changed(path.to_path_buf());
    let mut file = File::open(path).map_err(|e| PackError::Io(path.to_path_buf(), e))?;
    let meta = file
        .metadata()
        .map_err(|e| PackError::Io(path.to_path_buf(), e))?;
    if (meta.dev(), meta.ino()) != (dev, ino) {
        return Err(changed());
    }
    let length = usize::try_from(size).map_err(|_| PackError::TooBig)?;
    let mut data = Zeroizing::new(vec![0u8; length]);
    file.read_exact(&mut data).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            changed()
        } else {
            PackError::Io(path.to_path_buf(), e)
        }
    })?;
    let mut probe = [0u8; 1];
    let more = file
        .read(&mut probe)
        .map_err(|e| PackError::Io(path.to_path_buf(), e))?;
    probe.zeroize();
    if more != 0 {
        return Err(changed());
    }
    Ok(data)
}

/// Upper bound for the zip, far above deflate's worst case: per file its
/// size + size/64 + 1 KiB + twice its name; per folder 1 KiB + twice its
/// name; plus 64 KiB.
fn bound(entries: &[Entry]) -> Result<usize, PackError> {
    let mut total: u64 = 64 * 1024;
    for entry in entries {
        let name = u64::try_from(entry.name.len()).map_err(|_| PackError::TooBig)?;
        let mut add = name.checked_mul(2).ok_or(PackError::TooBig)?;
        add = add.checked_add(1024).ok_or(PackError::TooBig)?;
        if let Kind::File { size, .. } = entry.kind {
            add = add
                .checked_add(size)
                .and_then(|a| a.checked_add(size / 64))
                .ok_or(PackError::TooBig)?;
        }
        total = total.checked_add(add).ok_or(PackError::TooBig)?;
    }
    usize::try_from(total).map_err(|_| PackError::TooBig)
}

/// Writes the zip into a buffer of exactly `capacity` bytes, through a
/// `Cursor` over a fixed slice, which cannot grow: running out of room is
/// an error, never a reallocation that would leave an unwiped copy.
fn write_zip(entries: &[Entry], capacity: usize) -> Result<Zeroizing<Vec<u8>>, PackError> {
    let zip_error = |e: &dyn fmt::Display| PackError::Zip(e.to_string());
    let mut buffer = Zeroizing::new(vec![0u8; capacity]);
    let length = {
        let mut zip = ZipWriter::new(Cursor::new(buffer.as_mut_slice()));
        for entry in entries {
            match entry.kind {
                Kind::Folder => {
                    let options = SimpleFileOptions::default().unix_permissions(FOLDER_MODE);
                    zip.add_directory(entry.name.as_str(), options)
                        .map_err(|e| zip_error(&e))?;
                }
                Kind::File { size, dev, ino } => {
                    let options = SimpleFileOptions::default()
                        .compression_method(CompressionMethod::Deflated)
                        .unix_permissions(FILE_MODE)
                        .large_file(size >= 0xFFFF_FFFF);
                    zip.start_file(entry.name.as_str(), options)
                        .map_err(|e| zip_error(&e))?;
                    let data = read_file(&entry.path, size, dev, ino)?;
                    zip.write_all(&data).map_err(|e| zip_error(&e))?;
                }
            }
        }
        let cursor = zip.finish().map_err(|e| zip_error(&e))?;
        usize::try_from(cursor.position()).map_err(|e| zip_error(&e))?
    };
    buffer.truncate(length);
    Ok(buffer)
}

/// What `unpack` produced.
#[derive(Debug)]
pub enum Unpacked {
    /// A zip, unpacked: this many files (folders not counted).
    Files(usize),
    /// Bytes that are not a zip, saved as one file named `contents`.
    Contents,
}

const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
/// Copy buffer for unpacking, wiped when dropped.
const COPY_BUFFER: usize = 64 * 1024;

/// Unpacks a vault's contents into `dest`, an empty folder this run
/// created. A zip is unpacked by our own loop (never the zip crate's
/// `extract`), with the rules of spec/vault.md; anything else is saved as
/// `dest/contents`.
pub fn unpack(bytes: &[u8], dest: &Path, limits: &Limits) -> Result<Unpacked, PackError> {
    let archive = if bytes.starts_with(ZIP_MAGIC) {
        zip::ZipArchive::new(Cursor::new(bytes)).ok()
    } else {
        None
    };
    let Some(mut archive) = archive else {
        let mut written = 0;
        write_new_file(
            &dest.join("contents"),
            Path::new("contents"),
            &mut Cursor::new(bytes),
            limits.max_bytes,
            &mut written,
        )?;
        return Ok(Unpacked::Contents);
    };
    if archive.len() > limits.max_entries {
        return Err(PackError::TooManyEntries);
    }
    let mut written = 0u64;
    let mut files = 0usize;
    // Folders this run created, by their exact names.
    let mut made = HashSet::from([dest.to_path_buf()]);
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| PackError::BadArchive(e.to_string()))?;
        let (parts, is_folder) = safe_name(entry.name_raw())?;
        // The path inside the vault, for messages.
        let shown: PathBuf = parts.iter().collect();
        check_mode(entry.unix_mode(), is_folder, &shown)?;
        if is_folder {
            make_folders(dest, &parts, &mut made)?;
        } else {
            let (_, parents) = parts
                .split_last()
                .ok_or_else(|| PackError::BadName(shown.clone()))?;
            make_folders(dest, parents, &mut made)?;
            write_new_file(
                &dest.join(&shown),
                &shown,
                &mut entry,
                limits.max_bytes,
                &mut written,
            )?;
            files = files.saturating_add(1);
        }
    }
    Ok(Unpacked::Files(files))
}

/// Checks a raw zip name and splits it into its parts: UTF-8, not
/// starting with `/`, no `\`, NUL or other control characters, and only
/// plain parts (none empty, `.` or `..`). A trailing `/` marks a folder.
/// The zip crate's `enclosed_name` is not used: it rewrites bad names
/// (`/abs` to `abs`, `top/../leaf` to `leaf`) instead of refusing them.
fn safe_name(raw: &[u8]) -> Result<(Vec<&str>, bool), PackError> {
    let bad = || PackError::BadName(PathBuf::from(String::from_utf8_lossy(raw).into_owned()));
    let name = core::str::from_utf8(raw).map_err(|_| bad())?;
    let (body, is_folder) = match name.strip_suffix('/') {
        Some(body) => (body, true),
        None => (name, false),
    };
    if body.is_empty()
        || body.starts_with('/')
        || body.contains('\\')
        || body.chars().any(char::is_control)
    {
        return Err(bad());
    }
    let parts: Vec<&str> = body.split('/').collect();
    if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return Err(bad());
    }
    Ok((parts, is_folder))
}

/// When an entry carries a Unix mode, its type must match its name: a
/// regular file, or a folder for names ending in `/`. Links, devices and
/// pipes are refused. Entries without a mode cannot claim to be anything
/// else, so the real guards are the name rules and `create_new`.
fn check_mode(mode: Option<u32>, is_folder: bool, path: &Path) -> Result<(), PackError> {
    let Some(mode) = mode else { return Ok(()) };
    let kind = mode & S_IFMT;
    let matches = kind == 0 || kind == if is_folder { S_IFDIR } else { S_IFREG };
    if matches {
        Ok(())
    } else {
        Err(PackError::Special(path.to_path_buf()))
    }
}

/// Creates the folders `parts` names below `dest`, one level at a time,
/// with mode 0700. A folder this run already made (`made`, exact names) is
/// reused; anything else already there is a duplicate: a file of the same
/// name, or a folder whose name differs only in case on a case-insensitive
/// disk (`A/` and `a/`), which must not be merged.
fn make_folders(dest: &Path, parts: &[&str], made: &mut HashSet<PathBuf>) -> Result<(), PackError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut path = dest.to_path_buf();
    let mut shown = PathBuf::new();
    for part in parts {
        path.push(part);
        shown.push(part);
        if made.contains(&path) {
            continue;
        }
        fs::DirBuilder::new()
            .mode(FOLDER_MODE)
            .create(&path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    PackError::Duplicate(shown.clone())
                } else {
                    PackError::Io(shown.clone(), e)
                }
            })?;
        made.insert(path.clone());
    }
    Ok(())
}

/// Creates `path` (never overwriting, mode 0600; `shown` names it in
/// messages, as a path inside the vault) and copies `from` into it
/// through one wiped buffer, adding to `written` and stopping as soon as
/// the total would pass `max_bytes`, whatever the zip's headers claim.
fn write_new_file(
    path: &Path,
    shown: &Path,
    from: &mut impl io::Read,
    max_bytes: u64,
    written: &mut u64,
) -> Result<(), PackError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let io_error = |e| PackError::Io(shown.to_path_buf(), e);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                PackError::Duplicate(shown.to_path_buf())
            } else {
                io_error(e)
            }
        })?;
    let mut buffer = Zeroizing::new(vec![0u8; COPY_BUFFER]);
    loop {
        let read = from
            .read(&mut buffer)
            .map_err(|e| PackError::BadArchive(e.to_string()))?;
        if read == 0 {
            return Ok(());
        }
        let count = u64::try_from(read).map_err(|_| PackError::TooBig)?;
        *written = written.checked_add(count).ok_or(PackError::TooBig)?;
        if *written > max_bytes {
            return Err(PackError::TooBig);
        }
        let chunk = buffer.get(..read).ok_or(PackError::TooBig)?;
        file.write_all(chunk).map_err(io_error)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, TestResult, sample, tree};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use zeroize::Zeroizing;

    fn pack(folder: &Path, limits: &Limits) -> Result<Zeroizing<Vec<u8>>, PackError> {
        scan(folder, limits)?.write()
    }

    /// The entry names in a zip. `file_names()` yields names that may fail
    /// to decode, so each is checked.
    fn names(zip: &[u8]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let archive = zip::ZipArchive::new(io::Cursor::new(zip))?;
        Ok(archive
            .file_names()
            .map(|name| name.map(std::borrow::Cow::into_owned))
            .collect::<Result<_, _>>()?)
    }

    #[test]
    fn same_folder_gives_identical_bytes() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        assert_eq!(*pack(&docs, &LIMITS)?, *pack(&docs, &LIMITS)?);
        Ok(())
    }

    #[test]
    fn scan_counts_files_and_bytes() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        let scanned = scan(&docs, &LIMITS)?;
        assert_eq!(scanned.files, 4);
        assert_eq!(scanned.bytes, 5 + 10 + 256);
        Ok(())
    }

    #[test]
    fn top_folder_name_from_dot_and_trailing_slash() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        let plain = names(&pack(&docs, &LIMITS)?)?;
        let slash = names(&pack(&docs.join(""), &LIMITS)?)?;
        let dot = names(&pack(&docs.join("."), &LIMITS)?)?;
        assert!(plain.iter().all(|n| n.starts_with("docs/")), "{plain:?}");
        assert!(plain.contains(&"docs/".to_owned()));
        assert!(plain.contains(&"docs/empty/".to_owned()));
        assert_eq!(plain, slash);
        assert_eq!(plain, dot);
        Ok(())
    }

    #[test]
    fn symlinked_top_folder_is_followed_but_links_inside_are_refused() -> TestResult {
        // The owner names the folder; on macOS that path is often a link
        // (cloud drives). All three spellings resolve to the real folder
        // and take its real name.
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        let alias = t.0.join("alias");
        std::os::unix::fs::symlink(&docs, &alias)?;
        let expected = names(&pack(&docs, &LIMITS)?)?;
        for spelling in [alias.clone(), alias.join(""), alias.join(".")] {
            assert_eq!(names(&pack(&spelling, &LIMITS)?)?, expected, "{spelling:?}");
        }
        std::os::unix::fs::symlink(&t.0, docs.join("inner"))?;
        assert!(matches!(pack(&alias, &LIMITS), Err(PackError::Symlink(_))));
        Ok(())
    }

    #[test]
    fn a_file_is_not_a_folder() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        assert!(matches!(
            pack(&docs.join("a.txt"), &LIMITS),
            Err(PackError::NotAFolder(_))
        ));
        Ok(())
    }

    #[test]
    fn symlinks_and_special_files_are_refused() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        std::os::unix::fs::symlink(docs.join("a.txt"), docs.join("link"))?;
        assert!(matches!(pack(&docs, &LIMITS), Err(PackError::Symlink(_))));
        fs::remove_file(docs.join("link"))?;
        std::os::unix::fs::symlink(&t.0, docs.join("sub/dirlink"))?;
        assert!(matches!(pack(&docs, &LIMITS), Err(PackError::Symlink(_))));
        fs::remove_file(docs.join("sub/dirlink"))?;
        // A FIFO, made with mkfifo(1) since std cannot make one without
        // unsafe code.
        let status = std::process::Command::new("mkfifo")
            .arg(docs.join("fifo"))
            .status()?;
        assert!(status.success());
        assert!(matches!(pack(&docs, &LIMITS), Err(PackError::Special(_))));
        Ok(())
    }

    #[test]
    fn names_that_would_not_round_trip_are_refused() -> TestResult {
        for bad in ["back\\slash", "tab\there", "bell\u{7}"] {
            let t = TempDir::new()?;
            let docs = sample(&t.0)?;
            fs::write(docs.join(bad), b"x")?;
            assert!(
                matches!(pack(&docs, &LIMITS), Err(PackError::BadName(_))),
                "{bad:?}"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_names_are_refused() -> TestResult {
        use std::os::unix::ffi::OsStrExt as _;
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        fs::write(docs.join(std::ffi::OsStr::from_bytes(b"bad\xff")), b"x")?;
        assert!(matches!(pack(&docs, &LIMITS), Err(PackError::BadName(_))));
        Ok(())
    }

    #[test]
    fn entry_limit_counts_folders_and_the_top_folder() -> TestResult {
        let t = TempDir::new()?;
        let docs = t.0.join("docs");
        fs::create_dir(&docs)?;
        fs::write(docs.join("a"), b"")?;
        fs::write(docs.join("b"), b"")?;
        // docs/, docs/a, docs/b: three entries.
        let small = |max_entries| Limits {
            max_entries,
            max_bytes: 1024,
        };
        assert!(pack(&docs, &small(3)).is_ok());
        assert!(matches!(
            pack(&docs, &small(2)),
            Err(PackError::TooManyEntries)
        ));
        Ok(())
    }

    #[test]
    fn byte_limit_is_exact() -> TestResult {
        let t = TempDir::new()?;
        let docs = t.0.join("docs");
        fs::create_dir(&docs)?;
        fs::write(docs.join("a"), [7u8; 100])?;
        let limit = |max_bytes| Limits {
            max_entries: 10,
            max_bytes,
        };
        assert!(pack(&docs, &limit(100)).is_ok());
        assert!(matches!(pack(&docs, &limit(99)), Err(PackError::TooBig)));
        Ok(())
    }

    #[test]
    fn real_limits_match_the_spec() {
        assert_eq!(LIMITS.max_entries, 10_000);
        assert_eq!(LIMITS.max_bytes, 4_294_967_296);
    }

    #[test]
    fn too_small_output_buffer_fails_instead_of_growing() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        let scanned = scan(&docs, &LIMITS)?;
        // Room for nothing: writing must fail, not reallocate.
        assert!(matches!(
            write_zip(&scanned.entries, 16),
            Err(PackError::Zip(_))
        ));
        Ok(())
    }

    #[test]
    fn a_file_that_changes_while_read_is_refused() -> TestResult {
        let t = TempDir::new()?;
        let path = t.0.join("f");
        fs::write(&path, b"12345")?;
        let meta = fs::symlink_metadata(&path)?;
        let (dev, ino) = (meta.dev(), meta.ino());
        assert_eq!(read_file(&path, 5, dev, ino)?.as_slice(), b"12345");
        fs::write(&path, b"123456")?; // grew
        assert!(matches!(
            read_file(&path, 5, dev, ino),
            Err(PackError::Changed(_))
        ));
        fs::write(&path, b"1234")?; // shrank
        assert!(matches!(
            read_file(&path, 5, dev, ino),
            Err(PackError::Changed(_))
        ));
        fs::remove_file(&path)?;
        let other = t.0.join("other");
        fs::write(&other, b"12345")?;
        std::os::unix::fs::symlink(&other, &path)?; // swapped for a link
        assert!(matches!(
            read_file(&path, 5, dev, ino),
            Err(PackError::Changed(_))
        ));
        Ok(())
    }

    // ---- Unpacking ----

    /// Position of `needle` in `haystack` at or after `from`.
    fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        haystack
            .get(from..)?
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p.saturating_add(from))
    }

    /// A zip with the given (name, unix mode, bytes) entries. The zip
    /// writer's `unix_permissions` drops file-type and setuid bits, so each
    /// entry is written as a plain file and its full mode is then patched
    /// into the central directory: "version made by" host byte 3 (Unix) at
    /// offset 5, external attributes = mode << 16 at offset 38.
    fn hostile(
        entries: &[(&str, Option<u32>, &[u8])],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, _, data) in entries {
            w.start_file(*name, SimpleFileOptions::default())?;
            w.write_all(data)?;
        }
        let mut zip = w.finish()?.into_inner();
        let mut at = 0usize;
        for (_, mode, _) in entries {
            at = find(&zip, b"PK\x01\x02", at).ok_or("no central header")?;
            if let Some(mode) = mode {
                *zip.get_mut(at.saturating_add(5)).ok_or("short")? = 3;
                zip.get_mut(at.saturating_add(38)..at.saturating_add(42))
                    .ok_or("short")?
                    .copy_from_slice(&mode.checked_shl(16).ok_or("mode")?.to_le_bytes());
            }
            at = at.saturating_add(4);
        }
        // The fixture must say what the test claims (zip reports modes
        // without the setuid, setgid and sticky bits).
        let mut archive = zip::ZipArchive::new(Cursor::new(&zip))?;
        for (index, (_, mode, _)) in entries.iter().enumerate() {
            if let Some(mode) = mode {
                assert_eq!(
                    archive.by_index_raw(index)?.unix_mode(),
                    Some(mode & !0o7_000)
                );
            }
        }
        Ok(zip)
    }

    /// Replaces a name in a zip's local and central headers with another
    /// of the same length, to make names the zip writer refuses.
    fn rename_in_place(zip: &mut [u8], from: &str, to: &str) -> TestResult {
        assert_eq!(from.len(), to.len());
        let mut at = 0usize;
        let mut count = 0usize;
        while let Some(found) = find(zip, from.as_bytes(), at) {
            zip.get_mut(found..found.saturating_add(to.len()))
                .ok_or("short")?
                .copy_from_slice(to.as_bytes());
            at = found.saturating_add(1);
            count = count.saturating_add(1);
        }
        assert_eq!(count, 2, "{from} must appear in exactly two headers");
        Ok(())
    }

    /// Makes the local and central headers claim `size` uncompressed bytes.
    fn set_uncompressed_size(zip: &mut [u8], size: u32) -> TestResult {
        let local = find(zip, b"PK\x03\x04", 0).ok_or("no local header")?;
        zip.get_mut(local.saturating_add(22)..local.saturating_add(26))
            .ok_or("short")?
            .copy_from_slice(&size.to_le_bytes());
        let central = find(zip, b"PK\x01\x02", 0).ok_or("no central header")?;
        zip.get_mut(central.saturating_add(24)..central.saturating_add(28))
            .ok_or("short")?
            .copy_from_slice(&size.to_le_bytes());
        Ok(())
    }

    /// Unpacks into a fresh staging folder and reports whether it was
    /// refused; also checks nothing appeared next to the staging folder.
    fn refused(zip: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let t = TempDir::new()?;
        let dest = t.0.join("dest");
        fs::create_dir(&dest)?;
        let result = unpack(zip, &dest, &LIMITS);
        assert_eq!(
            fs::read_dir(&t.0)?.count(),
            1,
            "wrote outside the staging folder"
        );
        Ok(result.is_err())
    }

    fn staging() -> Result<(TempDir, PathBuf), Box<dyn std::error::Error>> {
        let t = TempDir::new()?;
        let dest = t.0.join("dest");
        fs::create_dir(&dest)?;
        Ok((t, dest))
    }

    #[test]
    fn round_trip_keeps_everything() -> TestResult {
        let t = TempDir::new()?;
        let docs = sample(&t.0)?;
        let zip = pack(&docs, &LIMITS)?;
        let out = t.0.join("out");
        fs::create_dir(&out)?;
        assert!(matches!(unpack(&zip, &out, &LIMITS)?, Unpacked::Files(4)));
        assert_eq!(tree(&out.join("docs"))?, tree(&docs)?);
        Ok(())
    }

    #[test]
    fn bad_names_are_refused() -> TestResult {
        for name in [
            "top/../leaf",
            "a/./b",
            "a//b",
            "C:\\x",
            "a\\b",
            "..",
            "./x",
            "x/..",
        ] {
            assert!(refused(&hostile(&[(name, None, b"x")])?)?, "{name:?}");
            // Refused for its name, before any folder is made: creating
            // folders one level at a time would also stop `..`, but only
            // as a second guard.
            let (_t, dest) = staging()?;
            let result = unpack(&hostile(&[(name, None, b"x")])?, &dest, &LIMITS);
            assert!(matches!(result, Err(PackError::BadName(_))), "{name:?}");
        }
        // Names the zip writer will not write: patched in afterwards.
        for (safe, bad) in [
            ("xabs", "/abs"),
            ("nulxx", "nul\0x"),
            ("tab\x41", "tab\x09"),
        ] {
            let mut zip = hostile(&[(safe, None, b"x")])?;
            rename_in_place(&mut zip, safe, bad)?;
            assert!(refused(&zip)?, "{bad:?}");
        }
        Ok(())
    }

    #[test]
    fn only_files_and_folders_are_unpacked() -> TestResult {
        assert!(refused(&hostile(&[(
            "link",
            Some(0o120_777),
            b"/etc/passwd"
        )])?)?);
        assert!(refused(&hostile(&[("fifo", Some(0o010_644), b"")])?)?);
        // A folder mode on a name without a trailing slash, and the reverse.
        assert!(refused(&hostile(&[("dir", Some(0o040_755), b"")])?)?);
        // setuid and exec bits are dropped: the file comes out 0600.
        let (_t, dest) = staging()?;
        unpack(&hostile(&[("run", Some(0o104_755), b"x")])?, &dest, &LIMITS)?;
        assert_eq!(
            fs::metadata(dest.join("run"))?.permissions().mode() & 0o7777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn entry_limit_is_checked_before_writing() -> TestResult {
        let (_t, dest) = staging()?;
        let zip = hostile(&[("a", None, b""), ("b", None, b""), ("c", None, b"")])?;
        let two = Limits {
            max_entries: 2,
            max_bytes: 1024,
        };
        assert!(matches!(
            unpack(&zip, &dest, &two),
            Err(PackError::TooManyEntries)
        ));
        assert_eq!(fs::read_dir(&dest)?.count(), 0);
        Ok(())
    }

    #[test]
    fn byte_limit_counts_what_is_decompressed() -> TestResult {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let deflate = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        w.start_file("big", deflate)?;
        w.write_all(&vec![0u8; 1 << 20])?;
        let zip = w.finish()?.into_inner();
        assert!(zip.len() < 10_000, "1 MiB of zeros compresses well");
        let small = Limits {
            max_entries: 10,
            max_bytes: 1000,
        };
        let (_t, dest) = staging()?;
        assert!(matches!(
            unpack(&zip, &dest, &small),
            Err(PackError::TooBig)
        ));
        let (_t2, dest2) = staging()?;
        let exact = Limits {
            max_entries: 10,
            max_bytes: 1 << 20,
        };
        unpack(&zip, &dest2, &exact)?;
        Ok(())
    }

    #[test]
    fn understated_size_in_header_does_not_help() -> TestResult {
        let mut zip = hostile(&[("big", None, &vec![0u8; 1 << 20])])?;
        set_uncompressed_size(&mut zip, 10)?;
        let small = Limits {
            max_entries: 10,
            max_bytes: 1000,
        };
        let (_t, dest) = staging()?;
        assert!(unpack(&zip, &dest, &small).is_err());
        assert!(fs::metadata(dest.join("big")).map_or(true, |m| m.len() <= 1000));
        Ok(())
    }

    #[test]
    fn duplicate_name_unpacks_once_and_overwrites_nothing() -> TestResult {
        let mut zip = hostile(&[("samf", None, b"first"), ("same", None, b"second")])?;
        rename_in_place(&mut zip, "samf", "same")?;
        let (_t, dest) = staging()?;
        unpack(&zip, &dest, &LIMITS)?;
        // zip 9.0.3 keeps the last entry of a duplicated name.
        assert_eq!(fs::read(dest.join("same"))?, b"second");
        assert_eq!(fs::read_dir(&dest)?.count(), 1);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn case_collision_is_refused_on_case_insensitive_disks() -> TestResult {
        assert!(refused(&hostile(&[("A", None, b"1"), ("a", None, b"2")])?)?);
        Ok(())
    }

    #[test]
    fn bytes_that_are_not_a_zip_are_saved_as_contents() -> TestResult {
        let (_t, dest) = staging()?;
        assert!(matches!(
            unpack(b"plain bytes", &dest, &LIMITS)?,
            Unpacked::Contents
        ));
        assert_eq!(fs::read(dest.join("contents"))?, b"plain bytes");
        Ok(())
    }

    #[test]
    fn zip_with_extra_fields_unpacks() -> TestResult {
        let zip = include_bytes!("../../../test-vectors/vault-zip/with-extras.zip");
        let (_t, dest) = staging()?;
        assert!(matches!(unpack(zip, &dest, &LIMITS)?, Unpacked::Files(2)));
        assert_eq!(
            fs::read(dest.join("letters/read-me-first.txt"))?,
            b"For my people.\n"
        );
        assert_eq!(
            fs::read(dest.join("letters/notes/keys.txt"))?,
            b"The spare key is with the neighbour.\n"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn folders_differing_only_in_case_are_refused() -> TestResult {
        // On a case-insensitive disk A/ and a/ are one folder; unpacking
        // must not merge two folders of the vault into one.
        let zip = hostile(&[("A/first.txt", None, b"1"), ("a/second.txt", None, b"2")])?;
        let (_t, dest) = staging()?;
        assert!(matches!(
            unpack(&zip, &dest, &LIMITS),
            Err(PackError::Duplicate(_))
        ));
        Ok(())
    }

    #[test]
    fn a_file_and_a_folder_with_the_same_name_are_a_duplicate() -> TestResult {
        let zip = hostile(&[("a", None, b"file"), ("a/b.txt", None, b"x")])?;
        let (_t, dest) = staging()?;
        let error = unpack(&zip, &dest, &LIMITS).err().ok_or("accepted")?;
        assert!(matches!(error, PackError::Duplicate(_)), "{error}");
        // Messages name the path inside the vault, not the staging folder.
        assert_eq!(
            error.to_string(),
            "the vault holds a twice; nothing was overwritten"
        );
        Ok(())
    }
}
