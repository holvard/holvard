// SPDX-FileCopyrightText: 2026 Holvard contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The terminal. Cards are shown and typed on the alternate screen (the one
//! `less` and `vim` use), so they don't stay in the terminal's scrollback.
//! Typed cards are read from `/dev/tty` one byte at a time, not through
//! `std::io::stdin`, whose shared buffer would keep an unwiped copy.
//!
//! Ctrl-C, a closed terminal or a kill signal while the alternate screen is
//! showing: `handle_interrupts` removes the files this run created and has
//! not kept, leaves the screen, says what was not finished, and then ends
//! the program the way the signal would have.
//!
//! Known limits: the kernel's terminal buffer and the terminal program's
//! own memory are out of our reach; screen recording or terminal logging
//! keeps everything.

use core::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal as _, Read, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use zeroize::{Zeroize as _, Zeroizing};

const ENTER_ALTERNATE: &str = "\x1b[?1049h";
const LEAVE_ALTERNATE: &str = "\x1b[?1049l";
const CLEAR: &str = "\x1b[2J\x1b[H";
/// Longest line accepted as a card: 33 words of at most 8 letters fit in
/// 300 bytes, so this leaves room for extra spaces.
const MAX_LINE: usize = 1024;

/// Whether the alternate screen is showing, for the interrupt handler.
static ALTERNATE: AtomicBool = AtomicBool::new(false);
/// What to say if the program is stopped now (Ctrl-C and the like).
static STOP_MESSAGE: Mutex<Option<String>> = Mutex::new(None);
/// Set once the program is being stopped; from then on nothing more is
/// written to the terminal, so no card can appear on the restored screen.
static STOPPING: AtomicBool = AtomicBool::new(false);
/// Held for every write to the terminal, and by the interrupt handler from
/// the moment it starts until the program ends, so the two never overlap.
static TERMINAL: Mutex<()> = Mutex::new(());

/// Marks the program as stopping: later writes to the terminal fail.
fn begin_stop() {
    STOPPING.store(true, Ordering::SeqCst);
}

/// Writes `text` to the terminal unless the program is stopping, under the
/// terminal lock. `then` runs under the same lock after a successful write.
fn write_terminal(file: &mut File, text: &str, then: impl FnOnce()) -> io::Result<()> {
    let _guard = TERMINAL.lock().unwrap_or_else(PoisonError::into_inner);
    if STOPPING.load(Ordering::SeqCst) {
        return Err(io::Error::other("stopping"));
    }
    file.write_all(text.as_bytes())?;
    file.flush()?;
    then();
    Ok(())
}

/// Sets what to say if the program is stopped from now on; `None` says
/// nothing.
pub fn set_stop_message(message: Option<String>) {
    if let Ok(mut current) = STOP_MESSAGE.lock() {
        *current = message;
    }
}

/// Handles Ctrl-C, a closed terminal and termination requests from here
/// on: a background thread removes the files this run created and has not
/// kept, leaves the alternate screen if it is showing, prints the stop
/// message, and then ends the program as the signal would have. Without
/// this, Ctrl-C on a card would leave a blank screen, and an unfinished
/// vault that blocks the next run.
pub fn handle_interrupts() -> io::Result<()> {
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;
    std::thread::spawn(move || {
        if let Some(signal) = signals.forever().next() {
            // Stop all terminal writes first and keep the lock until the
            // program ends, so the main thread can't show another card on
            // the restored screen.
            begin_stop();
            let _guard = TERMINAL.lock().unwrap_or_else(PoisonError::into_inner);
            // Files this run created and has not kept go first; held
            // until the program ends, so none can be kept after this.
            let _files = crate::disk::remove_unkept();
            let left_alternate = ALTERNATE.swap(false, Ordering::SeqCst);
            if left_alternate && let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty") {
                let _ = write!(tty, "{LEAVE_ALTERNATE}");
                let _ = tty.flush();
            }
            if let Some(message) = STOP_MESSAGE.lock().ok().and_then(|m| m.clone()) {
                // Leaving the alternate screen puts the cursor back on a
                // fresh line. On the normal screen the terminal has just
                // echoed `^C` on the current line, so start a new one.
                let newline = if left_alternate { "" } else { "\n" };
                eprintln!("{newline}holvard: {message}");
            }
            let _ = signal_hook::low_level::emulate_default_handler(signal);
            // Not reached for these signals; the shell's code for Ctrl-C.
            std::process::exit(130);
        }
    });
    Ok(())
}

/// What `read_line` got.
#[derive(Debug)]
pub enum Line {
    /// A non-empty line, trimmed.
    Card(Zeroizing<String>),
    /// A blank line (an extra Enter).
    Empty,
    /// Longer than any card; the rest of the line was read and dropped.
    TooLong,
    /// Not text (a stray byte that is not UTF-8).
    NotText,
    /// The input ended.
    End,
}

/// Whether cards can be shown and typed here: stdout is a terminal and the
/// controlling terminal (`/dev/tty`) can be opened.
pub fn interactive() -> bool {
    io::stdout().is_terminal() && Tty::open().is_ok()
}

/// The controlling terminal, for reading and writing.
pub struct Tty {
    file: File,
}

impl Tty {
    /// Opens `/dev/tty`.
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        Ok(Self { file })
    }

    /// Writes a line.
    pub fn say(&mut self, text: &str) -> io::Result<()> {
        write_terminal(&mut self.file, text, || ())?;
        write_terminal(&mut self.file, "\n", || ())
    }

    /// Switches to the alternate screen until the returned value is dropped.
    pub fn alternate(&mut self) -> io::Result<AltScreen<'_>> {
        write_terminal(&mut self.file, &format!("{ENTER_ALTERNATE}{CLEAR}"), || {
            ALTERNATE.store(true, Ordering::SeqCst);
        })?;
        Ok(AltScreen { tty: self })
    }
}

/// The alternate screen; leaving it restores the normal screen as it was.
pub struct AltScreen<'a> {
    tty: &'a mut Tty,
}

impl AltScreen<'_> {
    /// Clears the alternate screen.
    pub fn clear(&mut self) -> io::Result<()> {
        write_terminal(&mut self.tty.file, CLEAR, || ())
    }

    /// Writes text followed by a newline.
    pub fn say(&mut self, text: &str) -> io::Result<()> {
        self.tty.say(text)
    }

    /// Waits until Enter is pressed: `true`. `false` if the input ended
    /// first (Ctrl-D on an empty line gives that on a terminal).
    pub fn wait_enter(&mut self) -> io::Result<bool> {
        let mut byte = [0u8; 1];
        loop {
            if self.tty.file.read(&mut byte)? == 0 {
                return Ok(false);
            }
            if byte == [b'\n'] {
                return Ok(true);
            }
        }
    }

    /// Reads one typed line; see [`read_line`].
    pub fn read_card(&mut self) -> io::Result<Line> {
        read_line(&mut self.tty.file)
    }
}

impl Drop for AltScreen<'_> {
    fn drop(&mut self) {
        // Leave only once, even if the interrupt handler races us.
        let _guard = TERMINAL.lock().unwrap_or_else(PoisonError::into_inner);
        if ALTERNATE.swap(false, Ordering::SeqCst) {
            // Nothing more can be done if this fails.
            let _ = write!(self.tty.file, "{LEAVE_ALTERNATE}");
            let _ = self.tty.file.flush();
        }
    }
}

/// Reads one line, one byte per `read`, into a buffer allocated once and
/// wiped when dropped. A line longer than `MAX_LINE` is read to its end
/// and dropped, so its rest is never taken as the next line.
pub fn read_line(from: &mut impl Read) -> io::Result<Line> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    let mut byte = [0u8; 1];
    let mut too_long = false;
    let mut ended = false;
    loop {
        if from.read(&mut byte)? == 0 {
            ended = true;
            break;
        }
        if byte == [b'\n'] {
            break;
        }
        if line.len() < MAX_LINE {
            line.extend_from_slice(&byte);
        } else {
            too_long = true;
        }
    }
    byte.zeroize();
    if ended && line.is_empty() && !too_long {
        return Ok(Line::End);
    }
    if too_long {
        return Ok(Line::TooLong);
    }
    let Ok(text) = core::str::from_utf8(&line) else {
        return Ok(Line::NotText);
    };
    let text = text.trim();
    if text.is_empty() {
        return Ok(Line::Empty);
    }
    let mut card = Zeroizing::new(String::with_capacity(MAX_LINE));
    card.push_str(text);
    Ok(Line::Card(card))
}

/// Room for a card shown by `format_card`: title, 15 bytes per word, prompt.
fn format_capacity(words: usize) -> usize {
    words.saturating_mul(15).saturating_add(96)
}

/// A card as shown on screen: a title, its words numbered from 1, four per
/// row, and the prompt.
pub fn format_card(number: usize, card: &str) -> Zeroizing<String> {
    let words = card.split_whitespace().count();
    let mut shown = Zeroizing::new(String::with_capacity(format_capacity(words)));
    // Writing to a String cannot fail.
    let _ = write!(shown, "Card {number} of 3\n\n");
    for (index, word) in (1usize..).zip(card.split_whitespace()) {
        let _ = write!(shown, "{index:>2} {word:<8}");
        shown.push_str(if index % 4 == 0 { "\n" } else { "   " });
    }
    shown.push_str("\n\nWrite it down, check it, then press Enter.\n");
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(input: &[u8]) -> io::Result<Vec<Line>> {
        let mut input = io::Cursor::new(input.to_vec());
        let mut out = Vec::new();
        loop {
            let line = read_line(&mut input)?;
            let end = matches!(line, Line::End);
            out.push(line);
            if end {
                return Ok(out);
            }
        }
    }

    fn is_card(line: Option<&Line>, text: &str) -> bool {
        matches!(line, Some(Line::Card(s)) if s.as_str() == text)
    }

    #[test]
    fn reads_one_line_at_a_time() -> io::Result<()> {
        let got = lines(b"academic acid\nnext\n")?;
        assert!(is_card(got.first(), "academic acid"));
        assert!(is_card(got.get(1), "next"));
        assert!(matches!(got.get(2), Some(Line::End)));
        Ok(())
    }

    #[test]
    fn blank_line_means_stop() -> io::Result<()> {
        assert!(matches!(lines(b"   \n")?.first(), Some(Line::Empty)));
        Ok(())
    }

    #[test]
    fn long_line_is_refused_and_not_read_as_the_next_card() -> io::Result<()> {
        let mut data = vec![b'a'; 3000];
        data.extend_from_slice(b"\nreal card\n");
        let got = lines(&data)?;
        assert!(matches!(got.first(), Some(Line::TooLong)));
        assert!(is_card(got.get(1), "real card"));
        Ok(())
    }

    #[test]
    fn a_stray_byte_asks_again_instead_of_failing() -> io::Result<()> {
        let got = lines(b"acad\xffemic\nnext\n")?;
        assert!(matches!(got.first(), Some(Line::NotText)));
        assert!(is_card(got.get(1), "next"));
        Ok(())
    }

    #[test]
    fn crlf_and_a_missing_final_newline_are_handled() -> io::Result<()> {
        let got = lines(b"word\r\nlast")?;
        assert!(is_card(got.first(), "word"));
        assert!(is_card(got.get(1), "last"));
        Ok(())
    }

    #[test]
    fn card_is_shown_numbered_in_rows_of_four() {
        let shown = format_card(2, "aa bb cc dd ee");
        assert!(shown.starts_with("Card 2 of 3\n"));
        let rows: Vec<&str> = shown
            .lines()
            .filter(|l| l.contains(" aa ") || l.contains(" ee"))
            .collect();
        assert!(
            matches!(rows.as_slice(), [first, second]
                if first.contains(" 1 aa") && first.contains(" 4 dd") && second.contains(" 5 ee")),
            "{}",
            shown.as_str()
        );
        assert!(
            shown
                .trim_end()
                .ends_with("Write it down, check it, then press Enter.")
        );
    }

    #[test]
    fn showing_a_card_never_grows_its_buffer() {
        // 33 words of 8 letters, the longest a card can be.
        let card = vec!["abcdefgh"; 33].join(" ");
        let shown = format_card(3, &card);
        assert!(shown.capacity() >= shown.len());
        assert_eq!(shown.capacity(), format_capacity(33));
    }

    #[test]
    fn nothing_is_written_once_stopping_has_begun() -> Result<(), Box<dyn std::error::Error>> {
        // The interrupt handler restores the normal screen; after that, a
        // card must never be printed on it, even if the main thread is
        // still running.
        let t = crate::testutil::TempDir::new()?;
        let path = t.0.join("terminal");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let mut tty = Tty { file };
        tty.say("before")?;
        begin_stop();
        assert!(tty.say("card words").is_err());
        assert!(tty.alternate().is_err());
        assert_eq!(std::fs::read_to_string(&path)?, "before\n");
        Ok(())
    }
}
