//! THE WINDOWS LONE WRITE's writer (`route::lone_write_ships_on` has the
//! count and the screen): the member the walk reads alone is written
//! behind it, in order, on a thread of its own, into a file whose end is
//! kept a step ahead of the bytes written (`route::lone_write_end`).
//!
//! **Nothing of the member's file moves but the thread it is written on.**
//! The thread owns the member's [`TimedFile`] whole and makes its calls
//! for it, in the order the walk made them: every write, the close's flush,
//! and the drop that cuts a member that stopped short back to its bytes and
//! sets its mode, its time and its name. The writer the engine holds is
//! [`Behind`], which copies each piece it is given and hands it over; its
//! drop waits for the thread, so the file is closed, timed and named by
//! the time the walk looks at the path again, as before.
//!
//! **A write that fails is said at the next call.** The thread keeps the
//! first error and writes nothing after it; the next write or the close's
//! flush returns it, which ends the walk as a failed write does
//! (`Walk::on_close`). The engine may have read a few pieces more by then
//! (at most [`DEPTH`]); none of them is written.
//!
//! **The end of the file is kept a step ahead and moved back.** Before a
//! write that would pass it, the file's end is set a step past that write
//! (`route::LONE_WRITE_STEP`), but never to the member's declared length:
//! only the member's own last bytes take it there. So the writes inside the
//! end extend nothing, and a run KILLED mid member leaves its bytes and at
//! most a step of zeros past them, a file shorter than the member, under
//! the member's name (the promise: never a file a downloader reads as
//! complete). [`TimedFile::reserved`] says where the end is, so a member
//! that stops short is cut back to the bytes that arrived at its drop, as
//! a reservation is given back.
//!
//! Memory: [`DEPTH`] pieces in flight and as many kept to be used again,
//! each the engine's own piece (128 KiB for a stored member): about 2 MiB.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

/// The lone write's answer for this run (`Run::lone_written`), taken by the
/// first member's writer: one member a run, and only the one it said.
static LONE: AtomicBool = AtomicBool::new(false);

/// How many pieces may wait for the thread: the screen's figure.
pub(super) const DEPTH: usize = 8;

/// States whether this run's member is the lone write's.
pub(super) fn state(lone: bool) {
    LONE.store(lone, Ordering::Relaxed);
}

/// The member's writer: [`Behind`] for the lone write's member, the file
/// itself for every other, and for one whose thread the system refuses.
pub(super) fn writer(file: TimedFile) -> Box<dyn Write + Send> {
    if !LONE.swap(false, Ordering::Relaxed) || file.staged.is_some() || file.written != 0 {
        return Box::new(file);
    }
    let (tx, rx) = mpsc::sync_channel::<Hand>(DEPTH);
    let (give, back) = mpsc::channel::<Vec<u8>>();
    let failed = Arc::new(AtomicBool::new(false));
    let said = Arc::clone(&failed);
    let spawned = std::thread::Builder::new()
        .name("rarfast-lone-write".into())
        .spawn(move || write_behind(&rx, &give, &said));
    let Ok(join) = spawned else {
        return Box::new(file);
    };
    let behind = Behind {
        tx: Some(tx),
        back,
        failed,
        join: Some(join),
    };
    match behind
        .tx
        .as_ref()
        .map(|tx| tx.send(Hand::Open(Box::new(file))))
    {
        Some(Ok(())) => Box::new(behind),
        // The thread is gone before its first message: it had nothing, so
        // the file went with the message and comes back in the error.
        Some(Err(mpsc::SendError(Hand::Open(file)))) => {
            drop(behind);
            file
        }
        _ => Box::new(behind),
    }
}

/// What the walk hands the thread.
enum Hand {
    /// The member's file, first.
    Open(Box<TimedFile>),
    /// A piece of the member, in order.
    Piece(Vec<u8>),
    /// The close's flush, answered on the channel given.
    Flush(mpsc::SyncSender<std::io::Result<()>>),
}

/// The thread: the file's calls, in the order handed over, the first error
/// kept for the next flush. Ends when the walk's writer is dropped, and
/// drops the file here, before that drop returns.
fn write_behind(rx: &mpsc::Receiver<Hand>, give: &mpsc::Sender<Vec<u8>>, failed: &AtomicBool) {
    let mut file: Option<Box<TimedFile>> = None;
    let mut error: Option<std::io::Error> = None;
    for hand in rx {
        match hand {
            Hand::Open(opened) => file = Some(opened),
            Hand::Piece(piece) => {
                if error.is_none() && !failed.load(Ordering::Relaxed) {
                    if let Some(file) = file.as_mut() {
                        ahead(file, piece.len());
                        if let Err(e) = file.write_all(&piece) {
                            error = Some(e);
                            failed.store(true, Ordering::Relaxed);
                        }
                        #[cfg(feature = "read-depth-knob")]
                        stop_at(file.written);
                    }
                }
                let _ = give.send(piece);
            }
            Hand::Flush(answer) => {
                let said = match error.take() {
                    Some(e) => Err(e),
                    None if failed.load(Ordering::Relaxed) => Err(earlier()),
                    None => file.as_mut().map_or(Ok(()), |file| file.flush()),
                };
                let _ = answer.send(said);
            }
        }
    }
    drop(file);
}

/// Sets the file's end ahead of a write of `len` bytes where it would
/// pass it (`route::lone_write_end`). A file system that refuses it takes
/// the write as before, extending the file, and the end stays where it was.
fn ahead(file: &mut TimedFile, len: usize) {
    let end = file.reserved.max(file.written);
    let to = super::route::lone_write_end(end, file.written, len as u64, file.declared);
    if to > end && file.file.set_len(to).is_ok() {
        file.reserved = to;
    }
}

/// COUNT ONLY (feature `read-depth-knob`): `RARFAST_LONE_WRITE_STOP_AT=N`
/// ends the process outright, as a kill does, once N bytes of the member are
/// written: nothing is flushed, cut back or named after it. What
/// `tests/lone_write_windows.rs` reads the file a killed run leaves by.
#[cfg(feature = "read-depth-knob")]
fn stop_at(written: u64) {
    static AT: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let at = *AT.get_or_init(|| {
        std::env::var("RARFAST_LONE_WRITE_STOP_AT")
            .ok()
            .and_then(|v| v.trim().parse().ok())
    });
    if at.is_some_and(|at| written >= at) {
        std::process::abort();
    }
}

/// The error a call is given after the one that carried the write's own.
fn earlier() -> std::io::Error {
    std::io::Error::other("an earlier write of this member failed")
}

/// The thread is gone: it panicked, or its file was never handed over.
fn gone() -> std::io::Error {
    std::io::Error::other("the member's writer thread is gone")
}

/// The writer the engine holds for the lone write's member.
struct Behind {
    tx: Option<mpsc::SyncSender<Hand>>,
    /// Pieces the thread has written, to be filled again.
    back: mpsc::Receiver<Vec<u8>>,
    failed: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Behind {
    fn hand(&self, hand: Hand) -> std::io::Result<()> {
        match self.tx.as_ref().map(|tx| tx.send(hand)) {
            Some(Ok(())) => Ok(()),
            _ => Err(gone()),
        }
    }
}

impl Write for Behind {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.failed.load(Ordering::Relaxed) {
            return Err(self.flush().err().unwrap_or_else(earlier));
        }
        let mut piece = self.back.try_recv().unwrap_or_default();
        piece.clear();
        piece.extend_from_slice(buf);
        self.hand(Hand::Piece(piece))
    }

    /// Every piece handed over is written, then the file's own flush:
    /// what the close asks for before its verdict.
    fn flush(&mut self) -> std::io::Result<()> {
        let (answer, said) = mpsc::sync_channel(1);
        self.hand(Hand::Flush(answer))?;
        said.recv().unwrap_or_else(|_| Err(gone()))
    }
}

impl Drop for Behind {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
