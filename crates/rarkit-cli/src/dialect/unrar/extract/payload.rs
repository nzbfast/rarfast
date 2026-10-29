//! `p`'s standard output: what it is, and the writer its payload goes
//! through.
//!
//! Three levers from the print study of 30 Sep 2026 (its levers 4, 5
//! and 6), each behind a runtime knob that restores the old rule, so one
//! binary times a lever against the rule it replaces:
//!
//! | lever | what | knob restoring the old rule |
//! |---|---|---|
//! | 4 | a SOLID set printed into a regular file states the file cost class ([`states_file`]) | `RARFAST_P_SINK_FILE=0` |
//! | 5 | a pipe on standard output is widened to 1 MiB (`PIPE_BYTES`, Linux with glibc) | `RARFAST_P_PIPE=0` |
//! | 6 | the payload is written straight to the descriptor, one `write` a piece, not through the standard library's line writer, except into a pipe on macOS ([`writer`]) | `RARFAST_P_RAW=0` |
//!
//! Everything here reads standard output through a DUPLICATE of its
//! descriptor, taken once for the run: the same open file description, so
//! the same pipe, the same file offset and the same `O_APPEND`, and nothing
//! is ever written to descriptor 1 by two routes in one run (`p` sends no
//! message to standard output, [`super::super::Out::beside_payload`]).
//! Unix only: on Windows the console writer is the standard library's own
//! and every rule here keeps the old one.

use std::io::Write;
use std::sync::OnceLock;

/// What standard output is, as far as the levers care. Only Unix reads
/// it, so elsewhere every run is [`Kind::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) enum Kind {
    /// A FIFO: a pipe to a consumer, or a named pipe.
    Pipe,
    /// A regular file (`> out.bin`).
    File,
    /// Anything else: a terminal, `/dev/null`, a socket, a closed
    /// descriptor, or a system this module does not read.
    Other,
}

/// A knob: `0` or `off` restores the old rule, anything else (or nothing)
/// keeps the lever. Read once.
fn knob_on(name: &str, cell: &'static OnceLock<bool>) -> bool {
    *cell.get_or_init(|| {
        !matches!(
            crate::knob::reader_var(name)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "0" | "off"
        )
    })
}

/// Lever 4's knob.
fn sink_file_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    knob_on("RARFAST_P_SINK_FILE", &ON)
}

/// Lever 6's knob.
fn raw_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    knob_on("RARFAST_P_RAW", &ON)
}

/// Standard output's duplicate and what it is, taken once. `None` where
/// the descriptor could not be duplicated (closed) or on a system this
/// module does not read.
fn stdout() -> Option<&'static (std::fs::File, Kind)> {
    static OUT: OnceLock<Option<(std::fs::File, Kind)>> = OnceLock::new();
    OUT.get_or_init(open).as_ref()
}

#[cfg(unix)]
fn open() -> Option<(std::fs::File, Kind)> {
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileTypeExt;
    let file = std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned().ok()?);
    let kind = match file.metadata() {
        Ok(meta) if meta.file_type().is_fifo() => Kind::Pipe,
        Ok(meta) if meta.file_type().is_file() => Kind::File,
        _ => Kind::Other,
    };
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if kind == Kind::Pipe {
        widen(&file);
    }
    Some((file, kind))
}

#[cfg(not(unix))]
fn open() -> Option<(std::fs::File, Kind)> {
    None
}

/// What standard output is ([`Kind::Other`] where it cannot be read).
pub(super) fn kind() -> Kind {
    stdout().map_or(Kind::Other, |(_, kind)| *kind)
}

/// Lever 4: whether `p` of this set states `sink_is_file` `Some(true)`.
///
/// For a SOLID set printed into a REGULAR FILE. The engine's solid path
/// (`read::sequential`, `extract_solid`) then walks the chain on a worker
/// and leaves the caller's thread only the writes, which is what `x` of a
/// solid set does. Counted and timed on 1 Oct 2026:
/// into a file c6 1.09x on both architectures and small_solid_20k 1.22x
/// (x86) to 2.0x (macOS, with lever 6), no row lost.
///
/// NOT into a PIPE, although the research priced it there: the solid path
/// hands every member between two threads, and a consumer that shares the
/// machine's cores (any unpinned `rarfast p | ...`) pays for it. With the
/// consumer unpinned, small_solid_20k (20,000 members of 2.3 KiB) read
/// 0.650x on an M1 Mac (timed) and 0.822x on x86 against the old rule,
/// while c6 (members of 1.6 MB) read 1.13x and 1.03x; only a consumer on
/// a core of its own saw c6's 1.22x. A pipe scope for large members is
/// not yet swept by member size. NOT for `/dev/null` or a terminal (a
/// character device): there the caller's thread has nothing to hide. NOT
/// for a non-solid set: `Some(true)` puts every written member of any size
/// under the seam, and small-r read 0.21x with it.
pub(super) fn states_file(solid: bool) -> bool {
    solid && sink_file_on() && kind() == Kind::File
}

/// Lever 6: the writer one member's payload goes through.
///
/// The standard library's `Stdout` is a line writer: a piece holding a
/// newline is written up to its last one and its tail is buffered, to go
/// out ahead of the next piece, so a text member costs two `write` calls
/// a piece where one would do (36,891 for the 20,000 members of
/// small_solid_20k). This writes each piece whole to the duplicate
/// descriptor, and keeps nothing between calls, so a heading `-ierr`
/// holds for an encrypted member ([`super::ReleaseFirst`]) still leads its
/// member's first byte and follows the member before it.
///
/// Except into a PIPE on macOS, which keeps the line writer. Timed on
/// an M1 Mac (1 Oct 2026, K=7), c6 into a pipe read 0.980 [0.831, 0.990]
/// raw against the parent (pinned 0.985), the null [0.995, 1.060]; untimed
/// probes there found no write size that matches the line writer (whole
/// pieces, and slices of 64 KiB, 256 KiB and 1 MiB, all 2.00 to 2.03 s
/// against its 1.97 to 2.00), and slices cost the stored big member 3.9 percent
/// of instructions. The raw writer's gain into a macOS pipe was one 10 ms
/// tick on small_solid_20k, so the pipe keeps the old rule there; files
/// and `/dev/null` take the raw writer on every Unix (small_solid_20k into
/// `/dev/null` 1.167x on an M1 Mac, 1.076x on x86), and so does a Linux
/// pipe (level or better on every row counted).
pub(super) fn writer() -> Box<dyn Write + Send> {
    match stdout() {
        Some((_, Kind::Pipe)) if cfg!(target_os = "macos") => Box::new(std::io::stdout()),
        Some((file, _)) if raw_on() => Box::new(Raw(file)),
        _ => Box::new(std::io::stdout()),
    }
}

/// `EBADF`, the same number on every Unix this builds for.
const EBADF: i32 = 9;

/// Standard output's duplicate, written directly.
struct Raw(&'static std::fs::File);

impl Write for Raw {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match (&mut &*self.0).write(bytes) {
            // What `Stdout` does with a descriptor that refuses writes (one
            // opened for reading only): the bytes are taken and dropped.
            Err(error) if error.raw_os_error() == Some(EBADF) => Ok(bytes.len()),
            other => other,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Lever 5: the size a pipe on standard output is widened to.
///
/// Linux's default pipe holds 64 KiB, so a writer faster than its consumer
/// blocks, and is woken, sixteen times a MiB. At 1 MiB (the unprivileged
/// ceiling, `/proc/sys/fs/pipe-max-size`, by default) c6 into a pipe read
/// 4.65 to 3.45 s with the walk still writing (the research's
/// `pipe_size.py`). macOS sizes its pipes itself and has no such call.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(super) const PIPE_BYTES: i32 = 1 << 20;

/// `fcntl(F_SETPIPE_SZ)` on the pipe, unless its knob is off. Advice: a
/// refusal (over the ceiling, over the user's pipe quota) leaves the pipe
/// as it was, and a pipe already wider is left alone.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn widen(file: &std::fs::File) {
    use std::os::fd::AsRawFd;
    static ON: OnceLock<bool> = OnceLock::new();
    if !knob_on("RARFAST_P_PIPE", &ON) {
        return;
    }
    let fd = file.as_raw_fd();
    // SAFETY: two `fcntl` calls on a descriptor this process holds open for
    // the length of the call (the `&File` borrow), taking and returning
    // integers only; neither reads or writes any memory of ours.
    unsafe {
        if libc::fcntl(fd, libc::F_GETPIPE_SZ) < PIPE_BYTES {
            libc::fcntl(fd, libc::F_SETPIPE_SZ, PIPE_BYTES);
        }
    }
}
