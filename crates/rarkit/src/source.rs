//! The two traits a caller implements to hand the engine its bytes (API
//! spec section 3).
//!
//! Section 3 asks for as little as it can: one way in for the bytes of a
//! single file, and one way in for the next file of a set. Everything
//! else the engine needs it works out for itself.

use std::sync::Arc;

use crate::read::Archive;
use crate::Result;

/// Somewhere the engine can read bytes from, possibly while they are
/// still arriving.
///
/// - **There is no cursor.** Every read names its own offset and takes
///   `&self`, so several of the engine's threads may be inside one source
///   at once and none of them can disturb another's position. Nothing of
///   the engine's state lives in here.
/// - **Blocking is not an error.** An implementation that waits for bytes
///   to arrive is doing what this trait was shaped for. The engine holds
///   no lock of its own across the call.
/// - **A short read is not an error either** - the engine simply asks
///   again. What IS an error is `Ok(0)` before `len()` is reached, which
///   the engine reads as a source that stopped early and reports as
///   [`ErrorKind::Truncated`](crate::ErrorKind::Truncated).
/// - **Returning `Err` stops the operation**, and the `io::Error` travels
///   out intact inside
///   [`ErrorKind::Source`](crate::ErrorKind::Source). A source that
///   blocks cancels itself this way.
/// - **`available` only ever saves work.** The engine consults it to
///   avoid waiting where waiting is optional, and never relies on it for
///   an answer.
pub trait RangeSource: Send + Sync {
    /// Fill as much of `buf` as is available from `offset` onwards, and
    /// answer how much that was.
    ///
    /// Waiting for bytes that have not arrived yet is allowed. Answering
    /// with fewer than were asked for is allowed. `Ok(0)` carries one
    /// meaning and one only: `offset` has reached or passed the end of
    /// what this source will ever hold.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// How far from the start this source can be read without waiting.
    ///
    /// The figure may only ever grow. A source that is already complete
    /// answers with its whole length.
    fn available(&self) -> u64;

    /// How long this source will finally be, when that is known at all.
    fn len(&self) -> Option<u64>;

    /// Whether this source is known to hold nothing. A source whose
    /// length is not yet known is not empty, merely unmeasured.
    fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }
}

/// Copy what `data` holds from `offset` onwards into `buf`, and answer how
/// many bytes that was.
///
/// An offset past the end - including one too large for this target's
/// `usize` at all - yields nothing copied, which section 3.1 makes the
/// right answer rather than an error.
fn fill_from_slice(data: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let rest = usize::try_from(offset)
        .ok()
        .and_then(|start| data.get(start..))
        .unwrap_or_default();
    let taken = buf.len().min(rest.len());
    buf[..taken].copy_from_slice(&rest[..taken]);
    taken
}

impl RangeSource for [u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(fill_from_slice(self, offset, buf))
    }
    fn available(&self) -> u64 {
        self.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(<[u8]>::len(self) as u64)
    }
}

impl RangeSource for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(fill_from_slice(self, offset, buf))
    }
    fn available(&self) -> u64 {
        Vec::len(self) as u64
    }
    fn len(&self) -> Option<u64> {
        Some(Vec::len(self) as u64)
    }
}

impl<S: RangeSource + ?Sized> RangeSource for &S {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        (**self).available()
    }
    fn len(&self) -> Option<u64> {
        (**self).len()
    }
}

impl<S: RangeSource + ?Sized> RangeSource for Arc<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        (**self).available()
    }
    fn len(&self) -> Option<u64> {
        (**self).len()
    }
}

impl<S: RangeSource + ?Sized> RangeSource for Box<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        (**self).available()
    }
    fn len(&self) -> Option<u64> {
        (**self).len()
    }
}

/// A file is read by offset on both families of platform, which leaves
/// the descriptor's own cursor where the caller left it.
impl RangeSource for std::fs::File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(self, buf, offset)
        }
    }
    fn available(&self) -> u64 {
        self.metadata().map(|m| m.len()).unwrap_or(0)
    }
    fn len(&self) -> Option<u64> {
        self.metadata().ok().map(|m| m.len())
    }
}

/// A window onto `S` that begins at `base` and calls that offset zero.
///
/// Section 3.1 has this for the case where a caller already knows how far
/// into a file the archive starts - most often because the file is a
/// self-extracting executable and the stub's length is known. Wrapping it
/// here means the engine never learns about the stub and the caller never
/// adjusts an offset.
#[derive(Clone, Debug)]
pub struct Offset<S: RangeSource> {
    /// The source being windowed.
    pub inner: S,
    /// The offset in `inner` that this window calls zero.
    pub base: u64,
}

impl<S: RangeSource> RangeSource for Offset<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(at) = self.base.checked_add(offset) else {
            // An offset that overflows the address space is past any real
            // end, and section 3.1 makes past-the-end `Ok(0)`.
            return Ok(0);
        };
        self.inner.read_at(at, buf)
    }
    fn available(&self) -> u64 {
        self.inner.available().saturating_sub(self.base)
    }
    fn len(&self) -> Option<u64> {
        self.inner.len().map(|n| n.saturating_sub(self.base))
    }
}

/// Where the next volume of a set comes from.
///
/// The engine's demands here are deliberately easy to satisfy. It asks in
/// set order, never goes back, and asks for each volume exactly once, and
/// it does not ask until it actually needs the thing - so an
/// implementation whose volumes turn up in some other order has nothing
/// to arrange and need only wait inside `volume` for the one asked for.
/// It also never wants a volume PARSED: handing over the bytes is the
/// whole of the job, and the engine reads the headers itself.
///
/// Implemented already for a `Vec` or a slice of `Arc<dyn RangeSource>`,
/// for a slice of open [`Archive`] values - which saves re-reading
/// headers that are already parsed - and for `&mut F` where `F` is
/// `FnMut(u32) -> Result<Option<Arc<dyn RangeSource>>>`. That last one is
/// on `&mut F` rather than on `F` because a blanket implementation over
/// `F` would, under the coherence rules, collide with the one for `Vec`.
pub trait Volumes: Send {
    /// Hand over volume `index`, counting from zero in set order.
    ///
    /// Waiting until it exists is allowed. `Ok(None)` says the set has no
    /// such volume, which is how the engine learns where the set ends.
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>>;
}

impl Volumes for Vec<Arc<dyn RangeSource>> {
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>> {
        Ok(self.get(index as usize).cloned())
    }
}

impl Volumes for &[Arc<dyn RangeSource>] {
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>> {
        Ok(self.get(index as usize).cloned())
    }
}

impl Volumes for &[Archive] {
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>> {
        Ok(self.get(index as usize).map(|a| a.source().clone()))
    }
}

impl<F> Volumes for &mut F
where
    F: FnMut(u32) -> Result<Option<Arc<dyn RangeSource>>> + Send,
{
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>> {
        (**self)(index)
    }
}
