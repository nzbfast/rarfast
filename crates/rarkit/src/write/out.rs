//! Where a writer's bytes go (spec G section 2, the `Out` trait).
//!
//! One implementation serves a single archive and a volume set alike: a
//! volume is opened, filled, and closed, and the engine above never knows
//! which it is writing.
//!
//! **Back-patching, with a seek and without one.** A field the writer
//! cannot fill until the member's bytes have passed - the checksum of a
//! payload whose `crc32` the caller did not state - is written as a
//! placeholder of the right width and corrected afterwards. The output of
//! `finish_into` is a `Write` and cannot seek, so the bytes from the
//! placeholder onwards are HELD until the correction lands, and
//! `WriteReport::held_volume_bytes` reports the most that were held at
//! once. A caller who does not want that either states the CRC32 it
//! already has, or hands `finish_seek` an output that CAN seek, and then
//! the correction goes back over the placeholder and nothing is ever
//! held.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::error::Error;
use crate::Result;

// How many times the recovery copy has had to GROW on this thread, which
// is the figure `keep_a_copy`'s reserve exists to hold at zero. This
// crate's own tests only; nothing in a shipped build carries it.
#[cfg(test)]
thread_local! {
    static TEE_GREW: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Starts the count in [`tee_grew`] again from zero.
#[cfg(test)]
pub(crate) fn forget_tee_growth() {
    TEE_GREW.with(|count| count.set(0));
}

/// How many times a recovery copy has grown on this thread since
/// [`forget_tee_growth`].
#[cfg(test)]
pub(crate) fn tee_grew() -> usize {
    TEE_GREW.with(std::cell::Cell::get)
}

/// Notes that the recovery copy is about to be reallocated.
fn note_tee_growth(_tee: &[u8]) {
    #[cfg(test)]
    TEE_GREW.with(|count| count.set(count.get() + 1));
}

/// Opens each volume of the output in turn.
pub(crate) trait VolumeSource {
    /// One volume's writer.
    type W: Write;

    /// The writer for volume `index`, zero based.
    fn open(&mut self, index: u32) -> Result<Self::W>;

    /// The finished volume `index`, handed back in order.
    fn close(&mut self, index: u32, writer: Self::W) -> Result<()>;

    /// Whether a correction can be written back over the bytes it
    /// replaces, rather than held until it is known.
    fn can_patch(&self) -> bool {
        false
    }

    /// Writes `bytes` over the volume's bytes at `at`, counted from the
    /// volume's first, and leaves the writer positioned at the end again.
    /// Called only when [`VolumeSource::can_patch`] answers `true`.
    fn patch(&mut self, writer: &mut Self::W, at: u64, bytes: &[u8]) -> Result<()> {
        let _ = (writer, at, bytes);
        unreachable!("a patch on an output that cannot seek")
    }

    /// Whether the volume's own bytes can be read back while it is open,
    /// which lets an inline recovery record be computed from the volume
    /// instead of from a copy of it (spec G 3.11, `Out::keep_a_copy`).
    fn can_read_back(&self) -> bool {
        false
    }

    /// Fills `buf` with the volume's bytes at `at`, counted from the
    /// volume's first, and leaves the writer positioned at the end again.
    /// Called only when [`VolumeSource::can_read_back`] answers `true`,
    /// and only over bytes already written.
    fn read_back(&mut self, writer: &mut Self::W, at: u64, buf: &mut [u8]) -> Result<()> {
        let _ = (writer, at, buf);
        unreachable!("a read back from an output that cannot")
    }
}

/// The sink of a run, volume by volume.
pub(crate) struct Out<V: VolumeSource> {
    volumes: V,
    current: Option<V::W>,
    /// Bytes written to the volume now open.
    position: u64,
    /// Bytes written over every volume.
    total: u64,
    /// Volumes opened so far.
    opened: u32,
    /// Bytes held back because a placeholder is not yet corrected, and the
    /// position the first of them sits at.
    hold: Vec<u8>,
    hold_start: Option<u64>,
    /// The most bytes held at once, over the whole run.
    held_peak: u64,
    /// A copy of the volume's bytes as they will FINALLY stand, kept only
    /// when an inline recovery record has to be computed over them
    /// (spec G 3.11). A correction rewrites it too, so what the record
    /// covers is what the volume holds.
    tee: Option<Vec<u8>>,
}

impl<V: VolumeSource> Out<V> {
    /// A sink with no volume open yet.
    pub(crate) fn new(volumes: V) -> Out<V> {
        Out {
            volumes,
            current: None,
            position: 0,
            total: 0,
            opened: 0,
            hold: Vec::new(),
            hold_start: None,
            held_peak: 0,
            tee: None,
        }
    }

    /// Keeps a copy of each volume's bytes, for the recovery record.
    ///
    /// `reserve` is an UPPER BOUND on one volume's bytes, and the copy is
    /// allocated at it once rather than grown into. That is not a
    /// micro-optimisation, it is the whole of the finding: on
    /// macOS a heap buffer REALLOCATED while it is larger than about four
    /// megabytes leaves its whole dirty length resident for the life of
    /// the process, one realloc being enough and the length touched being
    /// the amount retained. A create leg run for 25 rounds in one process
    /// therefore climbed to 1.7 GiB on a 64 MiB archive, 67 MiB a round,
    /// and would not have stopped. The same bytes asked for at their
    /// final size in one call are reused round after round and the figure
    /// is flat, which is what this does.
    ///
    /// An over-reserve costs ADDRESS SPACE and not memory: the pages a
    /// volume never writes are never touched and never resident. So the
    /// bound may be generous and the only thing that must not happen is
    /// for it to be short.
    pub(crate) fn keep_a_copy(&mut self, reserve: usize) {
        let mut tee = Vec::new();
        // `reserve_exact` and not `reserve`: an amortised reserve rounds
        // up to its own growth curve, and the bound is already an
        // over-estimate that does not need doubling.
        tee.reserve_exact(reserve);
        self.tee = Some(tee);
    }

    /// Whether a copy of each volume is being kept for the recovery record.
    pub(crate) fn keeping_a_copy(&self) -> bool {
        self.tee.is_some()
    }

    /// The volume's bytes so far, when a copy is being kept.
    pub(crate) fn kept(&self) -> &[u8] {
        self.tee.as_deref().unwrap_or(&[])
    }

    /// Opens the next volume. The previous one must already be finished.
    pub(crate) fn start_volume(&mut self) -> Result<()> {
        debug_assert!(self.hold_start.is_none(), "a patch crossed a volume");
        let writer = self.volumes.open(self.opened)?;
        self.current = Some(writer);
        self.opened += 1;
        self.position = 0;
        Ok(())
    }

    /// Bytes written to the volume now open.
    pub(crate) fn position(&self) -> u64 {
        self.position
    }

    /// Bytes written over every volume.
    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    /// Volumes opened so far.
    pub(crate) fn volumes(&self) -> u32 {
        self.opened
    }

    /// The most bytes held at once for a correction.
    pub(crate) fn held_peak(&self) -> u64 {
        self.held_peak
    }

    /// Whether a correction goes back over its placeholder rather than
    /// holding the bytes after it.
    pub(crate) fn can_patch(&self) -> bool {
        self.volumes.can_patch()
    }

    /// Whether the open volume can be read back and written over, which
    /// is what an inline recovery record needs to be computed WITHOUT a
    /// copy of the volume (`rr5::encode_in_place`). Both, because the
    /// record is laid down first and filled in where it lies.
    pub(crate) fn can_read_back(&self) -> bool {
        self.volumes.can_patch() && self.volumes.can_read_back()
    }

    /// Fills `buf` with the open volume's bytes at `at`. Only when
    /// [`Out::can_read_back`], so nothing is ever held for a correction
    /// and every byte written is already where it will stay.
    pub(crate) fn read_back(&mut self, at: u64, buf: &mut [u8]) -> Result<()> {
        debug_assert!(self.can_read_back() && self.hold_start.is_none());
        let writer = self
            .current
            .as_mut()
            .expect("a byte was read back before a volume was opened");
        writer.flush().map_err(Error::from)?;
        self.volumes.read_back(writer, at, buf)
    }

    /// Writes `bytes` over the open volume's own bytes at `at`, which
    /// must already have been written. Only when [`Out::can_read_back`].
    pub(crate) fn overwrite(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        debug_assert!(self.can_read_back() && self.tee.is_none());
        debug_assert!(at + bytes.len() as u64 <= self.position);
        let writer = self
            .current
            .as_mut()
            .expect("a byte was written before a volume was opened");
        self.volumes.patch(writer, at, bytes)
    }

    /// Writes `bytes`, holding them when a correction is outstanding.
    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.hold_start.is_some() {
            self.hold.extend_from_slice(bytes);
            self.held_peak = self.held_peak.max(self.hold.len() as u64);
        } else {
            let writer = self
                .current
                .as_mut()
                .expect("a byte was written before a volume was opened");
            writer.write_all(bytes).map_err(Error::from)?;
        }
        if let Some(tee) = self.tee.as_mut() {
            if tee.len() + bytes.len() > tee.capacity() {
                note_tee_growth(tee);
            }
            tee.extend_from_slice(bytes);
        }
        self.position += bytes.len() as u64;
        self.total += bytes.len() as u64;
        Ok(())
    }

    /// Announces that the bytes from here on must be held until
    /// [`Out::correct`] lands.
    pub(crate) fn begin_hold(&mut self) {
        if self.volumes.can_patch() {
            // Nothing is held: the correction seeks back to the
            // placeholder and overwrites it where it already sits.
            return;
        }
        debug_assert!(self.hold_start.is_none(), "two holds at once");
        self.hold_start = Some(self.position);
    }

    /// Replaces the bytes at `at` with `bytes`, and releases the hold.
    pub(crate) fn correct(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        if let Some(tee) = self.tee.as_mut() {
            let at = at as usize;
            tee[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let Some(start) = self.hold_start.take() else {
            // The seekable path: back over the placeholder, and back to
            // the end. Nothing was held, so there is nothing to release.
            debug_assert!(
                self.volumes.can_patch(),
                "a correction with no hold outstanding"
            );
            let writer = self
                .current
                .as_mut()
                .expect("a byte was written before a volume was opened");
            return self.volumes.patch(writer, at, bytes);
        };
        let offset = (at - start) as usize;
        self.hold[offset..offset + bytes.len()].copy_from_slice(bytes);
        let held = std::mem::take(&mut self.hold);
        let writer = self
            .current
            .as_mut()
            .expect("a byte was written before a volume was opened");
        writer.write_all(&held).map_err(Error::from)?;
        self.hold = held;
        self.hold.clear();
        Ok(())
    }

    /// Finishes the open volume and hands it back to the provider.
    pub(crate) fn finish_volume(&mut self) -> Result<()> {
        if let Some(mut writer) = self.current.take() {
            writer.flush().map_err(Error::from)?;
            self.volumes.close(self.opened - 1, writer)?;
            if let Some(tee) = self.tee.as_mut() {
                tee.clear();
            }
        }
        Ok(())
    }
}

/// The record's in-place encode reads and writes the open volume through
/// the sink, never around it.
impl<V: VolumeSource> crate::recovery::rr5::InPlace for Out<V> {
    fn read(&mut self, at: u64, buf: &mut [u8]) -> Result<()> {
        self.read_back(at, buf)
    }

    fn write(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        self.overwrite(at, bytes)
    }
}

/// The single-archive case: one volume, from the caller's own writer.
pub(crate) struct OneVolume<W: Write>(pub(crate) Option<W>);

impl<W: Write> VolumeSource for OneVolume<W> {
    type W = W;

    fn open(&mut self, index: u32) -> Result<W> {
        debug_assert_eq!(index, 0, "a single archive asked for a second volume");
        self.0
            .take()
            .ok_or_else(|| crate::write::options::refuse("a second volume from a single output"))
    }

    fn close(&mut self, _index: u32, _writer: W) -> Result<()> {
        Ok(())
    }
}

/// The single-archive case over an output that can SEEK: one volume,
/// patched in place. What this buys is spec G 7.2's stored row and
/// one pass instead of two at once - no held bytes, and no second
/// read of a payload whose CRC32 the caller did not state, because the
/// header can carry a placeholder and be corrected where it lies.
pub(crate) struct OneSeekable<W: Write + Seek> {
    pub(crate) writer: Option<W>,
    /// Where the archive starts in `writer`, which is wherever the caller
    /// had it positioned: an archive may be appended to something else.
    base: u64,
}

impl<W: Write + Seek> OneSeekable<W> {
    /// A source over `writer`, starting wherever it is positioned now.
    pub(crate) fn new(mut writer: W) -> Result<OneSeekable<W>> {
        let base = writer.stream_position().map_err(Error::from)?;
        Ok(OneSeekable {
            writer: Some(writer),
            base,
        })
    }
}

impl<W: Write + Seek> VolumeSource for OneSeekable<W> {
    type W = W;

    fn open(&mut self, index: u32) -> Result<W> {
        debug_assert_eq!(index, 0, "a single archive asked for a second volume");
        self.writer
            .take()
            .ok_or_else(|| crate::write::options::refuse("a second volume from a single output"))
    }

    fn close(&mut self, _index: u32, _writer: W) -> Result<()> {
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, writer: &mut W, at: u64, bytes: &[u8]) -> Result<()> {
        let end = writer.stream_position().map_err(Error::from)?;
        writer
            .seek(SeekFrom::Start(self.base + at))
            .map_err(Error::from)?;
        writer.write_all(bytes).map_err(Error::from)?;
        writer.seek(SeekFrom::Start(end)).map_err(Error::from)?;
        Ok(())
    }
}

/// The single-archive case over an output that can SEEK and be READ
/// BACK: [`OneSeekable`], and an inline recovery record computed from the
/// archive where it lies rather than from a copy of it.
pub(crate) struct OneReadable<W: Read + Write + Seek>(pub(crate) OneSeekable<W>);

impl<W: Read + Write + Seek> VolumeSource for OneReadable<W> {
    type W = W;

    fn open(&mut self, index: u32) -> Result<W> {
        self.0.open(index)
    }

    fn close(&mut self, index: u32, writer: W) -> Result<()> {
        self.0.close(index, writer)
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, writer: &mut W, at: u64, bytes: &[u8]) -> Result<()> {
        self.0.patch(writer, at, bytes)
    }

    fn can_read_back(&self) -> bool {
        true
    }

    fn read_back(&mut self, writer: &mut W, at: u64, buf: &mut [u8]) -> Result<()> {
        let end = writer.stream_position().map_err(Error::from)?;
        writer
            .seek(SeekFrom::Start(self.0.base + at))
            .map_err(Error::from)?;
        writer.read_exact(buf).map_err(Error::from)?;
        writer.seek(SeekFrom::Start(end)).map_err(Error::from)?;
        Ok(())
    }
}

/// A volume set, from the caller's provider.
pub(crate) struct ManyVolumes<'o, O: crate::write::VolumeOut>(pub(crate) &'o mut O);

impl<O: crate::write::VolumeOut> VolumeSource for ManyVolumes<'_, O> {
    type W = O::W;

    fn open(&mut self, index: u32) -> Result<O::W> {
        self.0.volume(index)
    }

    fn close(&mut self, index: u32, writer: O::W) -> Result<()> {
        self.0.finished(index, writer)
    }

    fn can_patch(&self) -> bool {
        self.0.can_patch()
    }

    fn patch(&mut self, writer: &mut O::W, at: u64, bytes: &[u8]) -> Result<()> {
        self.0.patch(writer, at, bytes)
    }

    fn can_read_back(&self) -> bool {
        self.0.can_read_back()
    }

    fn read_back(&mut self, writer: &mut O::W, at: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read_back(writer, at, buf)
    }
}
