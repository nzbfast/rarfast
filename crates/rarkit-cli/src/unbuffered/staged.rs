//! An extracted member's output past the cache: whole blocks staged and
//! written by a ring of jobs, and the fall back to a plain file.

use super::*;

/// One staged write: a whole number of sectors.
pub(super) const BLOCK: usize = 4 << 20;

/// Full blocks an output keeps in flight behind the one being filled, as
/// shipped ([`depth_or`]): 0, the synchronous write, everywhere but Windows.
///
/// **Linux, measured**: on a Zen 4 rental (two KIOXIA NVMe, ext4, x to the
/// second drive, cold K=5) the 12 GiB member reached the drive's ceiling with
/// one synchronous write, 3,359 MiB/s, and every depth from 1 to 8 was level
/// on disk (0.998x to 1.001x the parent, single and `-v1g`) while costing
/// 0.2 s more CPU, and on the stored many-member set 28 to 184 MiB more peak memory
/// for the same wall.
#[cfg(not(windows))]
pub(super) const DEPTH: usize = 0;

/// **Windows: 1.** On a Windows desktop (i5-10600KF, Windows 11, a Corsair MP400
/// QLC NVMe, source and output on that one drive, warm, on disk with
/// `FlushFileBuffers` timed; INDICATIVE, the box is not qualified) the
/// stored 12 GiB member took 8.58 s with the synchronous write, where the
/// engine's thread reads, checks and writes each slab in turn, and 4.89 s
/// with one block in flight behind it: 1.74x (K=3, the shipped layout), and
/// 1.80x at K=5 on an earlier build (8.76 against 4.87), UnRAR.exe 7.23 at
/// 7.5 s. Depth 2 and 4 were level with 1 (4.70 to 4.91 s) and depth 8
/// slower (5.31), so the smallest depth that holds the win ships: one block,
/// 4 MiB an output more.
#[cfg(windows)]
pub(super) const DEPTH: usize = 1;

/// The depth of an ARCHIVE's output ([`Output`], for `a`): 0 on every
/// target, the synchronous write before this change. Its Windows rows were
/// not sat and no test runs on Windows, so an archive writer's output form
/// does not change there on the extract rows' evidence; the staging's
/// corrections and read-backs are covered at depths 0 to 3 by this file's
/// tests, for the day a create row asks for it.
pub(super) const OUTPUT_DEPTH: usize = 0;

/// The sector every alignment is taken to: 4 KiB covers the 512 byte and
/// the 4 KiB sectors NVMe and SATA drives present.
pub(super) const SECTOR: usize = 4096;

/// How a member of `declared` bytes is written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Form {
    /// Through the OS cache, as every member below [`LEAST`] is.
    Cached,
    /// Past the cache, through this module.
    Direct,
    /// Through the cache, with writeback started behind the cursor
    /// (`writeback`, Linux; the middle form). Elsewhere this reads
    /// as [`Form::Cached`].
    Behind,
}

/// The form a member of `declared` bytes takes here.
pub(crate) fn form(declared: u64) -> Form {
    if declared < LEAST {
        return Form::Cached;
    }
    match forced() {
        Forced::Off => Form::Cached,
        Forced::Behind => Form::Behind,
        // macOS's `F_NOCACHE`, a count arm only.
        Forced::Nocache => Form::Direct,
        _ if FLAG != 0 => Form::Direct,
        _ => Form::Cached,
    }
}

/// The block the engine's bytes are staged in, and how far the unbuffered
/// handle has written.
///
/// **OVERLAPPED.**
/// At a [`depth_or`] of 0 each full block is written on the engine's own thread
/// before the next copy starts, so exactly one direct write is in flight and
/// copy and write take turns: on a Windows desktop's QLC drive (Windows 11) that held
/// the stored 12 GiB member to about 1.52 GB/s against the drive's 2.53, a loss
/// to UnRAR.exe. At a depth of `n` the output has ONE WRITER THREAD and
/// `n + 1` blocks: the engine fills one while up to `n` full ones wait for or
/// are in the writer, which writes them in order, each at its own offset, so
/// the copy waits on the device only when every block is taken. One writer and
/// not several: ext4 serialises direct writes that allocate on the inode's
/// lock and Windows serialises every call on a synchronous handle, so two
/// writers on one file would queue behind each other; the drive's own queue
/// depth comes from the several outputs a pool writes at once.
///
/// At a depth above 0 a piece already on a sector boundary is COPIED into a
/// block like any other (the writer outlives the engine's borrow of it), where
/// at depth 0 it is written straight from its buffer.
pub(crate) struct Staged {
    pub(super) store: Vec<u8>,
    pub(super) at: usize,
    pub(super) fill: usize,
    /// Where the block being filled starts in the file: every byte before it
    /// has been handed to the device, and has LANDED once [`Staged::settle`]
    /// has run (at depth 0, at once).
    pub(super) done: u64,
    pub(super) path: PathBuf,
    /// Whether a fall back reopens the file for reading too, which an
    /// archive's output needs ([`Output`] reads a volume back) and a
    /// member's does not ask for.
    pub(super) readable: bool,
    /// The write-rate gate (judged per DEVICE).
    pub(super) gate: Gate,
    /// Why the output left direct writing, once it has.
    pub(super) fell: Option<Fell>,
    /// The device the output is on, where it can be named.
    pub(super) device: Option<u64>,
    /// For a MEMBER of an extract, how its bytes are produced, which the
    /// rule on facts asks ([`slow_for`]); `None` for an archive's output,
    /// which keeps the line's forms under either rule.
    pub(super) member: Option<Member>,
    /// The writer thread and its blocks, at a depth above 0.
    pub(super) ring: Option<Ring>,
    /// A direct write of this output found no room ([`no_room`]): it never
    /// falls back after that, whatever asks (a verdict that shuts the gate
    /// as the failed member is dropped, say).
    pub(super) full: bool,
}

/// Why a [`Staged`] output left direct writing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fell {
    /// The gate found the device slow, now or earlier in the process.
    Rate,
    /// A direct write failed.
    Failed,
}

/// One full block handed to the writer thread.
pub(super) struct Job {
    pub(super) buf: Vec<u8>,
    pub(super) at: usize,
    pub(super) len: usize,
    pub(super) offset: u64,
    /// Whether the write is timed for the device's probe.
    pub(super) timed: bool,
}

/// A job back from the writer: its block, and whether the write landed.
pub(super) struct Landed {
    pub(super) job: Job,
    pub(super) ok: bool,
    /// The write's error where it was refused for want of space
    /// ([`no_room`]).
    pub(super) full: Option<std::io::Error>,
}

/// An output's writer thread and the blocks it owns.
pub(super) struct Ring {
    /// `None` once closed, which ends the writer.
    pub(super) jobs: Option<std::sync::mpsc::Sender<Job>>,
    pub(super) back: std::sync::mpsc::Receiver<Landed>,
    pub(super) writer: Option<std::thread::JoinHandle<()>>,
    /// Blocks free to fill.
    pub(super) spare: Vec<Vec<u8>>,
    /// Jobs handed over and not yet back.
    pub(super) in_flight: usize,
    /// Blocks whose write FAILED, kept for the fall back to write cached.
    pub(super) failed: Vec<Job>,
    /// The first write refused for want of space ([`no_room`]): the output
    /// then never falls back.
    pub(super) full: Option<std::io::Error>,
}

/// Whether a failed write says its volume has NO ROOM: the volume is full,
/// or the user's quota on it is.
///
/// **Such a write is the output's error and never its fall back** (4 Oct
/// 2026). Every other failed direct write sends the output to the cache,
/// byte exact; this one would be refused there too, and asking costs: a
/// cached write takes its pages before the file system finds it has no
/// block for them, and under a cgroup memory cap with nothing left to
/// reclaim that allocation gets the process killed where it owed a write
/// error. Read on a write's ERROR only, so a write that lands pays nothing
/// for it.
pub(super) fn no_room(failed: &std::io::Error) -> bool {
    matches!(
        failed.kind(),
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
    )
}

/// `failed` again, for a second caller: the system's own code where it has
/// one, so the message is the system's.
pub(super) fn again(failed: &std::io::Error) -> std::io::Error {
    match failed.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => failed.kind().into(),
    }
}

/// A fresh block: its store and where its sector aligned part starts.
pub(super) fn block() -> (Vec<u8>, usize) {
    let store = vec![0u8; BLOCK + SECTOR];
    let at = store.as_ptr().align_offset(SECTOR);
    (store, at)
}

/// Writes all of `bytes` at `offset` through `file`, leaving its cursor
/// wherever the target's call leaves it: every direct write names its
/// offset, so no two writers of one file lean on a shared cursor.
pub(super) fn write_at(file: &File, bytes: &[u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(bytes, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut bytes, mut offset) = (bytes, offset);
        while !bytes.is_empty() {
            let n = file.seek_write(bytes, offset)?;
            if n == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[n..];
            offset += n as u64;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
}

/// The writer thread's loop: each job written at its offset, in the order
/// given, timed for `probe` where the job asks, and handed back.
pub(super) fn write_jobs(
    file: File,
    jobs: std::sync::mpsc::Receiver<Job>,
    back: std::sync::mpsc::Sender<Landed>,
    probe: Option<std::sync::Arc<Probe>>,
) {
    for job in jobs {
        let wrote = if forced() == Forced::Write {
            Err(std::io::Error::other("forced unbuffered write failure"))
        } else if forced() == Forced::Full {
            Err(std::io::ErrorKind::StorageFull.into())
        } else {
            let probe = probe.as_ref().filter(|_| job.timed);
            if let Some(probe) = probe {
                probe.start();
            }
            let wrote = write_at(&file, &job.buf[job.at..job.at + job.len], job.offset);
            if let Some(probe) = probe {
                probe.end(if wrote.is_ok() { job.len as u64 } else { 0 });
            }
            wrote
        };
        let landed = Landed {
            job,
            ok: wrote.is_ok(),
            full: wrote.err().filter(no_room),
        };
        if back.send(landed).is_err() {
            break;
        }
    }
}

impl Staged {
    /// Staging for the member at `path`, of kind `member`, whose file was
    /// just opened unbuffered as `file` and holds no byte yet. Its device is looked up in the gate's memo: remembered slow, the
    /// first [`Staged::put`] falls back before any direct write (unless the
    /// rule on facts keeps this member direct there, [`slow_for`]);
    /// remembered fast, nothing is timed; otherwise the output joins the
    /// device's probe, shared with every other output writing to that
    /// device.
    pub(crate) fn new(path: &Path, file: &File, member: Member) -> Staged {
        Staged::at_depth(path, file, depth_or(DEPTH), Some(member))
    }

    /// [`Staged::new`] with `depth` full blocks in flight behind the one
    /// being filled; `member` is `None` for an archive's output.
    pub(super) fn at_depth(
        path: &Path,
        file: &File,
        depth: usize,
        member: Option<Member>,
    ) -> Staged {
        let (store, at) = block();
        let device = device_of(path, file);
        // An ARCHIVE's output under a cgroup memory cap is not timed and
        // never leaves direct writing for the device's rate ([`capped`]).
        let gate = if forced() == Forced::On || (member.is_none() && capped()) {
            Gate::Open
        } else {
            let probe = probe_for(device);
            match probe.verdict() {
                Some(Verdict::Fast) => Gate::Open,
                Some(Verdict::Slow) => slow_gate(device, member, path),
                None if shared_probe() => Gate::Probing(probe),
                // Each output times its own writes, and the first verdict
                // is the device's.
                None => Gate::Probing(std::sync::Arc::new(Probe {
                    state: std::sync::Mutex::new(Probed::default()),
                    device: Some(probe),
                })),
            }
        };
        let mut staged = Staged {
            store,
            at,
            fill: 0,
            done: 0,
            path: path.to_path_buf(),
            readable: false,
            gate,
            fell: None,
            device,
            member,
            ring: None,
            full: false,
        };
        if depth > 0 && !matches!(staged.gate, Gate::Shut) {
            staged.ring = staged.start_ring(file, depth);
        }
        staged
    }

    /// The writer thread over a second handle to `file`, and `depth` spare
    /// blocks; `None` (depth 0's synchronous writes) where the handle cannot
    /// be duplicated or the thread cannot start.
    pub(super) fn start_ring(&self, file: &File, depth: usize) -> Option<Ring> {
        let own = file.try_clone().ok()?;
        let probe = match &self.gate {
            Gate::Probing(probe) => Some(probe.clone()),
            _ => None,
        };
        let (jobs, take) = std::sync::mpsc::channel();
        let (give, back) = std::sync::mpsc::channel();
        let writer = std::thread::Builder::new()
            .name("rarfast-direct".into())
            .spawn(move || write_jobs(own, take, give, probe))
            .ok()?;
        Some(Ring {
            jobs: Some(jobs),
            back,
            writer: Some(writer),
            spare: (0..depth).map(|_| block().0).collect(),
            in_flight: 0,
            failed: Vec::new(),
            full: None,
        })
    }

    /// Bytes handed to the device so far: every byte before this offset is
    /// written past the cache (once settled), or by a cached handle after a
    /// fall back.
    #[cfg(test)]
    pub(crate) fn done(&self) -> u64 {
        self.done
    }

    /// Why the output left direct writing, once [`Staged::put`] has said it
    /// did.
    pub(crate) fn fell(&self) -> Option<Fell> {
        self.fell
    }

    /// The form the rest of this output takes where the gate found its
    /// device slow ([`slow_for`]).
    pub(crate) fn slow_form(&self) -> Form {
        slow_for(self.device, self.member, &self.path)
    }

    /// Stage `buf`, writing each whole block through `file` (or handing it
    /// to the writer thread), or at depth 0 write it straight from `buf`
    /// where it is already aligned. `Ok(false)` when the member FELL BACK, a
    /// direct write having failed or the gate having found the device slow
    /// ([`Staged::fell`] says which): `file` is then a cached handle holding
    /// every byte so far, `buf` included, positioned at the end, and the
    /// caller drops this staging. `Err` with the write's own error, and no
    /// fall back, where a direct write found no room ([`no_room`]).
    pub(crate) fn put(&mut self, file: &mut File, mut buf: &[u8]) -> std::io::Result<bool> {
        while !buf.is_empty() {
            // The gate shut, by the device's probe or by the memo: the rest
            // of the output goes cached, from exactly here.
            if matches!(self.gate, Gate::Shut) {
                self.fall_back(file, Fell::Rate)?;
                file.write_all(buf)?;
                return Ok(false);
            }
            // Nothing staged and the piece on a sector boundary: at depth 0
            // its whole sectors go from the engine's own buffer, no copy.
            // The rest of it, under a sector, is staged below on the next
            // turn.
            if self.ring.is_none()
                && self.fill == 0
                && buf.as_ptr().align_offset(SECTOR) == 0
                && buf.len() >= SECTOR
            {
                let whole = buf.len() / SECTOR * SECTOR;
                if let Err(failed) = self.direct(file, &buf[..whole], Forced::Write) {
                    if no_room(&failed) {
                        self.full = true;
                        return Err(failed);
                    }
                    self.fall_back(file, Fell::Failed)?;
                    file.write_all(buf)?;
                    return Ok(false);
                }
                buf = &buf[whole..];
                continue;
            }
            let n = (BLOCK - self.fill).min(buf.len());
            let from = self.at + self.fill;
            self.store[from..from + n].copy_from_slice(&buf[..n]);
            self.fill += n;
            buf = &buf[n..];
            if self.fill == BLOCK {
                if let Err(failed) = self.submit(file) {
                    if no_room(&failed) {
                        self.full = true;
                        return Err(failed);
                    }
                    self.fall_back(file, Fell::Failed)?;
                    file.write_all(buf)?;
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The full block goes to the device: written here at depth 0, handed to
    /// the writer otherwise, with a free block (waiting for one if every
    /// block is taken) put in its place. `Err` where a direct write is known
    /// to have failed; the block is then kept for the fall back.
    pub(super) fn submit(&mut self, file: &mut File) -> std::io::Result<()> {
        let timed = matches!(self.gate, Gate::Probing(_));
        let Some(ring) = self.ring.as_mut() else {
            let (at, len) = (self.at, BLOCK);
            self.direct_staged(file, at, len, Forced::Write)?;
            self.fill = 0;
            return Ok(());
        };
        // A block to fill next: a spare, or the first to come back.
        let next = loop {
            ring.reap(false);
            if let Some(full) = &ring.full {
                return Err(again(full));
            }
            if !ring.failed.is_empty() {
                return Err(std::io::Error::other("a direct write failed"));
            }
            if let Some(next) = ring.spare.pop() {
                break next;
            }
            if ring.in_flight == 0 || !ring.reap(true) {
                return Err(std::io::Error::other("the direct writer stopped"));
            }
            if let Some(full) = &ring.full {
                return Err(again(full));
            }
        };
        let full = std::mem::replace(&mut self.store, next);
        let job = Job {
            buf: full,
            at: self.at,
            len: BLOCK,
            offset: self.done,
            timed,
        };
        self.at = self.store.as_ptr().align_offset(SECTOR);
        let refused = match ring.jobs.as_ref() {
            Some(jobs) => jobs.send(job).err().map(|refused| refused.0),
            None => Some(job),
        };
        if let Some(job) = refused {
            // The writer is gone and the job came back: its block is the
            // one being filled again, whole, for the fall back to write.
            // Dropped, the fall back wrote the spare put in its place, an
            // earlier block's bytes.
            let spare = std::mem::replace(&mut self.store, job.buf);
            ring.spare.push(spare);
            self.at = job.at;
            return Err(std::io::Error::other("the direct writer stopped"));
        }
        ring.in_flight += 1;
        self.done += BLOCK as u64;
        self.fill = 0;
        self.look();
        Ok(())
    }

    /// Waits for every block in flight to land. `Ok(false)` when one FAILED
    /// or the gate has shut meanwhile, and the output then falls back here
    /// (`file` becomes the cached handle, positioned at the end). Every byte
    /// before [`Staged::done`] is on disk after an `Ok(true)`. `Err`, and no
    /// fall back, where a block found no room ([`no_room`]).
    pub(crate) fn settle(&mut self, file: &mut File) -> std::io::Result<bool> {
        if let Some(ring) = self.ring.as_mut() {
            while ring.in_flight > 0 && ring.reap(true) {}
            if let Some(full) = &ring.full {
                return Err(again(full));
            }
            if !ring.failed.is_empty() || ring.in_flight > 0 {
                self.fall_back(file, Fell::Failed)?;
                return Ok(false);
            }
        }
        self.look();
        if matches!(self.gate, Gate::Shut) {
            self.fall_back(file, Fell::Rate)?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Write what is staged, at close: every block in flight landed, then the
    /// last one padded to a whole sector through the unbuffered handle, or
    /// cached after a fall back. The caller then cuts the file back to the
    /// bytes that arrived. A tail that finds no room is this call's error
    /// ([`no_room`]).
    pub(crate) fn finish(&mut self, file: &mut File) -> std::io::Result<()> {
        if !self.settle(file)? {
            return Ok(());
        }
        self.stop();
        if self.fill == 0 {
            return Ok(());
        }
        let at = self.at;
        let padded = self.fill.div_ceil(SECTOR) * SECTOR;
        self.store[at + self.fill..at + padded].fill(0);
        if let Err(failed) = self.direct_staged(file, at, padded, Forced::Tail) {
            if no_room(&failed) {
                self.full = true;
                return Err(failed);
            }
            self.fall_back(file, Fell::Failed)?;
        }
        self.fill = 0;
        Ok(())
    }

    /// One direct write of `bytes` (whole sectors) through `file` at
    /// [`Staged::done`], counted there when it lands; failed where a test
    /// forces `failure`.
    pub(super) fn direct(
        &mut self,
        file: &mut File,
        bytes: &[u8],
        failure: Forced,
    ) -> std::io::Result<()> {
        if forced() == failure {
            return Err(std::io::Error::other("forced unbuffered write failure"));
        }
        if forced() == Forced::Full {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        let probe = self.probing();
        if let Some(probe) = &probe {
            probe.start();
        }
        let wrote = write_at(file, bytes, self.done);
        if let Some(probe) = &probe {
            probe.end(if wrote.is_ok() { bytes.len() as u64 } else { 0 });
        }
        wrote?;
        self.done += bytes.len() as u64;
        self.look();
        Ok(())
    }

    /// [`Staged::direct`] of `len` staged bytes from `at`.
    pub(super) fn direct_staged(
        &mut self,
        file: &mut File,
        at: usize,
        len: usize,
        failure: Forced,
    ) -> std::io::Result<()> {
        let store = std::mem::take(&mut self.store);
        let wrote = self.direct(file, &store[at..at + len], failure);
        self.store = store;
        wrote
    }

    /// The device's probe, while this output is timed by it.
    pub(super) fn probing(&self) -> Option<std::sync::Arc<Probe>> {
        match &self.gate {
            Gate::Probing(probe) => Some(probe.clone()),
            _ => None,
        }
    }

    /// Reads the device's verdict, once there is one: the gate opens (fast)
    /// or shuts (slow; the next put falls back), except that a member the
    /// rule on facts keeps direct on a slow device stays ([`slow_gate`]).
    pub(super) fn look(&mut self) {
        let Gate::Probing(probe) = &self.gate else {
            return;
        };
        match probe.verdict() {
            Some(Verdict::Fast) => self.gate = Gate::Open,
            Some(Verdict::Slow) => self.gate = slow_gate(self.device, self.member, &self.path),
            None => {}
        }
    }

    /// Ends the writer thread, every job being back.
    pub(super) fn stop(&mut self) {
        if let Some(mut ring) = self.ring.take() {
            ring.jobs = None;
            while ring.in_flight > 0 && ring.reap(true) {}
            if let Some(writer) = ring.writer.take() {
                let _ = writer.join();
            }
        }
    }

    /// Open the member again CACHED, write there every block whose direct
    /// write failed, position it after what is staged and write that. `file`
    /// becomes that handle. A direct write that failed part way is written
    /// over: nothing it touched is trusted.
    pub(super) fn fall_back(&mut self, file: &mut File, why: Fell) -> std::io::Result<()> {
        if self.full {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        let failed = match self.ring.as_mut() {
            Some(ring) => {
                ring.jobs = None;
                while ring.in_flight > 0 && ring.reap(true) {}
                // A block that found no room is not asked of the cache
                // either, whoever asks for the fall back ([`no_room`]).
                if let Some(full) = &ring.full {
                    return Err(again(full));
                }
                std::mem::take(&mut ring.failed)
            }
            None => Vec::new(),
        };
        self.stop();
        let mut cached = self.reopen(file)?;
        for job in &failed {
            write_at(&cached, &job.buf[job.at..job.at + job.len], job.offset)?;
        }
        cached.seek(SeekFrom::Start(self.done))?;
        cached.write_all(&self.store[self.at..self.at + self.fill])?;
        self.done += self.fill as u64;
        self.fill = 0;
        self.gate = Gate::Shut;
        self.fell.get_or_insert(why);
        *file = cached;
        Ok(())
    }

    /// The output opened again by name, CACHED, for [`Staged::fall_back`];
    /// `held` is the handle its create returned.
    ///
    /// A MEMBER's second open refuses a symbolic link at the final
    /// component, as its create did (`safepath::reopen_output_file`):
    /// between the two a name can be swapped for a link, and the staged
    /// bytes would be written through it. An archive's output follows a
    /// link, as its create does ([`open_direct`]).
    ///
    /// **A file created without its owner's write bit is refused by name**
    /// (found 1 Oct 2026 on an EBS disk, x86-64 Linux: `x` of a tree holding
    /// a 94 MB binary of mode `0444` ended `Write error ... Permission
    /// denied`, exit 5, where the reference extracts it). A member is
    /// created with its stored mode, so the handle the create returned
    /// writes whatever that mode is, and a second open by name is judged by
    /// the mode: `0444`, `0555`, `0400` and `0000` all refuse their own
    /// owner. Then, and only then, the bits the open needs are added
    /// THROUGH `held`, the open is made, and the mode is put back through
    /// `held` at once, whether the open was taken or not. The file is wider
    /// than its stored mode for those three calls, and by the owner's bits
    /// alone. A fall back whose first open is taken costs nothing more than
    /// it did.
    pub(super) fn reopen(&self, held: &File) -> std::io::Result<File> {
        let open = || {
            if self.readable {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&self.path)
            } else {
                crate::safepath::reopen_output_file(&self.path)
            }
        };
        match open() {
            Err(refused) if refused.kind() == std::io::ErrorKind::PermissionDenied => {
                with_owner_access(held, self.readable, open).unwrap_or(Err(refused))
            }
            other => other,
        }
    }
}

/// Runs `open` with the owner's write bit (and read bit, for a `readable`
/// output) added to `held`'s file through the handle itself, and the mode
/// it had put back straight after. `None` where the file already has those
/// bits (the refusal was not the mode's), where its mode cannot be read or
/// widened, and off Unix, where no mode is applied at a create (Windows'
/// read-only attribute is not set by this crate; the day it is, it must go
/// on at the member's close, never at its create, or this reopen meets it).
#[cfg(unix)]
pub(super) fn with_owner_access<T>(
    held: &File,
    readable: bool,
    open: impl FnOnce() -> std::io::Result<T>,
) -> Option<std::io::Result<T>> {
    use std::os::unix::fs::PermissionsExt;
    let had = held.metadata().ok()?.permissions().mode() & 0o7777;
    let need = if readable { 0o600 } else { 0o200 };
    if had & need == need {
        return None;
    }
    held.set_permissions(std::fs::Permissions::from_mode(had | need))
        .ok()?;
    let opened = open();
    let _ = held.set_permissions(std::fs::Permissions::from_mode(had));
    Some(opened)
}

/// See the Unix [`with_owner_access`].
#[cfg(not(unix))]
pub(super) fn with_owner_access<T>(
    _held: &File,
    _readable: bool,
    _open: impl FnOnce() -> std::io::Result<T>,
) -> Option<std::io::Result<T>> {
    None
}

impl Ring {
    /// Takes back the jobs the writer has finished: waiting for one when
    /// `wait`, else only those already back. `false` when waiting found the
    /// writer gone.
    pub(super) fn reap(&mut self, wait: bool) -> bool {
        loop {
            let landed = if wait {
                match self.back.recv() {
                    Ok(landed) => landed,
                    Err(_) => return false,
                }
            } else {
                match self.back.try_recv() {
                    Ok(landed) => landed,
                    Err(_) => return true,
                }
            };
            self.in_flight -= 1;
            if landed.ok {
                self.spare.push(landed.job.buf);
            } else {
                if self.full.is_none() {
                    self.full = landed.full;
                }
                self.failed.push(landed.job);
            }
            if wait {
                return true;
            }
        }
    }
}

impl Drop for Staged {
    /// No write of this output outlives it: the writer is ended and joined.
    fn drop(&mut self) {
        self.stop();
    }
}

/// How many full blocks an output keeps in flight behind the one being
/// filled: `shipped` ([`DEPTH`] for a member, [`OUTPUT_DEPTH`] for an
/// archive's output); in a `reserve-knob` build `RARFAST_DIRECT_DEPTH` where
/// it is set, for both, so one binary times every depth (0 is the
/// synchronous writes before this change); in a test, the depth the test set.
pub(super) fn depth_or(shipped: usize) -> usize {
    #[cfg(test)]
    {
        TEST_DEPTH
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unwrap_or(shipped)
    }
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static SET: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        SET.get_or_init(|| {
            let depth = std::env::var("RARFAST_DIRECT_DEPTH")
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .map(|d| d.min(64));
            eprintln!("rarfast direct depth: {depth:?}");
            depth
        })
        .unwrap_or(shipped)
    }
    #[cfg(all(not(test), not(feature = "reserve-knob")))]
    {
        shipped
    }
}

/// The depth a test runs at, where one sets it (under [`TEST_SERIAL`]).
#[cfg(test)]
pub(crate) static TEST_DEPTH: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);
