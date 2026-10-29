//! Which reading of the password a RAR 3 member's data was keyed under,
//! found before a byte of it reaches the caller (spec B 3.2).
//!
//! A character outside the basic plane enters the RAR 3 key as one unit
//! on the reference programs for Linux and macOS and as two on the ones
//! for Windows, and both are genuine writers. Encrypted HEADERS carry a
//! checksum each, so the walk learns the reading as it reads them
//! (`KeyCache::rar4_either_reading`). A member whose DATA alone is
//! encrypted says nothing until its last byte: its checksum is the only
//! verdict.
//!
//! So the first such member is decoded here ONCE TO NO OUTPUT, from its
//! own byte range of the volume, under the first reading and, when its
//! checksum fails, under the second. The reading that checks is the
//! session's from then on, and the member's real decode, on whichever
//! unit runs it, starts only after: no driver writes a byte under a
//! reading that is then contradicted, and none has to take one back.
//!
//! Only for a password that holds such a character, and only until
//! something has verified. A member that checks under neither reading
//! leaves everything as it was: it is then decoded under the first
//! reading and reported as it always has been, and the next member looks
//! again.
//!
//! WHERE NOTHING IS LOOKED FOR, and the member keeps the reading the
//! session has (the first, until something verifies):
//!
//! - a member SPLIT across volumes: its checksum is on its last fragment
//!   and the walk has not reached that volume;
//! - a member that CONTINUES a solid chain: its decode stands on the
//!   window the members before it left, which a second decode would have
//!   to rebuild.
//!
//! MEMORY. The decode runs on the walking thread with the walk's own
//! decoders and scratch, after the driver has closed every member it had
//! in flight, so it holds what the walk's own decode of this member would
//! and nothing beside it; a RAR 3 stream built for it is given back before
//! the real decode is planned.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::*;
use crate::source::RangeSource;

/// What [`settle`] needs of the member being opened, beside its header.
pub(crate) struct Probe<'a> {
    pub(super) block: &'a crate::read::block::Block,
    pub(super) solid_archive: bool,
    /// The member's decode continues the stream of the member before it.
    pub(super) continues: bool,
    pub(super) decoders: &'a mut Decoders,
}

/// A member's packed bytes, read from its own range of its volume.
struct OwnRange {
    src: Arc<dyn RangeSource>,
    at: u64,
    end: u64,
}

impl PackedRead for OwnRange {
    fn read(&mut self, into: &mut [u8]) -> Result<usize> {
        let want = (self.end - self.at).min(into.len() as u64) as usize;
        if want == 0 {
            return Ok(0);
        }
        let got = self
            .src
            .read_at(self.at, &mut into[..want])
            .map_err(|e| Error::new(ErrorKind::Source(e)))?;
        if got == 0 {
            return Err(Error::new(ErrorKind::Truncated).with_offset(self.at));
        }
        self.at += got as u64;
        Ok(got)
    }
}

/// The tally of a decode that delivers nothing: it only lets a cancelled
/// operation out of a long member.
struct Unheard<'a>(Option<&'a AtomicBool>);

impl Tally for Unheard<'_> {
    fn output(&mut self, _: usize) -> Result<()> {
        match self.0 {
            Some(flag) if flag.load(Ordering::Relaxed) => Err(Error::new(ErrorKind::Cancelled)),
            _ => Ok(()),
        }
    }
}

/// Whether `file` is a member [`settle`] may be asked about: its data is
/// under the AES of this family and the session's reading is still open.
fn due<V: Volumes>(walk: &mut Walk<'_, V>, file: &FileHdr, format: Format) -> bool {
    if file.unpack_version < 29 || matches!(format, Format::Rar5 | Format::Rar13) {
        return false;
    }
    let ctx = walk.ctx();
    match ctx.options.password.as_ref() {
        Some(password) => ctx.keys.rar4_reading_open(password),
        None => false,
    }
}

/// Before an encrypted member is opened: where [`settle`] may run on it,
/// have the driver close every member it has in flight, so that nothing
/// else is decoding, or holding a window, while this one is read twice.
/// Asked BEFORE the member's `open`, because a driver settles between
/// members and not inside one.
#[cold]
pub(super) fn quiesce<V: Volumes, D: Driver>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    file: &FileHdr,
    format: Format,
) -> Result<()> {
    if due(walk, file, format) && !walk.headers_keyed() {
        run.driver.settle()?;
    }
    Ok(())
}

/// Find the session's reading from this member, where it can be found.
///
/// Asked for every AES member of this family; it does nothing unless
/// `KeyCache::rar4_reading_open` says the password has two readings and
/// neither has verified. It raises no error: whatever the decode here
/// meets is the real decode's to meet again and report.
pub(super) fn settle<V: Volumes, D: Driver>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    file: &FileHdr,
    format: Format,
    probe: Option<Probe<'_>>,
) -> Result<()> {
    if !due(walk, file, format) {
        return Ok(());
    }
    let Some(probe) = probe else {
        return Ok(());
    };
    // Headers that are encrypted have each been checked under the
    // session's key already: the reading is the one that opened them.
    if walk.headers_keyed() {
        walk.ctx().keys.rar4_reading_found();
        return Ok(());
    }
    if file.split_before || file.split_after || probe.continues {
        return Ok(());
    }
    let Some(src) = walk.shared_source() else {
        return Ok(());
    };
    if matches!(
        codec_of(file, format, probe.solid_archive),
        Codec::Missing(_)
    ) {
        return Ok(());
    }
    let Probe {
        block,
        solid_archive,
        decoders,
        ..
    } = probe;
    let held_before = decoders.holds_rar3();
    let scratch_idle = run.scratch.live_bytes() == 0;
    let policy = run.policy;
    let version = u8::try_from(file.unpack_version).unwrap_or(u8::MAX);
    let crate::read::reader::ReadCtx {
        options,
        keys: cache,
        ..
    } = walk.ctx();
    let Some(password) = options.password.as_ref() else {
        return Ok(());
    };
    let cancel = options.cancel.as_deref();
    let found = cache.rar4_either_reading(password, |cache| {
        let key = cache.rar4_cipher(password, file.rar4_salt)?;
        let cipher = rar4_family_cipher_on(version, password.as_bytes(), Some(key))?;
        let mut member = Member::<std::io::Sink>::of(
            Some(Out::Verify),
            file,
            format,
            None,
            &mut run.blake,
            blake_workers(&policy, decoders),
        );
        decode(
            OwnRange {
                src: Arc::clone(&src),
                at: block.data.start,
                end: block.data.end,
            },
            &mut member,
            &mut run.blake,
            &mut Unheard(cancel),
            Some(MemberDecryptor::new(cipher)),
            codec_of(file, format, solid_archive),
            decoders,
            &mut run.scratch,
            &policy,
            false,
            None,
        )?;
        match verdict(&member, &mut run.blake, file, false) {
            Some(true) => Ok(()),
            _ => Err(Error::new(ErrorKind::Corrupt(Corruption::Checksum))),
        }
    });
    if found.is_ok() {
        cache.rar4_reading_found();
    }
    // What was built for this decode alone is given back before the real
    // one is planned, on whichever unit that will be.
    if !held_before {
        decoders.release_rar3();
    }
    if scratch_idle {
        let scratch = &mut run.scratch;
        for buffer in [
            &mut scratch.packed,
            &mut scratch.copy,
            &mut scratch.copy_pair,
            &mut scratch.target,
        ] {
            *buffer = Vec::new();
        }
    }
    decoders.recharge_scratch(&run.scratch);
    Ok(())
}

/// Spec B 3.2 from the archives the evidence pass had the reference
/// programs judge: the genuine `r393_pw.rar` (rar 3.93, nine members
/// encrypted under `Secret`, headers clear), its packed bytes deciphered
/// and enciphered again under each reading of U+1F511 `key`, which is how
/// `specs/vectors-K/b3-rar3-kdf-probe.py astral` builds them. The Windows
/// capture records the sha256 of each archive beside its verdict
/// (`vectors-K/windows-06oct/probes/b3-astral.json`, calls 2 and 3), and
/// the archives built here are those, byte for byte.
///
/// Every test states its drivers: the sequential one at the default width
/// and at a width of one, and the pool at a width of two, the narrowest
/// hosted runner's. Memory: a 68 KiB archive, its 9 members and a 4 MiB
/// window; no test needs more than 64 MiB whatever the width.
///
/// Behind `repo-tests`, as every lib test that reads a file of this
/// repository from outside the crate is: a copy of the crate alone builds
/// and runs its lib tests without them.
#[cfg(all(test, feature = "repo-tests"))]
mod tests {
    use std::sync::{Arc, Mutex};

    use sha2::{Digest, Sha256};

    use crate::crypto::{rar4_decrypt_header, rar4_encrypt_header, Astral, Rar4Key};
    use crate::read::{
        Disposition, ExtractReport, MemberInfo, MemberOutcome, ParallelSink, ReadOptions, Session,
        Sink,
    };
    use crate::source::RangeSource;
    use crate::{MemoryPolicy, Password, Result};

    /// The pool width the parallel driver runs at here.
    const POOL: usize = 2;
    /// The password of the probe's arms.
    const KEYED: &str = "\u{1f511}key";

    fn genuine() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/legacy/archives/r393_pw.rar"
        ))
        .unwrap()
    }

    /// The packed range and salt of every encrypted member, read off the
    /// RAR 4 block chain (headers clear).
    fn encrypted_members(archive: &[u8]) -> Vec<(std::ops::Range<usize>, [u8; 8])> {
        let mut found = Vec::new();
        let mut at = 7;
        while at + 7 <= archive.len() {
            let kind = archive[at + 2];
            let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
            let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
            let data = if flags & 0x8000 != 0 || kind == 0x74 || kind == 0x7a {
                u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
            } else {
                0
            };
            if kind == 0x74 && flags & 0x0004 != 0 {
                let salt = archive[at + size - 8..at + size].try_into().unwrap();
                found.push((at + size..at + size + data, salt));
            }
            at += size + data;
            if kind == 0x7b {
                break;
            }
        }
        found
    }

    /// The genuine archive with every member's packed bytes under the key
    /// of `KEYED` in `reading`, and its sha256 as the capture writes it.
    fn rekeyed(reading: Astral) -> Vec<u8> {
        let mut archive = genuine();
        for (range, salt) in encrypted_members(&archive) {
            let old = Rar4Key::derive(b"Secret", Some(salt)).unwrap();
            let new = Rar4Key::derive_reading(KEYED.as_bytes(), Some(salt), reading).unwrap();
            rar4_decrypt_header(&old, &mut archive[range.clone()]).unwrap();
            rar4_encrypt_header(&new, &mut archive[range]).unwrap();
        }
        archive
    }

    fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A source that remembers every read made of it.
    struct Watched {
        bytes: Vec<u8>,
        reads: Mutex<Vec<(u64, usize)>>,
    }

    impl RangeSource for Watched {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let from = (offset as usize).min(self.bytes.len());
            let n = buf.len().min(self.bytes.len() - from);
            buf[..n].copy_from_slice(&self.bytes[from..from + n]);
            self.reads.lock().unwrap().push((offset, n));
            Ok(n)
        }

        fn available(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn len(&self) -> Option<u64> {
            Some(self.bytes.len() as u64)
        }
    }

    impl Watched {
        /// How many times over the bytes of `range` were read.
        fn times_read(&self, range: &std::ops::Range<usize>) -> f64 {
            let inside: usize = self
                .reads
                .lock()
                .unwrap()
                .iter()
                .map(|&(at, n)| {
                    let (from, to) = (at as usize, at as usize + n);
                    to.min(range.end).saturating_sub(from.max(range.start))
                })
                .sum();
            inside as f64 / range.len() as f64
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Closed {
        name: Vec<u8>,
        given: Vec<u8>,
        outcome: MemberOutcome,
    }

    #[derive(Default)]
    struct Keep(Vec<Closed>);

    impl Sink for Keep {
        type Out = Vec<u8>;

        fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
            Ok(if member.is_directory {
                Disposition::Skip
            } else {
                Disposition::Write(Vec::new())
            })
        }

        fn close(
            &mut self,
            member: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> Result<()> {
            self.0.push(Closed {
                name: member.name.to_vec(),
                given: out.unwrap_or_default(),
                outcome: *outcome,
            });
            Ok(())
        }
    }

    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct KeepParallel(Mutex<Vec<Closed>>);

    impl ParallelSink for KeepParallel {
        type Out = Shared;

        fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Shared>> {
            Ok(if member.is_directory {
                Disposition::Skip
            } else {
                Disposition::Write(Shared(Arc::default()))
            })
        }

        fn close(
            &self,
            member: &MemberInfo<'_>,
            out: Option<Shared>,
            outcome: &MemberOutcome,
        ) -> Result<()> {
            self.0.lock().unwrap().push(Closed {
                name: member.name.to_vec(),
                given: out.map(|w| w.0.lock().unwrap().clone()).unwrap_or_default(),
                outcome: *outcome,
            });
            Ok(())
        }
    }

    /// The three drivers every archive here is read through.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Through {
        Sequential,
        SequentialOneWide,
        Pool,
    }

    const DRIVERS: [Through; 3] = [
        Through::Sequential,
        Through::SequentialOneWide,
        Through::Pool,
    ];

    /// One read: what every member's `close` was told and given, in name
    /// order, the operation's error kind as text, the derivations the
    /// session ran, how many times over each encrypted member's packed
    /// bytes were read, and the report.
    struct Read {
        closed: Vec<Closed>,
        error: Option<String>,
        derivations: u64,
        times_read: Vec<f64>,
        report: Option<ExtractReport>,
        /// Every byte read of every volume.
        bytes_read: u64,
    }

    fn read_with(
        archive: &[u8],
        password: &str,
        through: Through,
        memory: Option<MemoryPolicy>,
    ) -> Read {
        read_set(&[archive.to_vec()], password, through, memory)
    }

    /// [`read`] by a session told beforehand that its reading is known,
    /// so that nothing is searched for: every member is decoded under the
    /// first reading and no other, as before a second one was looked for.
    fn read_unsearched(archive: &[u8], password: &str, through: Through) -> Read {
        read_as(&[archive.to_vec()], password, through, None, false)
    }

    /// [`read_with`] for a volume set; `times_read` is of the first
    /// volume's members.
    fn read_set(
        set: &[Vec<u8>],
        password: &str,
        through: Through,
        memory: Option<MemoryPolicy>,
    ) -> Read {
        read_as(set, password, through, memory, true)
    }

    fn read_as(
        set: &[Vec<u8>],
        password: &str,
        through: Through,
        memory: Option<MemoryPolicy>,
        searched: bool,
    ) -> Read {
        let archive = &set[0];
        let sources: Vec<Arc<Watched>> = set
            .iter()
            .map(|bytes| {
                Arc::new(Watched {
                    bytes: bytes.clone(),
                    reads: Mutex::default(),
                })
            })
            .collect();
        let source = &sources[0];
        let mut options = ReadOptions::default().with_password(Some(Password::from(password)));
        if through == Through::SequentialOneWide {
            options = options.with_workers(Some(1));
        }
        if let Some(memory) = memory {
            options = options.with_memory(memory);
        }
        let mut session = Session::new(options);
        if !searched {
            session.ctx.keys.rar4_reading_found();
        }
        let volumes: Vec<Arc<dyn RangeSource>> = sources
            .iter()
            .map(|source| Arc::clone(source) as Arc<dyn RangeSource>)
            .collect();
        let (result, mut closed) = match through {
            Through::Pool => {
                let sink = KeepParallel::default();
                let result = session.extract_parallel(volumes, &sink, POOL);
                (result, sink.0.into_inner().unwrap())
            }
            _ => {
                let mut sink = Keep::default();
                let result = session.extract(volumes, &mut sink, &mut ());
                (result, sink.0)
            }
        };
        closed.sort_by(|a, b| a.name.cmp(&b.name));
        Read {
            closed,
            error: result.as_ref().err().map(|e| format!("{:?}", e.kind())),
            derivations: session.ctx.keys.derivations(),
            times_read: encrypted_members(archive)
                .iter()
                .map(|(range, _)| source.times_read(range))
                .collect(),
            report: result.ok(),
            bytes_read: sources
                .iter()
                .flat_map(|source| source.reads.lock().unwrap().clone())
                .map(|(_, n)| n as u64)
                .sum(),
        }
    }

    fn read(archive: &[u8], password: &str, through: Through) -> Read {
        read_with(archive, password, through, None)
    }

    /// What the genuine archive holds, under its own password: one
    /// derivation, every member right. Returned with how many times over
    /// each member's packed bytes were read, which is the driver's own
    /// figure (a pool's walk and its worker each read a small member).
    fn plain(through: Through) -> (Vec<Closed>, Vec<f64>, u64) {
        let read = read(&genuine(), "Secret", through);
        assert_eq!(read.error, None, "{through:?}");
        assert_eq!(read.derivations, 1, "{through:?}");
        assert_eq!(read.closed.len(), 9, "{through:?}");
        assert!(read
            .closed
            .iter()
            .all(|member| member.outcome.checksum_ok == Some(true)));
        let peak = read.report.unwrap().peak_working_memory;
        (read.closed, read.times_read, peak)
    }

    /// `times` is `plain` with member 0's packed bytes read `more` times
    /// more, and no other member's read any more at all.
    fn assert_read_more(times: &[f64], plain: &[f64], more: f64, what: &str) {
        for (i, (got, was)) in times.iter().zip(plain).enumerate() {
            let want = if i == 0 { was + more } else { *was };
            assert!(
                (got - want).abs() < 0.01,
                "{what}: member {i} read {got} times over, {want} expected"
            );
        }
    }

    #[test]
    fn the_rebuilt_archives_are_the_ones_the_capture_judged() {
        // Call 2 of the capture: good under UnRAR.exe 7.23 for Windows.
        assert_eq!(
            sha256(&rekeyed(Astral::Pair)),
            "1a97e8b60c4e5775f91ff45375eaa7a95fbb8bd8dbebb823958210b5a6305ddd"
        );
        // Call 3: refused there, and good under unrar 7.23 for Linux and
        // macOS (`vectors-K/b3-rar3-kdf/astral.txt`).
        assert_eq!(
            sha256(&rekeyed(Astral::Low16)),
            "1d14f01c16d3332a70d8cde913223f015d42eaa78cffb3e5daaa427adc14c611"
        );
    }

    /// The archive the Windows program opens: every member comes out
    /// right through every driver, and each writer was given its member's
    /// own bytes and NOTHING before them, so no byte decoded under the
    /// first reading reached an output. The cost is one derivation more
    /// and the first member's packed bytes read twice more; the report's
    /// peak working memory is what it is with no search at all.
    #[test]
    fn data_keyed_under_the_pair_opens_and_nothing_else_reaches_a_writer() {
        let archive = rekeyed(Astral::Pair);
        for through in DRIVERS {
            let (members, times, peak) = plain(through);
            let read = read(&archive, KEYED, through);
            assert_eq!(read.error, None, "{through:?}");
            assert_eq!(read.closed, members, "{through:?}");
            assert_eq!(read.derivations, 2, "{through:?}");
            assert_read_more(&read.times_read, &times, 2.0, &format!("{through:?}"));
            assert_eq!(
                read.report.unwrap().peak_working_memory,
                peak,
                "{through:?}"
            );
        }
    }

    /// The archive the Linux and macOS programs open: the first reading
    /// checks, at one derivation and one silent decode of the first
    /// member.
    #[test]
    fn data_keyed_under_the_low_sixteen_bits_opens_at_one_derivation() {
        let archive = rekeyed(Astral::Low16);
        for through in DRIVERS {
            let (members, times, peak) = plain(through);
            let read = read(&archive, KEYED, through);
            assert_eq!(read.error, None, "{through:?}");
            assert_eq!(read.closed, members, "{through:?}");
            assert_eq!(read.derivations, 1, "{through:?}");
            assert_read_more(&read.times_read, &times, 1.0, &format!("{through:?}"));
            assert_eq!(
                read.report.unwrap().peak_working_memory,
                peak,
                "{through:?}"
            );
        }
    }

    /// A password with no character outside the basic plane is never
    /// searched for: `plain` reads each member as the driver always has,
    /// and so does a wrong one, at one derivation.
    #[test]
    fn a_password_with_one_reading_is_never_searched_for() {
        for through in DRIVERS {
            let (_, times, _) = plain(through);
            let wrong = read(&genuine(), "kez", through);
            assert_eq!(wrong.derivations, 1, "{through:?}");
            assert_read_more(&wrong.times_read, &times, 0.0, &format!("{through:?}"));
        }
    }

    /// A password that is not it under either reading fails exactly as it
    /// does when no second reading is looked for: what every `close` is
    /// told, every byte its writer was given and the operation's error are
    /// those of a session that decodes under the first reading alone.
    /// (Under a wrong key the packed bytes are noise, and which fault the
    /// decoder meets first is the decoder's; the search adds and removes
    /// none.) Two derivations, the one salt under each reading, however
    /// many members ask.
    #[test]
    fn a_wrong_password_with_an_outside_character_fails_as_it_did() {
        for through in DRIVERS {
            let before = read_unsearched(&genuine(), KEYED, through);
            assert_eq!(before.derivations, 1, "{through:?}");
            let read = read(&genuine(), KEYED, through);
            assert!(read.error.is_some(), "{through:?}");
            assert_eq!(read.error, before.error, "{through:?}");
            assert_eq!(read.closed, before.closed, "{through:?}");
            assert_eq!(read.closed.len(), 9, "{through:?}");
            for member in &read.closed {
                assert!(!member.outcome.password_refused);
                assert_eq!(member.outcome.bytes, member.given.len() as u64);
                // Only the member that declares no bytes can come out
                // right under a key that is not the archive's.
                assert!(
                    member.outcome.checksum_ok != Some(true) || member.given.is_empty(),
                    "{through:?}"
                );
            }
            assert_eq!(read.derivations, 2, "{through:?}");
        }
    }

    /// Under a NAMED budget of exactly what the archive's own minimum is,
    /// the search runs inside it: the read succeeds and its peak is the
    /// peak of the same read with nothing to search for.
    #[test]
    fn the_search_runs_inside_a_named_budget() {
        let archive = rekeyed(Astral::Pair);
        let named = MemoryPolicy::from_limit(64 << 20);
        let floor = {
            let options = ReadOptions::default()
                .with_password(Some(Password::from(KEYED)))
                .with_memory(named);
            let opened = crate::read::Archive::open(
                Arc::new(archive.clone()) as Arc<dyn RangeSource>,
                &options,
            )
            .unwrap();
            opened.minimum_working_memory(&named)
        };
        let budget = MemoryPolicy::from_limit(floor);
        for through in DRIVERS {
            let quiet = read_with(&genuine(), "Secret", through, Some(budget));
            let searched = read_with(&archive, KEYED, through, Some(budget));
            assert_eq!(quiet.error, None, "{through:?}");
            assert_eq!(searched.error, None, "{through:?}");
            assert_eq!(searched.closed, quiet.closed, "{through:?}");
            let (quiet, searched) = (quiet.report.unwrap(), searched.report.unwrap());
            assert_eq!(
                searched.peak_working_memory, quiet.peak_working_memory,
                "{through:?}"
            );
            assert!(searched.peak_working_memory <= floor, "{through:?}");
        }
    }

    /// Bytes that compress a little and are not all alike.
    fn body(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 32);
        let mut state = seed;
        while out.len() < len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(format!("{:08x} a line of the body\n", state >> 40).as_bytes());
        }
        out.truncate(len);
        out
    }

    /// A RAR 4 set from this crate's writer (which keys under the low 16
    /// bits, spec B 3.2): `members` under `password`, headers clear.
    fn written(
        password: &str,
        members: &[(&[u8], &[u8])],
        solid: bool,
        volume_size: Option<u64>,
    ) -> Vec<Vec<u8>> {
        use crate::write::{
            MemberSpec, Payload, Rar4Version, WriteFormat, WriteMethod, WriteOptions, Writer,
        };
        let mut writer = Writer::new(WriteOptions {
            format: WriteFormat::Rar4(Rar4Version::V29),
            // A set is stored, so that its one member crosses volumes
            // whatever its bytes are; a solid chain needs a codec.
            method: if volume_size.is_some() {
                WriteMethod::Stored
            } else {
                WriteMethod::Compressed {
                    level: 1,
                    dictionary: None,
                }
            },
            password: Some(Password::from(password)),
            entropy: crate::Entropy::Seeded([5u8; 32]),
            solid,
            volume_size,
            filters: crate::FilterPolicy::Off,
            host_os: crate::HostOs::Unix,
            ..WriteOptions::default()
        })
        .unwrap();
        for (name, data) in members {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(data),
                    mtime: None,
                    attributes: 0o644,
                    host_os: crate::HostOs::Unix,
                    is_directory: false,
                })
                .unwrap();
        }
        if volume_size.is_none() {
            let mut archive = Vec::new();
            writer.finish_into(&mut archive).unwrap();
            return vec![archive];
        }
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).unwrap();
        volumes
    }

    /// NOT SEARCHED, the first case: a member split across volumes keeps
    /// the session's reading. The set is read exactly as its twin under a
    /// password with one reading is: the same bytes of the same volumes,
    /// the same derivations, and it opens, being keyed under the first
    /// reading. (A split member keyed under the pair is not opened: spec
    /// B 3.2 asks for the second derivation "when the member does not
    /// check", and this reader cannot ask a split member before output.)
    #[test]
    fn a_member_split_across_volumes_is_not_searched() {
        let data = body(700_000, 7);
        let members: [(&[u8], &[u8]); 1] = [(b"split.txt", &data)];
        let keyed = written(KEYED, &members, false, Some(250_000));
        let twin = written("Secret", &members, false, Some(250_000));
        assert!(keyed.len() >= 2, "the member must cross a volume");
        for through in DRIVERS {
            let read = read_set(&keyed, KEYED, through, None);
            let quiet = read_set(&twin, "Secret", through, None);
            assert_eq!(read.error, None, "{through:?}");
            assert_eq!(read.closed.len(), 1);
            assert_eq!(read.closed[0].given, data, "{through:?}");
            assert_eq!(read.closed[0].outcome.checksum_ok, Some(true));
            assert_eq!(read.derivations, quiet.derivations, "{through:?}");
            assert_eq!(read.bytes_read, quiet.bytes_read, "{through:?}");
        }
    }

    /// NOT SEARCHED, the second case: a member that continues a solid
    /// chain. Under a password that is not it, the member that starts the
    /// chain is searched (read twice more than under a wrong password
    /// with one reading) and the two that continue it are not.
    #[test]
    fn a_member_continuing_a_solid_chain_is_not_searched() {
        let (a, b, c) = (body(60_000, 1), body(50_000, 2), body(40_000, 3));
        let members: [(&[u8], &[u8]); 3] = [(b"a.txt", &a), (b"b.txt", &b), (b"c.txt", &c)];
        let set = written("Secret", &members, true, None);
        for through in DRIVERS {
            let right = read_set(&set, "Secret", through, None);
            assert_eq!(right.error, None, "{through:?}");
            assert_eq!(right.closed.len(), 3);
            let quiet = read_set(&set, "kez", through, None);
            let wrong = read_set(&set, KEYED, through, None);
            assert_read_more(
                &wrong.times_read,
                &quiet.times_read,
                2.0,
                &format!("{through:?}"),
            );
            assert!(wrong
                .closed
                .iter()
                .all(|member| member.outcome.checksum_ok != Some(true)));
        }
    }
}
