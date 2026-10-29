//! `extract_parallel` against `extract` on the same bytes: the concurrent
//! driver's equivalence, driven by the fuzzer (19 Sep 2026).
//!
//! SPEC-API 4.4 promises that output per member is identical to the
//! sequential form and that `close` is in archive order, at every worker
//! count. That is a property no single input can establish and no output
//! byte shows, so it is asserted here over damaged archives, chopped
//! sources, arbitrary memory budgets and arbitrary widths: every run
//! extracts the same bytes TWICE, once each way, and the two answers must
//! agree member for member, verdict for verdict, and error for error.
//!
//! The DAMAGE is the point. Spec F section 8's rule - an extraction error
//! is never a silent success - is what the concurrent path is most able to
//! break, because a member that fails in a worker has to be reported
//! through its own `close` and in archive order, and the sequential path is
//! the only thing that says what that answer should be.

#![no_main]

#[path = "f_support.rs"]
mod support;

use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, MemoryPolicy, ParallelSink,
    RangeSource, ReadOptions, Result, Sink,
};
use support::{pick, VECTORS};

/// One member as either driver closed it: its name, its verdict, how many
/// bytes it produced and the CRC32 of those bytes.
///
/// The CRC32 and NOT the bytes, which is what the first two campaigns of
/// this target got wrong: a sink holding every member's decoded output so
/// that the two drivers could be compared on it is a sink that holds
/// whatever a fuzzer-chosen header declares, twice over, and the
/// out-of-memory that followed was this file's and not the engine's. A
/// digest compares just as strictly - a differing byte changes it - and
/// costs four bytes a member.
type Seen = (Vec<u8>, Option<bool>, u64, u32);

/// The most one member may hand this target's sink before the writer refuses.
///
/// Four mebibytes, and the figure is small because this target cannot tell a
/// slow decoder from a wrong one and is not for either: a RAR 1.5 member
/// whose declared size is corrupt decodes at the engine's ordinary rate, so
/// the only thing that keeps a run cheap is a small ceiling. Both drivers get
/// the same one, so it can end a run but it cannot make them disagree.
const MOST_PER_MEMBER: u64 = 4 << 20;

/// A writer that keeps a digest of what it was given and none of it, and
/// refuses once one MEMBER has produced [`MOST_PER_MEMBER`] bytes.
///
/// PER MEMBER and never a budget shared across them, which is the whole
/// reason this is sound: a shared counter is spent in the order the members
/// finish, the two drivers finish them in different orders by construction,
/// and the two runs would then refuse DIFFERENT members and this target
/// would report its own ceiling as an engine difference. A per-member
/// ceiling is reached by the same member either way.
#[derive(Default)]
struct Digest {
    crc: rarkit::checksum::Crc32,
    bytes: u64,
}

impl std::io::Write for Digest {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.bytes += data.len() as u64;
        if self.bytes > MOST_PER_MEMBER {
            return Err(std::io::Error::other("past this target's per-member ceiling"));
        }
        self.crc.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Serial {
    seen: Vec<Seen>,
}

impl Sink for Serial {
    type Out = Digest;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::default()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Digest>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.push((
            member.name.to_vec(),
            outcome.checksum_ok,
            outcome.bytes,
            out.map_or(0, |d| d.crc.finish()),
        ));
        Ok(())
    }
}

#[derive(Default)]
struct Wide {
    seen: Mutex<Vec<Seen>>,
}

impl ParallelSink for Wide {
    type Out = Digest;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::default()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Digest>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.lock().expect("the sink's own lock").push((
            member.name.to_vec(),
            outcome.checksum_ok,
            outcome.bytes,
            out.map_or(0, |d| d.crc.finish()),
        ));
        Ok(())
    }
}

/// One error's kind as a string, with a `LimitExceeded`'s `needed` figure
/// blanked.
///
/// SPEC-API 8.1 has `needed` as "the archive's figure", and for a window
/// it is. For spec I's TEXT MODEL it is the DECODER's: the arena is sized
/// against what that decoder already holds, so the same member asks for a
/// different figure depending on which members the decoder before it
/// decoded - and the two drivers spread the same members over a different
/// number of decoders by construction. OBSERVED: a damaged `r420_m5.rar`
/// where both paths stop on `DATA.BIN` with
/// `LimitExceeded { resource: TextModel, limit: 134217728 }` and needed
/// 171,668,708 on the walking thread against 142,308,580 on a worker.
///
/// The RESOURCE and the LIMIT are the archive's and the policy's and are
/// compared; `needed` is not. That `needed` depends on decoder history at
/// all is an open question for the specification.
fn kind_of(e: &rarkit::Error) -> String {
    let text = format!("{:?}", e.kind());
    match text.split_once("needed: ") {
        Some((head, rest)) => {
            let tail = rest.split_once(',').map_or("", |(_, tail)| tail);
            format!("{head}needed: _,{tail}")
        }
        None => text,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let seed = data[0];
    let budget = data[1];
    // Widths 1 to 4, not 1 to 9. Every run of this target spawns its width
    // in threads and joins them, and every run runs TWO extractions so that
    // it has something to compare against, so the exec is dear already: a
    // first campaign managed 63,000 runs in ten minutes where
    // `f_extract_any` managed 464,000. Four is enough for the property -
    // one member per worker, a queue with more than one entry in it, and a
    // worker freed and taken again - and the widths above it are covered by
    // `tests/parallel.rs`, which does not have to find its inputs.
    let width = usize::from(data[2] % 4) + 1;
    // The same budget range as `f_extract_any`, 1 MiB to 512 MiB, so the
    // two targets meet the same policies. Note what the range does to the
    // WIDTH: `from_limit` derives `max_workers` as `working_limit / 64
    // MiB`, and the effective width is `min(workers, max_workers)`, so
    // every budget below 128 MiB runs one member at a time whatever this
    // target asked for. That is the engine's rule and not this file's to
    // work around; it is written down because it means the widths above
    // one are only reached by the budgets above 128 MiB.
    let body = &data[3..];

    // Every vector here is far below the engine's measured offload floor,
    // so without this the concurrent driver would decode all of them on the
    // walking thread and this target would fuzz the path it is not for.
    // Thread-local, and libFuzzer runs one input at a time on one thread.
    rarkit::probe::set_offload_floor(Some(0));
    // The outputs bound (`RARKIT_OUTPUTS_OVER_BREADTH`, twice the breadth
    // by default), set EXPLICITLY both ways from the width
    // byte's third bit, which the width above does not read: set, 2 (a
    // worker whose answer has arrived is freed while earlier members wait
    // to close); clear, 1 (the pool that held a worker until its member
    // closed). The answer must be the sequential walk's either way.
    // Thread-local, like the floor.
    rarkit::probe::set_outputs_over_breadth(Some(if data[2] & 4 != 0 { 2 } else { 1 }));

    let (_label, base) = pick(VECTORS, seed);
    // Every vector is fuzzed, the three legacy containers included. They
    // were excluded here until 20 Sep 2026 on the reading that a damaged
    // `D140_M5.RAR` held spec A's decoder in `Rar15Lz::long_match` for over
    // twenty minutes; that reading was wrong and the measurement is in
    // `crates/rarkit/tests/rar15_declared_size.rs`. What those inputs do is
    // corrupt `DATA.BIN`'s declared unpacked size to as much as 4.27 GB, and
    // spec A sections 2, 4.11 and 6 put the decoder in contract to produce
    // it - at its ordinary 270 MB/s, so the twenty minutes was this tree's
    // fuzz build and not the decoder. The bound that makes them cheap enough
    // to fuzz is [`MOST_PER_MEMBER`] on the SINK, below.
    let mut bytes = base.to_vec();
    // Damage, at an offset the fuzzer picks: the archive's own bytes with
    // the seed's body exclusive-ored over them from there on.
    if !body.is_empty() {
        let at = usize::from(seed) * 13 % bytes.len();
        for (i, b) in body.iter().enumerate().take(bytes.len() - at) {
            bytes[at + i] ^= b;
        }
    }
    let opts = ReadOptions::default().with_memory(MemoryPolicy::from_limit(1u64 << (20 + u32::from(budget % 10)))).with_password(Some(rarkit::Password::from("Secret")));

    // WHAT BOUNDS THIS TARGET'S WORK, and why it is the sink and not a
    // listing.
    //
    // Nothing in spec F 4.3 bounds decode time or output size against PACKED
    // size: its three amplification cases are names, member tables and quick
    // open entries, and a member declaring an enormous unpacked size is none
    // of them. The engine is in contract to produce what the header declares
    // and 3.7.6's cancel flag is what a caller uses to stop it, so the bound
    // belongs here, where a caller's would be.
    //
    // It used to be the listing below alone, and that had a HOLE the three
    // pinned seeds in `../seeds/f_extract_parallel` go straight through:
    // `Archive::open` answers `Truncated` on all three, so `declared` was
    // never computed and the walk decoded 4.27 GB anyway. `MOST_PER_MEMBER`
    // on the sink closes it, because a sink needs no listing and refuses
    // whatever the header said. The listing is kept as a FAST PATH: when it
    // works it skips the decode entirely rather than paying for a ceiling's
    // worth of it.
    const MOST_OUTPUT: u64 = 4 << 20;
    let listed: Arc<dyn RangeSource> = Arc::new(bytes.clone());
    if let Ok(archive) = rarkit::Archive::open(listed, &opts) {
        let declared: u64 = archive
            .members()
            .map(|m| m.unpacked_size.unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        if declared > MOST_OUTPUT {
            return;
        }
    }

    let one: Arc<dyn RangeSource> = Arc::new(bytes.clone());
    let mut serial = Serial::default();
    let want = extract(vec![one], &opts, &mut serial, &mut ());

    // [`MOST_PER_MEMBER`] BOUNDS BOTH ARMS, which is what lets the wide one
    // run on every input the sequential one ran on.
    //
    // It did not, between 20 Sep 2026 and the fix in `read::concurrent`:
    // the sequential arm's wall tracked the ceiling exactly - 0.2 ms,
    // 3.3 ms, 12 ms and 48.6 ms at ceilings of 0, 1, 4 and 16 MiB on the
    // `D140_M5.RAR` seed whose `DATA.BIN` declares 2,634,043,104 bytes -
    // while the concurrent arm at width 4 took about 8 SECONDS at every one
    // of them, including a ceiling of ZERO, because a member whose writes
    // were pipelined onto a worker had no way to hear the refusal and the
    // walk decoded the whole declared size first. Eight seconds became a
    // 1229 second libFuzzer timeout once AddressSanitizer and coverage were
    // on top, so this target gated the wide arm on the sequential arm not
    // having tripped, and the inputs that tripped it lost their equivalence
    // check. `Refusal` in `read::concurrent` gives the refusal its way
    // back, `tests/parallel.rs`
    // `a_refused_write_stops_a_piped_member_s_decode` pins it, and the gate
    // is gone: the two arms now stop within a chunk of each other.
    let two: Arc<dyn RangeSource> = Arc::new(bytes);
    let wide = Wide::default();
    let have = extract_parallel(vec![two], &opts, &wide, width);
    let seen = wide.seen.into_inner().expect("the sink's own lock");

    // The two lists agree MEMBER FOR MEMBER as far as the shorter one
    // goes, and the shorter one is a prefix of the longer.
    //
    // They can differ in LENGTH, and only in one case: an error that ends
    // the whole OPERATION - a failed source, a cancel, a limit - stops the
    // sequential walk at the member that met it, while the concurrent walk
    // has already opened and may already have closed the members after it,
    // because running ahead of the decode is what it is for. SPEC-API 8.3
    // promises the bytes, the order and that no failure is lost, and all
    // three hold here; it does not promise that an aborted run stops at
    // the same member, and it cannot. A run that SUCCEEDS is held to equal
    // lengths below, which is where the promise bites.
    for (at, (a, b)) in serial.seen.iter().zip(&seen).enumerate() {
        assert_eq!(a.0, b.0, "width {width}: member {at} closed out of order");
        assert_eq!(a.1, b.1, "width {width}: member {at} got another verdict");
        assert_eq!(a.2, b.2, "width {width}: member {at} produced another length");
        assert_eq!(
            a.3, b.3,
            "width {width}: member {at} produced other bytes (CRC32)"
        );
    }
    match (&want, &have) {
        (Ok(want), Ok(have)) => {
            // Nothing ended the operation, so the two walks reached the
            // same end and closed the same members.
            assert_eq!(
                serial.seen.len(),
                seen.len(),
                "width {width}: two runs that both succeeded closed \
                 different numbers of members"
            );
            assert_eq!(want.members, have.members, "width {width}: report.members");
            assert_eq!(want.bytes, have.bytes, "width {width}: report.bytes");
            assert_eq!(
                want.checksum_failures, have.checksum_failures,
                "width {width}: report.checksum_failures"
            );
        }
        (Err(want), Err(have)) => assert_eq!(
            kind_of(want),
            kind_of(have),
            "width {width}: the two drivers ended with different errors\n  \
             sequential: {want:?}\n  concurrent: {have:?}\n  \
             sequential closed {:?}\n  concurrent closed {:?}",
            serial
                .seen
                .iter()
                .map(|m| String::from_utf8_lossy(&m.0).into_owned())
                .collect::<Vec<_>>(),
            seen.iter()
                .map(|m| String::from_utf8_lossy(&m.0).into_owned())
                .collect::<Vec<_>>()
        ),
        // One succeeded and the other did not. That is a real difference
        // whichever way round it is, and no running ahead explains it.
        (want, have) => panic!(
            "width {width}: one driver failed and the other did not: \
             sequential {want:?}, concurrent {have:?}"
        ),
    }
});
