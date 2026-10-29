//! The `.rev` files a RAR 5 set may carry beside it: writing them,
//! reading one, checking one, and putting missing volumes back from them
//! (API spec sections 7.4 and 9; spec L 3.6).
//!
//! A set of `k` data volumes and `m` recovery volumes is the Cauchy code of
//! spec L 3.4 with each data volume, zero-padded to the largest volume's
//! even length, as one data shard. A recovery volume's payload is one row
//! of that code, and its header carries the whole set's size-and-CRC32
//! table - which is also the set's identity, since the format has no
//! separate identifier (3.6.2).

use std::io::Write;
use std::ops::Range;
use std::sync::Arc;

pub(crate) mod format;

use crate::checksum::{crc32, Crc32};
use crate::memory::MemoryPolicy;
use crate::read::Progress;
use crate::recovery::gf16::{cauchy_cell, Coefficient};
use crate::recovery::io::{length, read_at_most, read_exact_at};
use crate::recovery::stripe::Rebuild;
use crate::write::VolumeOut;
use crate::{Error, ErrorKind, RangeSource, RecoveryFailure, Resource, Result};

/// Bytes read from one volume at a time while encoding.
const ENCODE_CHUNK: u64 = 1 << 20;
/// Recovery rows written per pass over the data, so the number of outputs
/// held open never depends on `m` (spec L 3.8).
const ROWS_PER_PASS: u64 = 32;

/// What [`create`] is allowed to spend. Spec L fixes the field list, and
/// there is one field: everything else about a `.rev` set follows from
/// the data volumes and the count asked for.
#[derive(Clone, Debug)]
pub struct RevOptions {
    /// The ceiling on what encoding may hold at once.
    pub memory: MemoryPolicy,
}

/// An account of a finished [`create`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RevReport {
    /// How many `.rev` files were produced.
    pub volumes: u32,
    /// How many bytes went into them, over all of them.
    pub bytes: u64,
    /// The high-water mark for THIS call, which is not what
    /// [`crate::memory::peak`] reports: that one counts the process.
    pub peak_working_memory: u64,
}

/// Produce `count` recovery volumes covering the data volumes `data`.
///
/// The set is a Cauchy code over the padded data volumes, as the module
/// comment describes, so `count` decides how many losses the set can
/// survive: any `count` of the data volumes can be rebuilt. Use
/// [`default_count`], [`count_for_percent`] or [`max_count`] to choose it.
pub fn create<O: VolumeOut>(
    data: &[Arc<dyn RangeSource>],
    count: u32,
    opts: &RevOptions,
    out: &mut O,
) -> Result<RevReport> {
    let k = u32::try_from(data.len()).unwrap_or(u32::MAX);
    if k == 0 || count == 0 || count > max_count(k) || k + count > 65_535 {
        return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
    }
    let (k, m) = (k as u16, count as u16);

    // The table, which is also the set's identity.
    let table = describe(data, opts.memory.max_workers)?;
    let payload = format::payload_len(table.iter().map(|v| v.size).max().unwrap_or(0));
    if payload == 0 {
        return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
    }

    // The accumulator below is `payload` bytes per row, and `payload` is
    // derived from the largest DATA VOLUME in the set, which is an
    // ordinary file size and may be well over 4 GiB. On a 64-bit target
    // this conversion cannot fail and nothing changes; on a 32-bit one it
    // is the difference between refusing the record and truncating the
    // length silently, allocating an accumulator of the wrong size and
    // then folding parity into it.
    let payload_len = usize::try_from(payload).map_err(|_| {
        Error::new(ErrorKind::LimitExceeded {
            resource: Resource::RepairWork,
            needed: payload,
            limit: usize::MAX as u64,
        })
    })?;
    let batch = (opts.memory.repair_limit / payload).clamp(1, ROWS_PER_PASS) as u16;
    let mut report = RevReport {
        peak_working_memory: u64::from(batch) * payload + ENCODE_CHUNK,
        ..RevReport::default()
    };

    let mut row = 0u16;
    while row < m {
        let rows = batch.min(m - row);
        let mut accumulator = vec![vec![0u8; payload_len]; usize::from(rows)];
        let mut chunk = vec![0u8; ENCODE_CHUNK as usize];
        for (j, volume) in data.iter().enumerate() {
            let coefficients: Vec<Coefficient> = (0..rows)
                .map(|slot| Coefficient::new(cauchy_cell(k, row + slot, j as u16)))
                .collect();
            let mut at = 0u64;
            while at < payload {
                let len = (payload - at).min(ENCODE_CHUNK) as usize;
                let got = read_at_most(volume.as_ref(), at, &mut chunk[..len])?;
                chunk[got..len].fill(0);
                for (accumulator, c) in accumulator.iter_mut().zip(&coefficients) {
                    // `at < payload`, and `payload` is known to fit a
                    // `usize` from `payload_len` above.
                    let at = at as usize;
                    c.fold(&mut accumulator[at..at + len], &chunk[..len]);
                }
                at += len as u64;
            }
        }
        for (slot, parity) in accumulator.iter().enumerate() {
            let index = row + slot as u16;
            let header = format::header(&table, m, index, crc32(parity));
            let mut writer = out.volume(u32::from(index))?;
            writer.write_all(&header).map_err(Error::caller)?;
            writer.write_all(parity).map_err(Error::caller)?;
            writer.flush().map_err(Error::caller)?;
            // The finished volume goes BACK to the provider, which is the
            // whole of `VolumeOut`'s contract: a provider writing straight
            // to a file lets the default body drop it, and one that
            // COLLECTS its volumes - the `Vec<Vec<u8>>` impl, and any
            // caller who keeps what it wrote - has no other way to be
            // handed them. Without this a collecting provider was told
            // `RevReport::volumes` recovery volumes had been written and
            // received none of them, which is `Writer::finish_volumes`'s
            // own rule broken by the one other emitter in this crate.
            // Found by `the_one_call_form_writes_what_rev5_create_writes`.
            out.finished(u32::from(index), writer)?;
            report.volumes += 1;
            report.bytes += header.len() as u64 + parity.len() as u64;
        }
        row += rows;
    }
    Ok(report)
}

/// Each data volume's size and CRC32.
///
/// **Bounded by `workers`, which is the caller's
/// [`MemoryPolicy::max_workers`](crate::MemoryPolicy::max_workers).** Every
/// source in flight holds a read buffer of [`ENCODE_CHUNK`] bytes, so the
/// sources hashed at once are a memory bearing unit and API 8.2's table
/// names this stage: "rev5 whole-source hashing and verification", at
/// most `max_workers` sources, one bounded read buffer each. Handing the
/// whole set to a pool put one buffer per SOURCE in flight instead, which
/// is more units than the ceiling allows whenever a set is wider than the
/// policy - a set of 64 volumes on the default policy's ceiling of 8 held
/// 64 MiB of read buffers where 8 MiB was promised.
///
/// The bound is a ceiling and not a demand: the sources are taken in runs
/// of `workers` and each run is hashed together, so a caller allowed
/// eight still gets eight at a time.
fn describe(data: &[Arc<dyn RangeSource>], workers: usize) -> Result<Vec<DataVolume>> {
    let one = |volume: &Arc<dyn RangeSource>| -> Result<DataVolume> {
        let size = length(volume.as_ref());
        Ok(DataVolume {
            size,
            crc32: whole_crc32(volume.as_ref(), size)?,
        })
    };
    in_flight_bound(data, workers, one)
}

/// Run `one` over `items`, with at most `workers` of them in flight at
/// once (API 8.2). The answers are in the order given, and the first
/// failure in that order is the one returned.
///
/// This is the whole of what bounds `rev5`'s two whole-source stages. A
/// plain `par_iter` over the set does not: how many items a pool has in
/// flight is the POOL's width, which is the caller's and is not the
/// memory dial (API 8.3), so a wide pool and a narrow policy put more
/// read buffers in the air than the policy allows.
fn in_flight_bound<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    one: impl Fn(&T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let width = workers.max(1);
    let mut out = Vec::with_capacity(items.len());
    for run in items.chunks(width) {
        #[cfg(feature = "parallel")]
        if width > 1 && run.len() > 1 {
            use rayon::prelude::*;
            let mut done: Vec<R> = run.par_iter().map(&one).collect::<Result<Vec<R>>>()?;
            out.append(&mut done);
            continue;
        }
        for item in run {
            out.push(one(item)?);
        }
    }
    Ok(out)
}

/// The CRC32 of a whole source, read positionally in 1 MiB blocks.
fn whole_crc32(src: &dyn RangeSource, size: u64) -> Result<u32> {
    let mut hasher = Crc32::new();
    let mut buf = vec![0u8; ENCODE_CHUNK as usize];
    let mut at = 0u64;
    while at < size {
        let want = (size - at).min(ENCODE_CHUNK) as usize;
        let got = read_at_most(src, at, &mut buf[..want])?;
        if got == 0 {
            break;
        }
        hasher.update(&buf[..got]);
        at += got as u64;
    }
    Ok(hasher.finish())
}

/// The count to use when the caller has no opinion, which is ten per cent
/// of the data volumes.
pub fn default_count(data_volumes: u32) -> u32 {
    count_for_percent(data_volumes, 10)
}

/// How many recovery volumes `percent` per cent of `data_volumes` comes
/// to, rounded up so that a small set still gets one.
pub fn count_for_percent(data_volumes: u32, percent: u32) -> u32 {
    (u64::from(data_volumes) * u64::from(percent)).div_ceil(100) as u32
}

/// The most recovery volumes a set of this size may have. Asking
/// [`create`] for more than this is refused.
pub fn max_count(data_volumes: u32) -> u32 {
    data_volumes.saturating_mul(10)
}

/// Read the header of one `.rev` file and say what set it belongs to.
///
/// This touches the header only; nothing of the payload is read, and
/// whether the payload survived is [`RevInfo::verify_payload`]'s question.
pub fn inspect(src: &dyn RangeSource) -> Result<RevInfo> {
    format::parse(src)
}

/// What one `.rev` file's header says about itself and its set.
///
/// The format has no set identifier, so there is no `set_id` here: two
/// volumes are of one set when their counts and their whole tables agree
/// (spec L 3.6.2, question in the API's section 9 answered).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevInfo {
    /// Which row of the code this volume's payload is.
    pub row: u32,
    /// How many data volumes the set was built over.
    pub data_count: u32,
    /// How many recovery volumes the set has in all.
    pub recovery_count: u32,
    /// The set's table of data volumes, in set order. This doubles as the
    /// set's identity, which is what [`RevInfo::same_set`] compares.
    pub data_volumes: Vec<DataVolume>,
    /// Where the payload sits in the source this header was read from.
    pub payload: Range<u64>,
    /// The CRC32 the header records for that payload.
    pub payload_crc: u32,
}

/// One row of the table a recovery volume keeps about the data volumes.
///
/// Two numbers are enough to recognise a volume and to know it is
/// undamaged, and they are also all a rebuild has to verify its own
/// output against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataVolume {
    /// The volume's length in bytes.
    pub size: u64,
    /// The CRC32 over the whole of that volume's file.
    pub crc32: u32,
}

impl RevInfo {
    /// Read the payload and check it against the CRC32 the header
    /// records for it.
    ///
    /// A payload that does not match is `Ok(false)`, not an error: a
    /// damaged recovery volume is a fact about the set, and a caller
    /// collecting which volumes are usable wants it as an answer.
    pub fn verify_payload(&self, src: &dyn RangeSource) -> Result<bool> {
        let mut hasher = Crc32::new();
        let mut buf = vec![0u8; ENCODE_CHUNK as usize];
        let mut at = self.payload.start;
        while at < self.payload.end {
            let want = (self.payload.end - at).min(ENCODE_CHUNK) as usize;
            let got = read_at_most(src, at, &mut buf[..want])?;
            if got == 0 {
                return Ok(false);
            }
            hasher.update(&buf[..got]);
            at += got as u64;
        }
        Ok(hasher.finish() == self.payload_crc)
    }

    /// Whether `other` came from the same set as this one.
    ///
    /// The format records no set identifier, so this compares what it
    /// does record: the two counts and the whole data-volume table
    /// (spec L 3.6.2).
    pub fn same_set(&self, other: &RevInfo) -> bool {
        self.data_count == other.data_count
            && self.recovery_count == other.recovery_count
            && self.data_volumes == other.data_volumes
    }

    /// The padded shard length every volume of the set is addressed
    /// against.
    fn shard_len(&self) -> u64 {
        format::payload_len(self.data_volumes.iter().map(|v| v.size).max().unwrap_or(0))
    }
}

/// Check a batch of candidate files against the data volumes a set
/// expects, one answer per target in the order given.
///
/// A target matches when its length and its CRC32 are what the set
/// recorded. Under the `parallel` feature the targets are checked
/// together rather than in turn, which matters because each answer costs
/// a full read of the file.
///
/// **`policy` is what bounds that.** Each target in flight holds a read
/// buffer, so the targets checked at once are memory bearing units and
/// [`MemoryPolicy::max_workers`](crate::MemoryPolicy::max_workers) is
/// their ceiling (API 8.2). This function used to read no policy at all
/// and hand every target to the pool at once, which put one read buffer
/// per TARGET in the air however narrow the caller's budget was; API 8.2
/// calls a stage that puts more memory bearing units in flight than the
/// ceiling allows a defect, and that is the direction this was in.
///
/// Answers are still one per target in the order given, whatever the
/// ceiling, so nothing a caller reads from this changes with the policy
/// but the memory it costs.
pub fn matches(
    targets: &[(&dyn RangeSource, &DataVolume)],
    policy: &MemoryPolicy,
) -> Vec<Result<bool>> {
    let one = |&(src, want): &(&dyn RangeSource, &DataVolume)| -> Result<bool> {
        if length(src) != want.size {
            return Ok(false);
        }
        Ok(whole_crc32(src, want.size)? == want.crc32)
    };
    // One `Result` per target rather than the first failure, which is
    // this entry point's contract, so the runs are walked here rather
    // than through `in_flight_bound`.
    let width = policy.max_workers.max(1);
    let mut out: Vec<Result<bool>> = Vec::with_capacity(targets.len());
    for run in targets.chunks(width) {
        #[cfg(feature = "parallel")]
        if width > 1 && run.len() > 1 {
            use rayon::prelude::*;
            out.append(&mut run.par_iter().map(one).collect::<Vec<_>>());
            continue;
        }
        out.extend(run.iter().map(one));
    }
    out
}

/// The answers a repair needs before it reads to rebuild: for each data
/// volume there, whether it is the table's (as [`matches`]), and for each
/// recovery volume, whether its payload is the one its header records
/// (as [`RevInfo::verify_payload`]).
///
/// ONE batch under one ceiling. Each check in flight holds a read
/// buffer, so the checks made at once are memory bearing units and
/// `policy.max_workers` bounds them together (API 8.2), the data volumes
/// first and then the payloads.
fn checked(
    present: &[(&dyn RangeSource, &DataVolume)],
    payloads: &[(&RevInfo, &dyn RangeSource)],
    policy: &MemoryPolicy,
) -> (
    std::vec::IntoIter<Result<bool>>,
    std::vec::IntoIter<Result<bool>>,
) {
    let one = |at: &usize| -> Result<bool> {
        match at.checked_sub(present.len()) {
            None => {
                let (src, want) = present[*at];
                Ok(length(src) == want.size && whole_crc32(src, want.size)? == want.crc32)
            }
            Some(e) => payloads[e].0.verify_payload(payloads[e].1),
        }
    };
    let all: Vec<usize> = (0..present.len() + payloads.len()).collect();
    let width = policy.max_workers.max(1);
    let mut out: Vec<Result<bool>> = Vec::with_capacity(all.len());
    for run in all.chunks(width) {
        #[cfg(feature = "parallel")]
        if width > 1 && run.len() > 1 {
            use rayon::prelude::*;
            out.append(&mut run.par_iter().map(one).collect::<Vec<_>>());
            continue;
        }
        out.extend(run.iter().map(one));
    }
    let sound = out.split_off(present.len());
    (out.into_iter(), sound.into_iter())
}

/// Rebuild the data volumes the caller marked absent, and verify each one
/// before returning.
///
/// The volumes to rebuild are those left `None` in `set.data`. `out` is
/// asked for one writer per rebuilt index, as it is reached. Nothing is
/// handed back unchecked: every rebuilt volume is measured and hashed
/// against the size and CRC32 the set recorded for it, and one that fails
/// is named in the report rather than passed off as mended.
///
/// The whole plan is costed against `policy.repair_limit` BEFORE any
/// source is read, so a set too large to rebuild inside the budget fails
/// with [`LimitExceeded`](crate::ErrorKind::LimitExceeded) having spent
/// nothing.
pub fn repair(
    set: &RepairSet<'_>,
    policy: &MemoryPolicy,
    out: &mut dyn FnMut(u32) -> Result<Box<dyn Write + Send>>,
    progress: &mut dyn Progress,
) -> Result<RepairReport> {
    let Some((first, _)) = set.recovery.first() else {
        return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
    };
    if set.recovery.iter().any(|(info, _)| !first.same_set(info)) {
        return Err(Error::new(ErrorKind::Recovery(
            RecoveryFailure::SetMismatch,
        )));
    }
    let k = u16::try_from(first.data_count)
        .map_err(|_| Error::new(ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged)))?;
    if set.data.len() != usize::from(k) {
        return Err(Error::new(ErrorKind::Recovery(
            RecoveryFailure::SetMismatch,
        )));
    }
    let shard_len = first.shard_len();
    let table = first.data_volumes.clone();

    // A present volume that does not match its table row counts as
    // missing (3.6.2), and only a `.rev` whose payload is intact can
    // carry an equation, one per row.
    // Every one of those answers costs a whole read of a file, so they
    // are asked together, as one batch under the policy's ceiling (API
    // 8.2): the data volumes there and then the recovery payloads. Asked
    // one after another they left every core but one idle.
    let present: Vec<(&dyn RangeSource, &DataVolume)> = set
        .data
        .iter()
        .enumerate()
        .filter_map(|(j, slot)| slot.as_ref().map(|src| (src.as_ref(), &table[j])))
        .collect();
    let mut rows_seen: Vec<(u16, &Arc<dyn RangeSource>, &RevInfo)> = Vec::new();
    for (info, src) in &set.recovery {
        let row = u16::try_from(info.row).unwrap_or(u16::MAX);
        if !rows_seen.iter().any(|(seen, _, _)| *seen == row) {
            rows_seen.push((row, src, info));
        }
    }
    let payloads: Vec<(&RevInfo, &dyn RangeSource)> = rows_seen
        .iter()
        .map(|(_, src, info)| (*info, src.as_ref()))
        .collect();
    let (mut answers, sound) = checked(&present, &payloads, policy);
    let mut damaged: Vec<u16> = Vec::new();
    for (j, slot) in set.data.iter().enumerate() {
        let missing = match slot {
            None => true,
            Some(_) => !answers.next().expect("one answer per present volume")?,
        };
        if missing {
            damaged.push(j as u16);
        }
    }
    if damaged.is_empty() {
        // Nothing to rebuild: what the recovery payloads answered, an
        // error among it, is not this call's to report.
        return Ok(RepairReport::default());
    }

    let mut usable: Vec<(u16, &Arc<dyn RangeSource>, &RevInfo)> = Vec::new();
    for (one, sound) in rows_seen.into_iter().zip(sound) {
        if sound? {
            usable.push(one);
        }
    }
    usable.sort_by_key(|(row, _, _)| *row);
    if damaged.len() > usable.len() {
        return Err(Error::new(ErrorKind::Recovery(
            RecoveryFailure::TooManyMissing {
                missing: damaged.len() as u32,
                available: usable.len() as u32,
            },
        )));
    }

    let rows: Vec<u16> = usable.iter().map(|(row, _, _)| *row).collect();
    let plan = Rebuild::new(k, shard_len, &damaged, &rows)?;
    let stripe = plan.stripe_len(policy)?;
    // The walk across the pool takes a shorter stripe where it runs.
    #[cfg(feature = "parallel")]
    let team = plan.wide_team(stripe, policy);
    #[cfg(feature = "parallel")]
    let stripe = team.map_or(stripe, |(wide, _)| wide);
    let peak = plan.working_bytes(stripe);
    if peak > policy.repair_limit {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: Resource::RepairWork,
            needed: peak,
            limit: policy.repair_limit,
        }));
    }

    // One writer, one running CRC32 and one byte budget per rebuilt
    // volume: nothing rebuilt is held whole.
    let mut writers: Vec<Box<dyn Write + Send>> = Vec::with_capacity(damaged.len());
    for &j in &damaged {
        writers.push(out(u32::from(j))?);
    }
    let mut hashers = vec![Crc32::new(); damaged.len()];
    let mut written = vec![0u64; damaged.len()];

    {
        let read_shard = |j: u16, at: u64, buf: &mut [u8]| -> Result<()> {
            let source = set.data[usize::from(j)]
                .as_ref()
                .expect("an intact shard is present");
            let real = table[usize::from(j)].size;
            let have = real.saturating_sub(at).min(buf.len() as u64) as usize;
            buf[have..].fill(0);
            if have > 0 {
                read_exact_at(source.as_ref(), at, &mut buf[..have])?;
            }
            Ok(())
        };
        let read_parity = |e: usize, at: u64, buf: &mut [u8]| -> Result<()> {
            let (_, src, info) = &usable[e];
            read_exact_at(src.as_ref(), info.payload.start + at, buf)
        };
        // What of a rebuilt stripe is the volume's own, written and
        // hashed: a volume shorter than the shard ends before it.
        let keep = |writer: &mut Box<dyn Write + Send>,
                    hasher: &mut Crc32,
                    written: &mut u64,
                    want: u64,
                    bytes: &[u8]|
         -> Result<()> {
            let room = want.saturating_sub(*written).min(bytes.len() as u64) as usize;
            if room > 0 {
                writer.write_all(&bytes[..room]).map_err(Error::caller)?;
                hasher.update(&bytes[..room]);
                *written += room as u64;
            }
            Ok(())
        };
        let want = |t: usize| table[usize::from(damaged[t])].size;
        #[cfg(feature = "parallel")]
        let wide = team.is_some();
        #[cfg(not(feature = "parallel"))]
        let wide = false;
        #[cfg(feature = "parallel")]
        if let Some((_, threads)) = team {
            use rayon::prelude::*;
            // Each rebuilt volume has a writer of its own, so a stripe
            // goes to all of them at once, `threads` at a time.
            let mut emit = |_at: u64, stripes: &[Vec<u8>], len: usize| -> Result<()> {
                let mut each: Vec<_> = writers
                    .iter_mut()
                    .zip(hashers.iter_mut())
                    .zip(written.iter_mut())
                    .zip(stripes)
                    .enumerate()
                    .collect();
                for run in each.chunks_mut(threads) {
                    run.par_iter_mut().try_for_each(
                        |(t, (((writer, hasher), written), bytes))| {
                            keep(writer, hasher, written, want(*t), &bytes[..len])
                        },
                    )?;
                }
                Ok(())
            };
            plan.run_wide(stripe, threads, &read_shard, &read_parity, &mut emit)?;
        }
        if !wide {
            let mut read_shard = read_shard;
            let mut read_parity = read_parity;
            let mut emit = |t: usize, _at: u64, bytes: &[u8]| -> Result<()> {
                keep(
                    &mut writers[t],
                    &mut hashers[t],
                    &mut written[t],
                    want(t),
                    bytes,
                )
            };
            plan.run(stripe, policy, &mut read_shard, &mut read_parity, &mut emit)?;
        }
    }

    let mut report = RepairReport {
        peak_working_memory: peak,
        ..RepairReport::default()
    };
    for (t, &j) in damaged.iter().enumerate() {
        writers[t].flush().map_err(Error::caller)?;
        let want = &table[usize::from(j)];
        if written[t] == want.size && hashers[t].finish() == want.crc32 {
            report.rebuilt.push(u32::from(j));
            progress.volume_done(u32::from(j))?;
        } else {
            report.failed.push(u32::from(j));
        }
    }
    progress.output(report.rebuilt.len() as u64 * shard_len)?;
    Ok(report)
}

/// The set a [`repair`] is to work from: what survives, and what is to be
/// rebuilt from it.
pub struct RepairSet<'a> {
    /// Every data volume position in set order. `None` marks one that is
    /// missing or known bad, and those are the ones `repair` writes.
    pub data: Vec<Option<Arc<dyn RangeSource>>>,
    /// The recovery volumes to draw on, each with the header already
    /// parsed by [`inspect`].
    pub recovery: Vec<(&'a RevInfo, Arc<dyn RangeSource>)>,
}

/// An account of a finished repair, in either family.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepairReport {
    /// The positions that were rebuilt AND passed their check. An inline
    /// repair, which has one volume, reports 0 here.
    pub rebuilt: Vec<u32>,
    /// The positions that were rebuilt and did NOT pass. A rebuild that
    /// failed its check is reported rather than kept.
    pub failed: Vec<u32>,
    /// The high-water mark for this call alone.
    pub peak_working_memory: u64,
}

/// The code's arithmetic on its own, with no container around it.
///
/// Section 9 makes this public so that a test can construct a set, damage
/// it deliberately and know exactly what it damaged. Spec L defines the
/// field and the matrix.
pub mod parity {
    use crate::recovery::gf16::{cauchy_cell, Coefficient};
    use crate::{Error, ErrorKind, RecoveryFailure, Result};

    /// Fill each shard of `parity` with its row of the code over `data`.
    ///
    /// Every shard, data and parity alike, must be the same length; the
    /// padding that makes that true of real volumes is the caller's.
    pub fn encode(data: &[&[u8]], parity: &mut [&mut [u8]]) -> Result<()> {
        let bad = || Error::new(ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged));
        let k = u16::try_from(data.len()).map_err(|_| bad())?;
        let m = u16::try_from(parity.len()).map_err(|_| bad())?;
        if k == 0 || m == 0 || u32::from(k) + u32::from(m) > 65_535 {
            return Err(bad());
        }
        let len = data[0].len();
        if data.iter().any(|s| s.len() != len) || parity.iter().any(|s| s.len() != len) {
            return Err(bad());
        }
        for (row, out) in parity.iter_mut().enumerate() {
            out.fill(0);
            for (j, shard) in data.iter().enumerate() {
                Coefficient::new(cauchy_cell(k, row as u16, j as u16)).fold(out, shard);
            }
        }
        Ok(())
    }
}
