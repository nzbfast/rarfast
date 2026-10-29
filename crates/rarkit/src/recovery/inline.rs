//! Verify and repair one volume from its RAR 5 inline record (spec L 3.8).
//!
//! Group by group: the table in any surviving record of a group names each
//! data slice's expected CRC-64, the slices' actual registers are computed
//! over the volume as it stands, and a mismatching slice is damaged. A
//! group is recoverable when its damaged slices are no more numerous than
//! its surviving records with distinct rows. Every rebuilt slice is checked
//! against its own table entry before it is believed, and only its REAL
//! bytes - those below `P` - are written back. Damage at or after `P` is
//! not the record's to repair: a lost record just means one fewer row.
//!
//! The rebuilt slices are held until they are written, and they are
//! charged to `MemoryPolicy::repair_limit` with the stripe. A repair whose
//! slices all fit is rebuilt whole and written in one pass. One whose
//! slices do not fit is rebuilt in BATCHES, in the order the slices lie in
//! the volume, each batch written before the next is rebuilt (`batch_end`);
//! what is refused is a limit below one slice and the smallest stripe.

use std::io::Write;

use crate::carry::g_recovery::recovery::rar5::MIN_STRIPE_LEN;
use crate::checksum::crc64::Crc64Register;
use crate::memory::MemoryPolicy;
use crate::recovery::io::{length, read_at_most, read_exact_at};
use crate::recovery::rr5;
use crate::recovery::scan::{parity_at, slice, Found};
use crate::recovery::stripe::Rebuild;
use crate::rev5::RepairReport;
use crate::source::RangeSource;
use crate::{Error, ErrorKind, RecoveryFailure, Resource, Result};

/// Bytes copied per block when the repaired volume is written out.
const COPY_BLOCK: usize = 1 << 20;

/// One rebuilt slice, ready to be written into the protected prefix.
struct Patch {
    /// Where the slice's real bytes start in the volume.
    at: u64,
    bytes: Vec<u8>,
}

/// One damaged slice: where it lies in the volume, and which it is.
#[derive(Clone, Copy)]
struct Damaged {
    at: u64,
    group: u64,
    shard: u16,
}

/// Repair `src` from `found` into `out`.
///
/// The output is written once, in order, so the rebuilt slices are taken
/// in the order they lie in the volume. As many as fit the repair limit
/// are rebuilt, the volume is written up to the last of them, and they
/// are dropped before the next are rebuilt. A repair whose slices all fit
/// is one batch: every group rebuilt once, then the volume written, which
/// is the whole of what this did before there were batches. Past that, a
/// group with slices in several batches is read and folded once for each,
/// which is the price of running at all: with `d` shards damaged from end
/// to end and room for `c` of them, about `d / c` passes over the volume.
///
/// **An error after the first batch leaves a partial output**, where a
/// repair within the limit writes nothing until every slice is rebuilt.
pub(crate) fn repair(
    src: &dyn RangeSource,
    found: &Found,
    policy: &MemoryPolicy,
    out: &mut dyn Write,
) -> Result<RepairReport> {
    let plan = &found.plan;
    let mut peak = 0u64;
    let mut rebuilt_any = false;
    let mut failed_any = false;

    // Every group's expected table, from any surviving record of it; a
    // group no record survives for is not the record's to judge.
    let rows_by_group = found.rows_by_group();
    let mut tables: Vec<Option<Vec<u64>>> = Vec::new();
    for (group, rows) in rows_by_group.iter().enumerate() {
        let group = group as u64;
        tables.push(match rows.first() {
            Some(&row) => Some(rr5::read_table(
                src,
                found
                    .record(row, group)
                    .expect("a surviving row has its record"),
            )?),
            None => None,
        });
    }
    let damaged_by_group = damaged_slices(src, plan, &tables, policy)?;
    for (damaged, rows) in damaged_by_group.iter().zip(&rows_by_group) {
        if damaged.len() > rows.len() {
            return Err(Error::new(ErrorKind::Recovery(
                RecoveryFailure::TooManyMissing {
                    missing: damaged.len() as u32,
                    available: rows.len() as u32,
                },
            )));
        }
    }

    // The damaged slices in the order they lie in the volume, which is by
    // shard and then by group.
    let mut order: Vec<Damaged> = damaged_by_group
        .iter()
        .enumerate()
        .flat_map(|(group, damaged)| {
            let group = group as u64;
            damaged.iter().map(move |&shard| Damaged {
                at: slice(plan, shard, group).0,
                group,
                shard,
            })
        })
        .collect();
    order.sort_by_key(|slice| slice.at);

    let mut writer = Repaired::new(src);
    let mut done = 0usize;
    while done < order.len() {
        let end = batch_end(plan, &damaged_by_group, &order, done, policy)?;
        let batch = &order[done..end];
        // Which shards of each group this batch keeps, ascending.
        let mut wanted: Vec<Vec<u16>> = vec![Vec::new(); damaged_by_group.len()];
        for slice in batch {
            wanted[slice.group as usize].push(slice.shard);
        }
        let mut patches: Vec<Patch> = Vec::with_capacity(batch.len());
        // Real bytes of the batch's slices kept so far.
        let mut kept = 0u64;
        for group in 0..plan.group_count {
            let wanted = &mut wanted[group as usize];
            if wanted.is_empty() {
                continue;
            }
            wanted.sort_unstable();
            let rows = &rows_by_group[group as usize];
            let table = tables[group as usize]
                .as_ref()
                .expect("a group with damage was judged against its table");
            let group_len = plan.group_len(group);
            let damaged = &damaged_by_group[group as usize];

            let plan_rebuild = Rebuild::new(plan.k, group_len, damaged, rows)?;
            // The stripe gets what the held slices leave of the limit,
            // which `batch_end` has shown is at least the minimum stripe.
            let held = kept + (wanted.len() as u64) * group_len;
            let stripe = plan_rebuild.stripe_len(&MemoryPolicy {
                repair_limit: policy.repair_limit.saturating_sub(held),
                ..*policy
            })?;
            // Where each damaged shard's stripe goes: a slice of this
            // batch, or nowhere when the shard is another batch's.
            let slots: Vec<Option<usize>> = damaged
                .iter()
                .map(|j| wanted.binary_search(j).ok())
                .collect();
            let mut slices = vec![vec![0u8; group_len as usize]; wanted.len()];
            peak = peak.max(plan_rebuild.working_bytes(stripe) + held);
            let chosen: Vec<u16> = rows[..damaged.len()].to_vec();
            {
                let mut read_shard = |j: u16, at: u64, buf: &mut [u8]| -> Result<()> {
                    let (base, real) = slice(plan, j, group);
                    let have = real.saturating_sub(at).min(buf.len() as u64) as usize;
                    buf[have..].fill(0);
                    if have > 0 {
                        read_exact_at(src, base + at, &mut buf[..have])?;
                    }
                    Ok(())
                };
                let mut read_parity = |e: usize, at: u64, buf: &mut [u8]| -> Result<()> {
                    let record = found
                        .record(chosen[e], group)
                        .expect("a chosen row has its record");
                    read_exact_at(src, parity_at(record) + at, buf)
                };
                let mut emit = |t: usize, at: u64, bytes: &[u8]| -> Result<()> {
                    if let Some(slot) = slots[t] {
                        slices[slot][at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
                    }
                    Ok(())
                };
                plan_rebuild.run(stripe, policy, &mut read_shard, &mut read_parity, &mut emit)?;
            }

            // Nothing rebuilt is believed until it matches its own table
            // entry.
            for (slot, &j) in wanted.iter().enumerate() {
                let (at, real) = slice(plan, j, group);
                let mut register = Crc64Register::new();
                register.update(&slices[slot][..real as usize]);
                if register.state() != table[usize::from(j)] {
                    failed_any = true;
                    continue;
                }
                rebuilt_any = true;
                if real > 0 {
                    let mut bytes = std::mem::take(&mut slices[slot]);
                    bytes.truncate(real as usize);
                    bytes.shrink_to_fit();
                    kept += real;
                    patches.push(Patch { at, bytes });
                }
            }
        }
        patches.sort_by_key(|p| p.at);
        writer.through(&patches, out)?;
        done = end;
    }
    writer.finish(out)?;
    Ok(RepairReport {
        rebuilt: if rebuilt_any { vec![0] } else { Vec::new() },
        failed: if failed_any { vec![0] } else { Vec::new() },
        peak_working_memory: peak,
    })
}

/// What rebuilding the slices `batch` holds at its most (spec L 3.8:
/// working memory "fits `MemoryPolicy::repair_limit`").
///
/// A rebuilt slice is held whole until it has passed its check, and a
/// checked one is held until its batch is written. So what a group needs
/// is the real bytes of every slice of the batch kept from the groups
/// before it, its own slices of the batch at the group's length, and one
/// stripe's working rows, which are counted over ALL the group's damaged
/// shards because the solve is; the answer is the most any group needs.
fn batch_need(plan: &rr5::Rr5Plan, damaged_by_group: &[Vec<u16>], batch: &[Damaged]) -> u64 {
    // (group, slices of the batch, their real bytes), ascending by group.
    let mut groups: Vec<(u64, u64, u64)> = Vec::new();
    let mut sorted: Vec<&Damaged> = batch.iter().collect();
    sorted.sort_by_key(|slice| slice.group);
    for slice_of in sorted {
        let real = slice(plan, slice_of.shard, slice_of.group).1;
        match groups.last_mut() {
            Some(last) if last.0 == slice_of.group => {
                last.1 += 1;
                last.2 += real;
            }
            _ => groups.push((slice_of.group, 1, real)),
        }
    }
    let mut kept = 0u64;
    let mut needed = 0u64;
    for (group, count, real) in groups {
        let group_len = plan.group_len(group);
        let d = damaged_by_group[group as usize].len() as u64;
        let stripe = group_len.min(MIN_STRIPE_LEN as u64);
        needed = needed.max(kept + count * group_len + (2 * d + 2) * stripe);
        kept += real;
    }
    needed
}

/// Where the batch that starts at `order[start]` ends: every slice left
/// when they fit `policy.repair_limit`, and otherwise the longest run of
/// them that does.
///
/// A limit that does not hold even ONE slice beside the smallest stripe
/// is `LimitExceeded { RepairWork }` naming both figures. Every batch is
/// planned before a byte of it is rebuilt, but only the first is planned
/// before a byte is WRITTEN; the least a later batch needs is no more
/// than the first's unless its group has more damage, so a caller that
/// raises `repair_limit` to `needed` and retries gets further each time.
fn batch_end(
    plan: &rr5::Rr5Plan,
    damaged_by_group: &[Vec<u16>],
    order: &[Damaged],
    start: usize,
    policy: &MemoryPolicy,
) -> Result<usize> {
    let limit = policy.repair_limit;
    let fits = |end: usize| batch_need(plan, damaged_by_group, &order[start..end]) <= limit;
    if fits(order.len()) {
        return Ok(order.len());
    }
    if !fits(start + 1) {
        return Err(Error::new(ErrorKind::LimitExceeded {
            resource: Resource::RepairWork,
            needed: batch_need(plan, damaged_by_group, &order[start..start + 1]),
            limit,
        }));
    }
    // What a batch needs only grows with the slices in it, so the longest
    // that fits is found by doubling and then halving the gap.
    let mut low = start + 1;
    let mut high = order.len();
    let mut step = 1usize;
    while low + step < high {
        if fits(low + step) {
            low += step;
            step *= 2;
        } else {
            high = low + step;
            break;
        }
    }
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if fits(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

/// Below this many bytes of slices per thread the calling thread hashes
/// them alone: the gate is work per thread, as the fold's is (spec L 7).
#[cfg(feature = "parallel")]
const HASH_TEAM_MIN_PER_THREAD: u64 = 1 << 20;

/// Which data slices of each group no longer match their recorded CRC-64,
/// by group; a group with no table has none.
///
/// Every slice of every judged group is read and hashed once. That is the
/// whole of the repair's reading before it knows what to rebuild, so it
/// runs on a team: at most `policy.max_workers` threads of the caller's
/// pool at once (the helper bound a write has, applied to
/// this pass), and only as many as get a MiB of slices each. The slices
/// are cut into that many runs in (group, shard) order, one task a run,
/// each with its own slice buffer; the answer does not depend on the cut.
fn damaged_slices(
    src: &dyn RangeSource,
    plan: &rr5::Rr5Plan,
    tables: &[Option<Vec<u64>>],
    policy: &MemoryPolicy,
) -> Result<Vec<Vec<u16>>> {
    let slices: Vec<(u64, u16)> = tables
        .iter()
        .enumerate()
        .filter(|(_, table)| table.is_some())
        .flat_map(|(group, _)| (0..plan.k).map(move |j| (group as u64, j)))
        .collect();
    let check = |run: &[(u64, u16)]| -> Result<Vec<(u64, u16)>> {
        let mut scratch = vec![0u8; crate::recovery::rr5::GROUP_MAX as usize];
        let mut bad = Vec::new();
        for &(group, j) in run {
            let (at, real) = slice(plan, j, group);
            let buf = &mut scratch[..real as usize];
            if !buf.is_empty() {
                read_exact_at(src, at, buf)?;
            }
            let mut register = Crc64Register::new();
            register.update(buf);
            let table = tables[group as usize]
                .as_ref()
                .expect("a judged group has a table");
            if register.state() != table[usize::from(j)] {
                bad.push((group, j));
            }
        }
        Ok(bad)
    };

    let threads = hash_team(plan, slices.len() as u64, policy);
    let bad: Vec<(u64, u16)> = if threads > 1 {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            let run = slices.len().div_ceil(threads);
            let found: Vec<Result<Vec<(u64, u16)>>> =
                slices.par_chunks(run).with_max_len(1).map(&check).collect();
            let mut bad = Vec::new();
            for part in found {
                bad.extend(part?);
            }
            bad
        }
        #[cfg(not(feature = "parallel"))]
        unreachable!("no team without the parallel feature")
    } else {
        check(&slices)?
    };

    let mut by_group = vec![Vec::new(); tables.len()];
    for (group, j) in bad {
        by_group[group as usize].push(j);
    }
    Ok(by_group)
}

/// How many threads hash the slices: 1 without the parallel feature, and
/// otherwise the fewest of the policy's workers, the pool's width and one
/// per MiB of slices.
fn hash_team(plan: &rr5::Rr5Plan, slices: u64, policy: &MemoryPolicy) -> usize {
    #[cfg(feature = "parallel")]
    {
        let bytes = slices.saturating_mul(plan.shard_len.min(crate::recovery::rr5::GROUP_MAX));
        let by_work = usize::try_from(bytes / HASH_TEAM_MIN_PER_THREAD).unwrap_or(usize::MAX);
        policy
            .max_workers
            .min(rayon::current_num_threads())
            .min(by_work)
            .max(1)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (plan, slices, policy);
        1
    }
}

/// The volume on its way to `out`, each rebuilt slice in its place.
struct Repaired<'s> {
    src: &'s dyn RangeSource,
    volume: u64,
    /// How much of the volume has been written.
    at: u64,
    buf: Vec<u8>,
}

impl<'s> Repaired<'s> {
    fn new(src: &'s dyn RangeSource) -> Repaired<'s> {
        Repaired {
            src,
            volume: length(src),
            at: 0,
            buf: vec![0u8; COPY_BLOCK],
        }
    }

    /// Copy the volume up to `until`.
    fn copy_to(&mut self, until: u64, out: &mut dyn Write) -> Result<()> {
        while self.at < until {
            let want = (until - self.at).min(COPY_BLOCK as u64) as usize;
            let got = read_at_most(self.src, self.at, &mut self.buf[..want])?;
            if got == 0 {
                break;
            }
            out.write_all(&self.buf[..got]).map_err(Error::caller)?;
            self.at += got as u64;
        }
        Ok(())
    }

    /// Write the volume through the last of `patches`, which are in
    /// volume order and after everything written so far.
    fn through(&mut self, patches: &[Patch], out: &mut dyn Write) -> Result<()> {
        for patch in patches {
            self.copy_to(patch.at.min(self.volume), out)?;
            if self.at != patch.at {
                // The source ended short of the patch: nothing after
                // this point is the record's to place.
                break;
            }
            out.write_all(&patch.bytes).map_err(Error::caller)?;
            self.at += patch.bytes.len() as u64;
        }
        Ok(())
    }

    /// Everything past the last patch.
    fn finish(mut self, out: &mut dyn Write) -> Result<()> {
        self.copy_to(self.volume, out)
    }
}
