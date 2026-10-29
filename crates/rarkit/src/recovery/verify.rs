//! Say what a RAR 5 inline record finds wrong with a volume before any of
//! it is mended, and mend only what can be (spec L 3.8).
//!
//! Spec L 3.8 decides damage group by group: a data slice whose CRC-64 no
//! longer matches its record's table entry is damaged, and a group is
//! recoverable when its damaged slices are no more numerous than its
//! surviving rows. `repair_inline` answers that question all at once and
//! refuses the whole volume when one group fails it. A caller that has to
//! REPORT each damaged slice, or keep the groups that did mend, needs the
//! answer per group, and this is where it gets it.

use std::io::Write;

use crate::checksum::crc64::Crc64Register;
use crate::recovery::io::read_exact_at;
use crate::recovery::rr5;
use crate::recovery::scan::{self, slice, Found};
use crate::rev5::RepairReport;
use crate::{RangeSource, ReadOptions, Result};

/// What a volume's RAR 5 inline record says of it, group by group.
///
/// Returned by [`check_inline`] and handed back to [`repair_checked`],
/// which mends from the same scan rather than repeating it.
#[derive(Clone, Debug)]
pub struct InlineCheck {
    /// Protected bytes, `P`: the file from byte 0 up to the record's own
    /// header, any bytes before the signature included (spec L 3.5.1).
    /// Only these are ever mended.
    pub protected: u64,
    /// Shard length in bytes, `G`.
    pub shard_len: u64,
    /// Data shards, `k`.
    pub shards: u16,
    /// Recovery rows the record was written with, `m`. A group whose
    /// [`GroupCheck::rows`] is fewer has lost rows to damage inside the
    /// record itself.
    pub rows: u16,
    /// Every group, in order.
    pub groups: Vec<GroupCheck>,
    found: Found,
}

/// One group of an [`InlineCheck`]: the same window of every shard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupCheck {
    /// Where the group's window starts inside a shard (65,536 per group).
    pub offset: u64,
    /// The window's length in bytes.
    pub len: u64,
    /// Distinct recovery rows that survive for this group. A group with
    /// none has no table to check against, so `damaged` is empty for it
    /// because nothing is KNOWN, not because nothing is wrong.
    pub rows: u16,
    /// The shards whose slice in this window no longer matches, ascending.
    pub damaged: Vec<u16>,
}

impl GroupCheck {
    /// Whether the rows that survive can rebuild every damaged slice.
    pub fn recoverable(&self) -> bool {
        self.damaged.len() <= usize::from(self.rows)
    }
}

impl InlineCheck {
    /// Where slice `shard` of group `group` starts in the volume.
    pub fn slice_offset(&self, shard: u16, group: usize) -> u64 {
        u64::from(shard) * self.shard_len + self.groups[group].offset
    }
}

/// Find `src`'s RAR 5 inline record and check every data slice against it,
/// repairing nothing.
///
/// A volume with no RAR 5 record is [`crate::RecoveryFailure::NoRecord`];
/// the RAR 4 family's records are not read here.
pub fn check_inline(src: &dyn RangeSource, opts: &ReadOptions) -> Result<InlineCheck> {
    let found = scan::scan(src, &opts.memory)?;
    let plan = &found.plan;
    let mut groups = Vec::with_capacity(plan.group_count as usize);
    for group in 0..plan.group_count {
        let len = plan.group_len(group);
        let rows = found.rows_for(group);
        let mut damaged = Vec::new();
        if let Some(&first) = rows.first() {
            let table = rr5::read_table(
                src,
                found
                    .record(first, group)
                    .expect("a surviving row has its record"),
            )?;
            let mut scratch = vec![0u8; len as usize];
            for j in 0..plan.k {
                let (at, real) = slice(plan, j, group);
                let buf = &mut scratch[..real as usize];
                if !buf.is_empty() {
                    read_exact_at(src, at, buf)?;
                }
                let mut register = Crc64Register::new();
                register.update(buf);
                if register.state() != table[usize::from(j)] {
                    damaged.push(j);
                }
            }
        }
        groups.push(GroupCheck {
            offset: group * rr5::GROUP_MAX,
            len,
            rows: rows.len() as u16,
            damaged,
        });
    }
    Ok(InlineCheck {
        protected: plan.protected,
        shard_len: plan.shard_len,
        shards: plan.k,
        rows: plan.m,
        groups,
        found,
    })
}

/// Write `src` to `out` with every RECOVERABLE group of `check` mended and
/// every other byte copied as it stands.
///
/// This is `repair_inline` with one difference: a group with more damage
/// than rows is left alone instead of failing the volume, so the groups
/// that can mend still do. `check` must come from [`check_inline`] over
/// the same `src`.
pub fn repair_checked(
    src: &dyn RangeSource,
    check: &InlineCheck,
    opts: &ReadOptions,
    out: &mut dyn Write,
) -> Result<RepairReport> {
    let mut found = check.found.clone();
    // A group with no records is one `inline::repair` skips, which is
    // exactly what an unrecoverable group has to be here.
    found
        .records
        .retain(|record| check.groups[record.group as usize].recoverable());
    crate::recovery::inline::repair(src, &found, &opts.memory, out)
}
