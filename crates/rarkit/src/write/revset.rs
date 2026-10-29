//! Writing a volume set together with its `.rev` recovery volumes in one
//! call (spec G 3.11's last paragraph, SPEC-L 3.6, SPEC-API 7.4).
//!
//! **Why this is not just `rev5::create`.** Recovery volumes are parity
//! ACROSS the finished data volumes: row `i` of a Cauchy code over every
//! volume of the set, and the header of each `.rev` file carries a table
//! of every data volume's length and CRC32 (SPEC-L 3.6.1). So no `.rev`
//! byte can be produced until the LAST data volume exists, while
//! [`Writer::finish_volumes`] streams each volume and keeps none of them.
//! A caller wanting both had to write the set, keep the volumes itself,
//! build sources over them and call [`rev5::create`] - which is exactly
//! what the `rv` command and the `-rv` switch need, and what nothing in
//! the public API did for them.
//!
//! [`Writer::finish_volumes_with_recovery`] closes that: it writes the
//! set, asks the provider for each finished volume back, and writes the
//! recovery volumes. Spec G 3.11's obligation on the writer - that the
//! volumes it produces are ones `rev5::create` can cover - is then
//! checked by the call itself rather than left to the caller.
//!
//! **The one designed difference from the reference.** SPEC-L 3.6.2: the
//! format has no set identifier, so two `.rev` files belong to one set
//! when their whole data-volume table matches. Nothing here is derived
//! from a clock, and a set written twice from the same volumes is
//! byte-identical.

use std::sync::Arc;

use crate::error::{Error, ErrorKind, RecoveryFailure};
use crate::rev5::{self, RevOptions, RevReport};
use crate::source::RangeSource;
use crate::write::{VolumeOut, WriteReport, Writer};
use crate::Result;

/// How many `.rev` recovery volumes to write for a set (SPEC-L 3.6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevCount {
    /// What the reference's `rv` with no number gives: 10 percent of the
    /// data volume count, rounded up ([`rev5::default_count`]).
    #[default]
    Default,
    /// A percentage of the data volume count, rounded up
    /// ([`rev5::count_for_percent`]). This is the reference's `-rv<n>%`.
    Percent(u32),
    /// Exactly this many, which is the reference's `rv<n>`.
    Exactly(u32),
}

impl RevCount {
    /// The count this policy comes to for a set of `data_volumes`.
    ///
    /// Zero is not a count: a policy that rounds to nothing is refused
    /// rather than quietly writing no recovery at all, because a caller
    /// who asked for recovery and got none has been told the opposite of
    /// the truth.
    pub fn resolve(self, data_volumes: u32) -> Result<u32> {
        let count = match self {
            RevCount::Default => rev5::default_count(data_volumes),
            RevCount::Percent(percent) => rev5::count_for_percent(data_volumes, percent),
            RevCount::Exactly(count) => count,
        };
        if count == 0 || count > rev5::max_count(data_volumes) {
            return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
        }
        Ok(count)
    }
}

/// A volume provider that can hand a FINISHED volume back to be read.
///
/// [`VolumeOut`] is a one-way street: it gives the writer somewhere to
/// put each volume and takes it back when it is full. Recovery volumes
/// need every data volume readable once the set is complete, so a
/// provider that wants them implements this as well - by keeping the
/// bytes, as [`Vec<Vec<u8>>`] does, or by reopening the file it wrote.
pub trait VolumeSet {
    /// Volume `index` (0-based, in set order) as a readable source.
    ///
    /// Called only after the whole set is written, once per volume per
    /// pass, and the engine makes several passes over a large set
    /// (SPEC-L 3.6.3's windowed solve), so a provider backed by files
    /// should reopen rather than hold them all in memory.
    fn finished_volume(&self, index: u32) -> Result<Arc<dyn RangeSource>>;
}

/// Keeps every volume in memory, so it can hand them straight back.
impl VolumeSet for Vec<Vec<u8>> {
    fn finished_volume(&self, index: u32) -> Result<Arc<dyn RangeSource>> {
        match self.get(index as usize) {
            Some(bytes) => Ok(Arc::new(bytes.clone()) as Arc<dyn RangeSource>),
            None => Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord))),
        }
    }
}

impl<'a> Writer<'a> {
    /// Write a volume set and its `.rev` recovery volumes in one call.
    ///
    /// The data volumes go to `out` exactly as
    /// [`Writer::finish_volumes`] writes them, and the recovery volumes
    /// then go to `rev` in row order, so `rev`'s volume 0 is the file the
    /// reference names `<base>.part1.rev` (SPEC-L 3.6.4: the caller
    /// names the files).
    ///
    /// `recovery` is the count policy; a set of one data volume cannot
    /// carry recovery volumes and is refused, as is a policy that rounds
    /// to none.
    ///
    /// The volumes are read back through [`VolumeSet`] after the set is
    /// complete, because a `.rev` file's parity and its table both cover
    /// every data volume of the set.
    pub fn finish_volumes_with_recovery<O, R>(
        self,
        out: &mut O,
        rev: &mut R,
        recovery: RevCount,
        options: &RevOptions,
    ) -> Result<(WriteReport, RevReport)>
    where
        O: VolumeOut + VolumeSet,
        R: VolumeOut,
    {
        let report = self.finish_volumes(out)?;
        let count = recovery.resolve(report.volumes)?;
        let data: Vec<Arc<dyn RangeSource>> = (0..report.volumes)
            .map(|index| out.finished_volume(index))
            .collect::<Result<Vec<_>>>()?;
        let rev_report = rev5::create(&data, count, options, rev)?;
        Ok((report, rev_report))
    }
}
