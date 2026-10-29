//! One stripe engine for both RAR 5 repairs (spec L 3.8).
//!
//! Inline records and `.rev` sets differ only in what a "shard" is - a
//! group's slice of the protected prefix, or a whole data volume - so the
//! solve, the memory bound and the parallel gate are written once here and
//! driven by two callers.
//!
//! Never holds a whole shard grid. For a stripe of `w` bytes, each intact
//! source's stripe is read once and folded into the `d` accumulators of the
//! missing shards; the `d x d` system is inverted ONCE, outside the stripe
//! loop, and applied per stripe. Working memory is `(2d + 2) w` plus the
//! plan, which depends on the damage count and never on the size of the
//! set.

#[cfg(feature = "parallel")]
use crate::carry::g_recovery::recovery::rar5::RECOVER_FOLD_CHUNK;
use crate::carry::g_recovery::recovery::rar5::{MAX_STRIPE_PLAN_CELLS, MIN_STRIPE_LEN};
use crate::memory::MemoryPolicy;
use crate::recovery::gf16::{cauchy_cell, solve, Coefficient};
use crate::{Error, ErrorKind, RecoveryFailure, Resource, Result};

/// Fills `buf` with data shard `j` from `at`, zero-padded past its real
/// bytes. Called only for intact shards.
pub(crate) type ReadShard<'a> = dyn FnMut(u16, u64, &mut [u8]) -> Result<()> + 'a;
/// The same for the parity of equation `e`.
pub(crate) type ReadParity<'a> = dyn FnMut(usize, u64, &mut [u8]) -> Result<()> + 'a;
/// Receives shard `damaged[t]`'s rebuilt stripe, in order.
pub(crate) type Emit<'a> = dyn FnMut(usize, u64, &[u8]) -> Result<()> + 'a;

/// [`ReadShard`] for [`Rebuild::run_wide`]: called from many threads at
/// once, each for a piece of its own.
#[cfg(feature = "parallel")]
pub(crate) type ReadShardWide<'a> = dyn Fn(u16, u64, &mut [u8]) -> Result<()> + Sync + 'a;
/// [`ReadParity`] for [`Rebuild::run_wide`], under the same terms.
#[cfg(feature = "parallel")]
pub(crate) type ReadParityWide<'a> = dyn Fn(usize, u64, &mut [u8]) -> Result<()> + Sync + 'a;
/// Receives every rebuilt shard's stripe at once, in order: the stripe's
/// offset, one row per damaged shard, and how many bytes of each row are
/// the stripe.
#[cfg(feature = "parallel")]
pub(crate) type EmitWide<'a> = dyn FnMut(u64, &[Vec<u8>], usize) -> Result<()> + 'a;

/// Bytes one task of [`Rebuild::run_wide`] reads, folds and solves at a
/// time. Even, as a symbol is two bytes; small enough that a task's
/// source piece and its accumulators stay in a core's own cache.
#[cfg(feature = "parallel")]
const WIDE_CHUNK: usize = 256 * 1024;
/// The longest stripe [`Rebuild::run_wide`] takes. Its output rows are
/// used again stripe after stripe, so a longer one buys no speed and
/// costs pages.
#[cfg(feature = "parallel")]
const WIDE_STRIPE: u64 = 16 << 20;
/// How many coefficients [`Rebuild::run_wide`] builds once and keeps for
/// the whole run, about a kilobyte each. A plan with more builds each
/// where it is used, as [`Rebuild::run`] does.
#[cfg(feature = "parallel")]
const WIDE_READY_CELLS: usize = 4096;

/// A validated plan for rebuilding `damaged` shards from `rows`.
#[derive(Debug)]
pub(crate) struct Rebuild {
    k: u16,
    /// Data shard indices to rebuild, ascending.
    damaged: Vec<u16>,
    /// One recovery row per damaged shard, in the order the inverse
    /// expects; distinct.
    rows: Vec<u16>,
    /// `inverse[t][e]`: shard `damaged[t]`'s share of equation `e`.
    inverse: Vec<Vec<u16>>,
    /// Bytes each shard is addressed against.
    shard_len: u64,
}

impl Rebuild {
    /// Build and invert the system. `rows` must be at least as long as
    /// `damaged`; the first `damaged.len()` are used.
    pub(crate) fn new(k: u16, shard_len: u64, damaged: &[u16], rows: &[u16]) -> Result<Rebuild> {
        let d = damaged.len();
        if d == 0 {
            return Err(Error::new(ErrorKind::Recovery(RecoveryFailure::NoRecord)));
        }
        if rows.len() < d {
            return Err(Error::new(ErrorKind::Recovery(
                RecoveryFailure::TooManyMissing {
                    missing: d as u32,
                    available: rows.len() as u32,
                },
            )));
        }
        let cells = (d as u64).saturating_mul(u64::from(k));
        if cells > MAX_STRIPE_PLAN_CELLS as u64 {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::RepairWork,
                needed: cells * 2,
                limit: MAX_STRIPE_PLAN_CELLS as u64 * 2,
            }));
        }
        let rows: Vec<u16> = rows[..d].to_vec();
        // The system: equation `e` is recovery row `rows[e]`, restricted to
        // the missing columns. A Cauchy submatrix is always invertible, so
        // a singular one here means the records disagree about the code and
        // the recovery data, not the volume, is what is damaged.
        let mut matrix: Vec<Vec<u16>> = rows
            .iter()
            .map(|&row| damaged.iter().map(|&j| cauchy_cell(k, row, j)).collect())
            .collect();
        let mut identity: Vec<Vec<u8>> = (0..d)
            .map(|e| {
                let mut row = vec![0u8; 2 * d];
                row[2 * e..2 * e + 2].copy_from_slice(&1u16.to_le_bytes());
                row
            })
            .collect();
        solve(&mut matrix, &mut identity, 2 * d)
            .ok_or_else(|| Error::new(ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged)))?;
        // `identity` now holds the inverse by rows: row `t` of it is
        // shard `damaged[t]`'s share of each equation in turn, which is
        // exactly what the fold below applies.
        let inverse = (0..d)
            .map(|t| {
                (0..d)
                    .map(|e| u16::from_le_bytes([identity[t][2 * e], identity[t][2 * e + 1]]))
                    .collect()
            })
            .collect();
        Ok(Rebuild {
            k,
            damaged: damaged.to_vec(),
            rows,
            inverse,
            shard_len,
        })
    }

    /// Bytes this plan reserves for a stripe of `stripe_len`: one
    /// right-hand-side row and one output row per damaged shard, plus a
    /// read buffer and the source stripe being folded.
    pub(crate) fn working_bytes(&self, stripe_len: u64) -> u64 {
        (2 * self.damaged.len() as u64 + 2) * stripe_len
    }

    /// The longest stripe `policy` affords, even and at least
    /// [`MIN_STRIPE_LEN`]. A budget too small for even that is
    /// [`Resource::RepairWork`], reported before any payload is read.
    pub(crate) fn stripe_len(&self, policy: &MemoryPolicy) -> Result<u64> {
        let rows = 2 * self.damaged.len() as u64 + 2;
        let floor = MIN_STRIPE_LEN as u64;
        if policy.repair_limit < rows * floor && self.shard_len > floor {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::RepairWork,
                needed: rows * floor,
                limit: policy.repair_limit,
            }));
        }
        // Capped at what this target can address as well as at what the
        // policy budgets. `MemoryPolicy`'s fields are public, so a caller
        // may raise `repair_limit` past a 32-bit address space; the stripe
        // buffers below are sized by this figure through a narrowing cast,
        // and a truncated stripe length would rebuild the wrong bytes
        // rather than refuse. On a 64-bit target `usize::MAX` is
        // `u64::MAX` and this `min` is the identity.
        let afford = (policy.repair_limit / rows)
            .max(floor)
            .min(usize::MAX as u64);
        Ok((afford.min(self.shard_len).max(2)) & !1)
    }

    /// Rebuild every damaged shard, a stripe at a time.
    ///
    /// `read_shard(j, at, buf)` fills `buf` with data shard `j` from `at`,
    /// zero-padded past its real bytes; it is called only for intact
    /// shards. `read_parity(e, at, buf)` does the same for the parity of
    /// equation `e`. `emit(t, at, bytes)` receives shard `damaged[t]`'s
    /// rebuilt stripe.
    pub(crate) fn run(
        &self,
        stripe_len: u64,
        policy: &MemoryPolicy,
        read_shard: &mut ReadShard<'_>,
        read_parity: &mut ReadParity<'_>,
        emit: &mut Emit<'_>,
    ) -> Result<()> {
        let d = self.damaged.len();
        // `stripe_len` comes from `Rebuild::stripe_len`, which caps it at
        // both the repair budget and `usize::MAX`, so this is exact on any
        // pointer width.
        let w = stripe_len as usize;
        let mut accumulator = vec![vec![0u8; w]; d];
        let mut output = vec![vec![0u8; w]; d];
        let mut source = vec![0u8; w];
        // One table per equation for the shard being folded, rebuilt once
        // per (source, stripe pass) and never per symbol.
        let mut coefficients: Vec<Coefficient> = Vec::with_capacity(d);

        let mut at = 0u64;
        while at < self.shard_len {
            let len = (self.shard_len - at).min(stripe_len) as usize;
            for row in accumulator.iter_mut() {
                row[..len].fill(0);
            }
            for j in 0..self.k {
                if self.damaged.binary_search(&j).is_ok() {
                    continue;
                }
                read_shard(j, at, &mut source[..len])?;
                coefficients.clear();
                coefficients.extend(
                    self.rows
                        .iter()
                        .map(|&row| Coefficient::new(cauchy_cell(self.k, row, j))),
                );
                fold_into(&mut accumulator, &coefficients, &source[..len], len, policy);
            }
            // The equations' constant terms: parity XOR the intact side.
            for (e, row) in accumulator.iter_mut().enumerate() {
                read_parity(e, at, &mut source[..len])?;
                for (dst, src) in row[..len].iter_mut().zip(&source[..len]) {
                    *dst ^= *src;
                }
            }
            // Apply the inverse: shard t is the folded sum of the
            // equations, one coefficient each.
            for (t, out) in output.iter_mut().enumerate() {
                out[..len].fill(0);
                for (e, acc) in accumulator.iter().enumerate() {
                    let c = Coefficient::new(self.inverse[t][e]);
                    c.fold(&mut out[..len], &acc[..len]);
                }
            }
            for (t, out) in output.iter().enumerate() {
                emit(t, at, &out[..len])?;
            }
            at += len as u64;
        }
        Ok(())
    }
}

/// Coefficients built once for a run, or built where they are used when
/// there are too many to keep.
#[cfg(feature = "parallel")]
struct Ready(Option<Vec<Coefficient>>);

#[cfg(feature = "parallel")]
impl Ready {
    fn of(cells: usize, value: impl Fn(usize) -> u16) -> Ready {
        Ready(
            (cells <= WIDE_READY_CELLS)
                .then(|| (0..cells).map(|i| Coefficient::new(value(i))).collect()),
        )
    }

    /// `dst ^= c * src` for cell `index`, whose value is `value`.
    fn fold(&self, index: usize, value: u16, dst: &mut [u8], src: &[u8]) {
        match &self.0 {
            Some(kept) => kept[index].fold(dst, src),
            None => Coefficient::new(value).fold(dst, src),
        }
    }
}

#[cfg(feature = "parallel")]
impl Rebuild {
    /// Whether [`Rebuild::run_wide`] is the walk for this plan under
    /// `policy`, and then the stripe it takes and how many tasks it runs
    /// at once. `stripe_len` is [`Rebuild::stripe_len`]'s answer.
    ///
    /// The stripe is never longer than `stripe_len`, so
    /// [`Rebuild::working_bytes`] of it still bounds the walk: `d` output
    /// rows of a stripe, and for each task in flight a source piece and
    /// `d` accumulators of [`WIDE_CHUNK`], which with a stripe of at
    /// least `d + 1` pieces is no more than the `d + 2` stripes left.
    pub(crate) fn wide_team(&self, stripe_len: u64, policy: &MemoryPolicy) -> Option<(u64, usize)> {
        let threads = policy.max_workers.min(rayon::current_num_threads());
        let stripe = stripe_len.min(WIDE_STRIPE);
        let floor = (self.damaged.len() as u64 + 1) * WIDE_CHUNK as u64;
        (threads > 1 && stripe >= floor).then_some((stripe, threads))
    }

    /// [`Rebuild::run`] across the pool: the same bytes, by another walk.
    ///
    /// A stripe is cut into pieces of [`WIDE_CHUNK`], and one task does
    /// the whole of a piece: it reads that piece of every intact shard
    /// and folds it into its own accumulators, takes in the parity, and
    /// applies the inverse into the output rows. So the reads, the folds
    /// and the solve all run `threads` wide, and no task shares a buffer
    /// with another. At most `threads` tasks are in flight.
    pub(crate) fn run_wide(
        &self,
        stripe_len: u64,
        threads: usize,
        read_shard: &ReadShardWide<'_>,
        read_parity: &ReadParityWide<'_>,
        emit: &mut EmitWide<'_>,
    ) -> Result<()> {
        use rayon::prelude::*;
        let d = self.damaged.len();
        let w = stripe_len as usize;
        let intact: Vec<u16> = (0..self.k)
            .filter(|j| self.damaged.binary_search(j).is_err())
            .collect();
        // Cell `s * d + e`: intact shard `intact[s]`'s share of equation
        // `e`. Cell `t * d + e` of the inverse: as `self.inverse`.
        let share = |i: usize| cauchy_cell(self.k, self.rows[i % d], intact[i / d]);
        let solved = |i: usize| self.inverse[i / d][i % d];
        let shares = Ready::of(intact.len() * d, share);
        let inverse = Ready::of(d * d, solved);

        let tasks = threads.min(w.div_ceil(WIDE_CHUNK)).max(1);
        let piece = WIDE_CHUNK.min(w);
        let mut scratch: Vec<(Vec<u8>, Vec<Vec<u8>>)> = (0..tasks)
            .map(|_| (vec![0u8; piece], vec![vec![0u8; piece]; d]))
            .collect();
        let mut output = vec![vec![0u8; w]; d];

        let mut at = 0u64;
        while at < self.shard_len {
            let len = (self.shard_len - at).min(stripe_len) as usize;
            {
                // Piece `c` of the stripe, as one slice of each output row.
                let mut rows: Vec<_> = output
                    .iter_mut()
                    .map(|row| row[..len].chunks_mut(WIDE_CHUNK))
                    .collect();
                let mut pieces: Vec<Vec<&mut [u8]>> = (0..len.div_ceil(WIDE_CHUNK))
                    .map(|_| rows.iter_mut().filter_map(Iterator::next).collect())
                    .collect();
                for (run, team) in pieces.chunks_mut(tasks).enumerate() {
                    team.par_iter_mut()
                        .zip(scratch.par_iter_mut())
                        .enumerate()
                        .try_for_each(|(i, (outs, (source, accumulator)))| -> Result<()> {
                            let from = at + ((run * tasks + i) * WIDE_CHUNK) as u64;
                            let n = outs[0].len();
                            for row in accumulator.iter_mut() {
                                row[..n].fill(0);
                            }
                            for (s, &j) in intact.iter().enumerate() {
                                read_shard(j, from, &mut source[..n])?;
                                for (e, row) in accumulator.iter_mut().enumerate() {
                                    let cell = s * d + e;
                                    shares.fold(cell, share(cell), &mut row[..n], &source[..n]);
                                }
                            }
                            // The equations' constant terms: parity XOR
                            // the intact side.
                            for (e, row) in accumulator.iter_mut().enumerate() {
                                read_parity(e, from, &mut source[..n])?;
                                for (dst, src) in row[..n].iter_mut().zip(&source[..n]) {
                                    *dst ^= *src;
                                }
                            }
                            for (t, out) in outs.iter_mut().enumerate() {
                                out.fill(0);
                                for (e, row) in accumulator.iter().enumerate() {
                                    let cell = t * d + e;
                                    inverse.fold(cell, solved(cell), out, &row[..n]);
                                }
                            }
                            Ok(())
                        })?;
                }
            }
            emit(at, &output, len)?;
            at += len as u64;
        }
        Ok(())
    }
}

/// Fold one source stripe into every accumulator.
///
/// The team engages only when each worker would get real work: the gate is
/// the window per thread, never a flat byte count (spec L section 7). With
/// the gate open the unit of work is a (equation, 64 KiB chunk) pair, so a
/// repair of a single missing shard still spreads across the pool.
fn fold_into(
    accumulator: &mut [Vec<u8>],
    coefficients: &[Coefficient],
    source: &[u8],
    len: usize,
    policy: &MemoryPolicy,
) {
    #[cfg(feature = "parallel")]
    {
        use crate::carry::g_recovery::recovery::rar5::striped_team_min_window_for;
        use rayon::prelude::*;
        let threads = policy.max_workers.min(rayon::current_num_threads());
        if threads > 1 && len >= striped_team_min_window_for(threads) {
            accumulator
                .par_iter_mut()
                .zip(coefficients.par_iter())
                .for_each(|(row, c)| {
                    row[..len]
                        .par_chunks_mut(RECOVER_FOLD_CHUNK)
                        .enumerate()
                        .for_each(|(index, dst)| {
                            let at = index * RECOVER_FOLD_CHUNK;
                            c.fold(dst, &source[at..at + dst.len()]);
                        });
                });
            return;
        }
    }
    let _ = policy;
    for (row, c) in accumulator.iter_mut().zip(coefficients) {
        c.fold(&mut row[..len], source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::gf16::field;

    fn policy(repair_limit: u64, max_workers: usize) -> MemoryPolicy {
        MemoryPolicy {
            working_limit: 1 << 30,
            max_window: 1 << 30,
            max_dictionary: 1 << 20,
            repair_limit,
            read_ahead: 1 << 20,
            max_workers,
            ..MemoryPolicy::from_limit(1 << 30)
        }
    }

    /// Encode `k` shards into `m` Cauchy rows, knock some out, and rebuild.
    fn round_trip(k: u16, m: u16, shard_len: usize, damaged: &[u16], stripe: u64, workers: usize) {
        let mut x: u32 = 0x1234_5678;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        };
        let shards: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..shard_len).map(|_| next()).collect())
            .collect();
        let gf = field();
        let parity: Vec<Vec<u8>> = (0..m)
            .map(|row| {
                let mut out = vec![0u8; shard_len];
                for (j, shard) in shards.iter().enumerate() {
                    let c = cauchy_cell(k, row, j as u16);
                    let (left, _) = out.as_chunks_mut::<2>();
                    let (right, _) = shard.as_chunks::<2>();
                    for (d, s) in left.iter_mut().zip(right) {
                        *d = (gf.mul(c, u16::from_le_bytes(*s)) ^ u16::from_le_bytes(*d))
                            .to_le_bytes();
                    }
                }
                out
            })
            .collect();
        let rows: Vec<u16> = (0..damaged.len() as u16).collect();
        let plan = Rebuild::new(k, shard_len as u64, damaged, &rows).unwrap();
        let mut rebuilt = vec![vec![0u8; shard_len]; damaged.len()];
        plan.run(
            stripe,
            &policy(1 << 30, workers),
            &mut |j, at, buf| {
                buf.copy_from_slice(&shards[usize::from(j)][at as usize..at as usize + buf.len()]);
                Ok(())
            },
            &mut |e, at, buf| {
                let row = usize::from(rows[e]);
                buf.copy_from_slice(&parity[row][at as usize..at as usize + buf.len()]);
                Ok(())
            },
            &mut |t, at, bytes| {
                rebuilt[t][at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
        for (t, &j) in damaged.iter().enumerate() {
            assert_eq!(rebuilt[t], shards[usize::from(j)], "shard {j}");
        }
        // The wide walk, where the plan and the pool give it a team: the
        // same bytes.
        #[cfg(feature = "parallel")]
        if let Some((wide, team)) = plan.wide_team(stripe, &policy(1 << 30, workers)) {
            let mut again = vec![vec![0u8; shard_len]; damaged.len()];
            plan.run_wide(
                wide,
                team,
                &|j, at, buf| {
                    buf.copy_from_slice(
                        &shards[usize::from(j)][at as usize..at as usize + buf.len()],
                    );
                    Ok(())
                },
                &|e, at, buf| {
                    let row = usize::from(rows[e]);
                    buf.copy_from_slice(&parity[row][at as usize..at as usize + buf.len()]);
                    Ok(())
                },
                &mut |at, stripes, len| {
                    for (t, bytes) in stripes.iter().enumerate() {
                        again[t][at as usize..at as usize + len].copy_from_slice(&bytes[..len]);
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(again, rebuilt, "the wide walk");
        }
    }

    /// Needs a pool two threads wide to say anything, and 20 MB.
    #[test]
    fn the_wide_walk_gives_the_same_bytes_as_the_stripe_walk() {
        // Two stripes and a part of a third, the last piece short.
        round_trip(6, 3, 2_200_002, &[1, 4], 1 << 20, 4);
        // One shard, and a stripe of exactly two pieces.
        round_trip(5, 2, 1_048_576, &[3], 512 * 1024, 2);
    }

    #[test]
    fn rebuilds_one_shard() {
        round_trip(8, 2, 4096, &[3], 4096, 1);
    }

    #[test]
    fn rebuilds_every_shard_it_has_rows_for() {
        round_trip(12, 4, 2048, &[0, 5, 11], 2048, 1);
        round_trip(12, 4, 2048, &[0, 1, 2, 3], 2048, 1);
    }

    #[test]
    fn striping_does_not_change_the_answer() {
        for stripe in [2u64, 64, 1000, 4096] {
            round_trip(10, 3, 4096, &[2, 7], stripe, 1);
        }
    }

    #[test]
    fn the_team_gives_the_same_bytes_as_the_calling_thread() {
        // Past the per-thread gate, so the parallel arm actually runs.
        round_trip(6, 2, 16 << 20, &[1, 4], 16 << 20, 8);
    }

    #[test]
    fn refuses_a_budget_below_the_minimum_stripe() {
        let plan = Rebuild::new(8, 1 << 20, &[1, 2], &[0, 1]).unwrap();
        let err = plan.stripe_len(&policy(1024, 1)).unwrap_err();
        assert!(matches!(
            err.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::RepairWork,
                ..
            }
        ));
        // A shard shorter than the floor always fits.
        let small = Rebuild::new(8, 512, &[1], &[0]).unwrap();
        assert_eq!(small.stripe_len(&policy(1024, 1)).unwrap(), 512);
    }

    #[test]
    fn refuses_more_damage_than_rows() {
        let err = Rebuild::new(8, 1024, &[1, 2, 3], &[0]).unwrap_err();
        assert!(matches!(
            err.kind(),
            ErrorKind::Recovery(RecoveryFailure::TooManyMissing {
                missing: 3,
                available: 1
            })
        ));
    }
}
