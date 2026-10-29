//! The tree walk's probe: one member walked by a named count of walkers,
//! for the gate bench to time. `bench-internals` alone.

use super::*;

/// A lab probe over the tree's walk ALONE: no parse, no entropy coder.
///
/// It drives exactly the scheduling [`Engine::with_tree`] drives - the
/// same chunking, the same deal, the same walkers - and times each piece
/// separately, so a scaling figure can be attributed rather than guessed
/// at. Behind `bench-internals`; nothing shipped reaches it.
#[cfg(all(feature = "bench-internals", feature = "parallel"))]
#[derive(Default, Clone)]
pub struct WalkProbe {
    /// Wall seconds for the whole walk of the span.
    pub wall: f64,
    /// Seconds the walkers were busy, summed over every walker.
    pub busy: f64,
    /// Summed over chunks: the busiest walker of each.
    pub chunk_max: f64,
    /// Summed over chunks: the mean walker of each.
    pub chunk_mean: f64,
    /// Seconds spent dealing positions to the walkers.
    pub deal: f64,
    /// The longest share any one walker was dealt in any one chunk, and
    /// the mean share over all walkers and chunks.
    pub share_max: usize,
    pub share_mean: f64,
    /// How many chunks were walked.
    pub chunks: usize,
    /// Summed over chunks: the positions of the single busiest BUCKET,
    /// which no assignment of buckets to walkers can split. This is the
    /// floor on what balancing the deal could ever reach.
    pub bucket_max: usize,
    /// Summed over chunks: the makespan a longest-processing-time-first
    /// assignment of the chunk's buckets to `walkers` bins would give,
    /// counting positions. What a balanced deal would cost.
    pub lpt: usize,
    /// Summed over chunks: the chunk's positions.
    pub positions: usize,
    /// A digest of every hint the walk left, so two deals can be compared
    /// for having walked to the same answers without a caller holding two
    /// hint buffers of the span.
    pub digest: u64,
}

/// Walk `span` with `walkers` walkers and report where the time went.
/// See [`WalkProbe`].
#[cfg(all(feature = "bench-internals", feature = "parallel"))]
pub fn walk_probe(
    span: &[u8],
    dictionary: usize,
    walkers: usize,
    stride: usize,
    bins_per_walker: usize,
) -> WalkProbe {
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    let mut tree = BucketTrees::new(dictionary);
    let group = WALK_BLOCKS * PARSE_BLOCK_BYTES;
    let hints = empty_slots(group * stride);
    let busy: Vec<AtomicU64> = (0..walkers).map(|_| AtomicU64::new(0)).collect();
    let mut probe = WalkProbe::default();
    let mut digest = 0xcbf2_9ce4_8422_2325u64;
    let mut shares = crate::carry::h_ours::codec::rar50::tree::Deal::default();
    let bins = walkers * bins_per_walker;
    let mut offer: Vec<usize> = Vec::new();
    let started = Instant::now();
    let mut at = 0;
    while at < span.len() {
        let end = (at + group).min(span.len());
        for slot in &hints[..(end - at) * stride] {
            slot.store(0, Ordering::Relaxed);
        }
        // The same chunking `advance_range` uses, dealt and walked here so
        // each piece can be timed on its own.
        let mut chunk_at = at;
        while chunk_at < end {
            let chunk = chunk_at..(chunk_at + TREE_SKEW_BOUND).min(end);
            let dealt = Instant::now();
            tree.share_chunk(span, chunk.clone(), bins, &mut shares);
            probe.deal += dealt.elapsed().as_secs_f64();
            for bin in 0..shares.bins() {
                let share = shares.bin(bin);
                probe.share_max = probe.share_max.max(share.len());
                probe.share_mean += share.len() as f64;
            }
            {
                // What the deal COULD have been: the chunk's positions by
                // bucket, biggest first into the emptiest bin.
                let mut counts = std::collections::HashMap::new();
                for pos in chunk.clone() {
                    if pos + 4 > span.len() {
                        break;
                    }
                    let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
                    let bucket = (word.wrapping_mul(0x9E37_79B1) >> tree.bucket_shift) as usize;
                    *counts.entry(bucket).or_insert(0usize) += 1;
                    probe.positions += 1;
                }
                let mut sizes: Vec<usize> = counts.into_values().collect();
                sizes.sort_unstable_by(|a, b| b.cmp(a));
                probe.bucket_max += sizes.first().copied().unwrap_or(0);
                let mut bins = vec![0usize; walkers];
                for size in sizes {
                    let least = bins.iter().enumerate().min_by_key(|(_, b)| **b).unwrap().0;
                    bins[least] += size;
                }
                probe.lpt += bins.iter().copied().max().unwrap_or(0);
            }
            for slot in &busy {
                slot.store(0, Ordering::Relaxed);
            }
            offer.clear();
            offer.extend(0..shares.bins());
            let sizes: Vec<usize> = (0..shares.bins())
                .map(|bin| shares.bin(bin).len())
                .collect();
            offer.sort_unstable_by_key(|&bin| std::cmp::Reverse(sizes[bin]));
            let taken = std::sync::atomic::AtomicUsize::new(0);
            let finder = &tree;
            let hints = &hints;
            let busy = &busy;
            let shares_now = &shares;
            let offer_now = &offer;
            let taken = &taken;
            let skip = crate::carry::h_ours::codec::rar50::tree::skips_same_stores(walkers);
            rayon::in_place_scope(|scope| {
                for slot in busy.iter().take(walkers) {
                    scope.spawn(move |_| {
                        let ran = Instant::now();
                        loop {
                            let next = taken.fetch_add(1, Ordering::Relaxed);
                            let Some(&bin) = offer_now.get(next) else {
                                break;
                            };
                            let share = shares_now.bin(bin);
                            if share.is_empty() {
                                break;
                            }
                            finder.walk(span, share, &[end], at, Some(hints), stride, skip);
                        }
                        slot.store(ran.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    });
                }
            });
            let each: Vec<f64> = busy
                .iter()
                .map(|slot| slot.load(Ordering::Relaxed) as f64 / 1e9)
                .collect();
            probe.busy += each.iter().sum::<f64>();
            probe.chunk_max += each.iter().copied().fold(0.0, f64::max);
            probe.chunk_mean += each.iter().sum::<f64>() / walkers as f64;
            probe.chunks += 1;
            chunk_at = chunk.end;
        }
        for slot in &hints[..(end - at) * stride] {
            digest = digest
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(u64::from(slot.load(Ordering::Relaxed)));
        }
        tree.next = end;
        at = end;
    }
    probe.wall = started.elapsed().as_secs_f64();
    probe.digest = digest;
    probe.share_mean /= (probe.chunks * walkers).max(1) as f64;
    probe
}
