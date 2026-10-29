//! What an engine holds and will hold: the flight terms and the finders'
//! bytes the write engine's admission reads.

use super::*;

/// The distance the tree's ring is sized for, given the reach `needed`.
///
/// The parallel walk holds the tree's window [`TREE_SKEW_BOUND`] below its
/// ring, so a ring sized to the dictionary reaches 256 KiB less than the
/// dictionary: 1.75 MiB of a 2 MiB one, where the chains of levels 1 to 3
/// reach all 2 MiB. That band is not small. On 9,681 small members in a
/// solid set, ordered so that near copies sit 1 to 2 MiB apart, it made
/// level 5 write 14 per cent MORE than level 3 at 2 MiB, and level 5 won
/// by 8 per cent from 4 MiB up.
/// Up to [`TREE_FULL_REACH_MOST`] the ring is widened by the skew so that
/// the window is the whole dictionary; above it the lost band is at most
/// one sixteenth of the reach and doubling the ring would cost more
/// memory than the band is worth, so the ring stays the dictionary's.
///
/// **SOLID runs only** ([`Plan::wide_ring`]). A non-solid member's reach
/// is the member itself, and the worker team's crews, which encode only
/// non-solid members, size a READER member's run from the archive's
/// dictionary: widened there, every crew's tree doubled for nothing a
/// member of at most 256 KiB could reach. Counted untimed on an Apple M3 Mac
/// (small9k and one 20 MiB member, `-m5 -mt8`, `rarfast a`): peak RSS 301
/// to 482 MiB for 0.4 per cent of archive.
pub(super) fn tree_ring(needed: usize) -> usize {
    if needed <= TREE_FULL_REACH_MOST {
        needed + TREE_SKEW_BOUND
    } else {
        needed
    }
}

/// Whether a run of `plan` widens the tree's ring to the whole dictionary
/// without being solid: [`Plan::full_reach`], or in a bench build
/// `RARKIT_WIDE_RING=0` / `=1` to force it off or on for every tree plan,
/// which is how the reach is counted in one binary.
pub(super) fn full_reach(plan: Plan) -> bool {
    #[cfg(feature = "bench-internals")]
    {
        static FORCED: OnceLock<Option<bool>> = OnceLock::new();
        let forced = *FORCED.get_or_init(|| {
            std::env::var("RARKIT_WIDE_RING")
                .ok()
                .map(|value| value == "1")
        });
        if let Some(on) = forced {
            return on && plan.finder == Finder::Tree;
        }
    }
    plan.full_reach
}

impl Engine {
    /// What this engine's parses hold now, in bytes: SPEC-API 8.2's
    /// "one scratch per active walker" and "a wave's output buffers",
    /// which [`Engine::held_bytes`] and [`Engine::structure_bytes`] leave
    /// out. Each parse in flight keeps a scratch (a block's tokens at
    /// eight bytes a token, the optimal parse's window and the price
    /// model), the widest wave's block outputs are kept to be handed out
    /// again, and the tree's walkers keep their bins. All of it is kept
    /// between members, so it is resident for the whole run.
    pub(crate) fn flight_bytes(&self) -> u64 {
        let scratches: u64 = self
            .scratches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(Scratch::held_bytes)
            .sum();
        let outs: u64 = self
            .spare_outs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|out| out.capacity() as u64)
            .sum();
        let bins = self.tree.as_ref().map_or(0, BucketTrees::bins_bytes);
        #[cfg(feature = "parallel")]
        let build = self
            .build
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .held_bytes();
        #[cfg(not(feature = "parallel"))]
        let build = 0;
        scratches + outs + bins + build
    }

    /// The most [`Engine::flight_bytes`] reads once this engine has
    /// flushed `bytes` staged in one segment: a function of the plan, the
    /// hold and the pool's width, for a writer to charge before anything
    /// is built.
    ///
    /// A flush parses at most a wave's blocks at once, and at most as many
    /// as the pool has threads, each with its own scratch; every block of
    /// the wave keeps its output until the wave is appended. The tree's
    /// wave is its hints' width; the chains' is at most the held wave.
    pub(crate) fn flight_term(&self, bytes: usize) -> u64 {
        self.flight_term_over(bytes, bytes)
    }

    /// [`Engine::flight_term`] for a flush of `bytes` at the end of a run
    /// of `span` bytes, which is what the chains are sized from and what
    /// they wrap over: `bytes` itself for a fresh member encoded whole (a
    /// crew's), the history and the flush for a member encoded a window at
    /// a time (the writer's lead).
    ///
    /// The CHAINS' wave is what `Chains::wave_bytes` lets them parse at
    /// once, and a held wave ([`Engine::hold_wave`]) bounds it only where
    /// the chains' cyclic buffer is shorter than the span. Chains sized from
    /// a member shorter than their held ceiling never wrap, and there every
    /// block of the flush is parsed at once, held or not: counted 30 Sep
    /// 2026 on bin4g at `-m3`, a worker team's large crews, held to four
    /// blocks, held what eight cost. The charge
    /// follows what runs.
    pub(crate) fn flight_term_over(&self, bytes: usize, span: usize) -> u64 {
        // Where the level has another effort, the flush may be either
        // finder's, and the charge is the larger.
        let own = self.flight_term_by(self.own.finder, bytes, span);
        match self.own.other {
            Some(other) => own.max(self.flight_term_by(other.finder, bytes, span)),
            None => own,
        }
    }

    /// [`Engine::flight_term_over`] for a flush walked by `finder`.
    pub(super) fn flight_term_by(&self, finder: Finder, bytes: usize, span: usize) -> u64 {
        let blocks = bytes.div_ceil(PARSE_BLOCK_BYTES).max(1);
        let (width, parses) = match finder {
            Finder::Tree => {
                let width = self.hint_width(self.tree_effort().candidates, blocks, 1);
                (width, width.min(threads()).min(self.parses))
            }
            Finder::Chain => {
                let span = span.max(bytes);
                let wave = Chains::wave_for(self.dictionary, span, self.wave, span);
                // Held as `Engine::with_chains` holds it.
                let width = blocks
                    .min(wave / PARSE_BLOCK_BYTES)
                    .max(1)
                    .min(self.chain_width);
                (width, width.min(threads()))
            }
        };
        #[cfg(feature = "parallel")]
        let build = match finder {
            Finder::Chain if self.chain_builders(width) > 1 => {
                Build::most_bytes(self.chain_builders(width))
            }
            _ => 0,
        };
        #[cfg(not(feature = "parallel"))]
        let build = 0;
        let optimal = if self.own.parses_optimally() {
            OptimalScratch::most_bytes()
        } else {
            0
        };
        // A block is at most the flush, so a flush shorter than a block
        // holds no more tokens and output than it has bytes.
        let block = bytes.clamp(1, PARSE_BLOCK_BYTES);
        let scratch = (block * std::mem::size_of::<Token>() + PARSE_TABLES_MOST) as u64 + optimal;
        // The walk deals a group across walkers only from
        // `WALK_ALONE_BYTES` up (`Engine::with_tree`), and a deal holds at
        // most one chunk's positions.
        let walkers = self.walkers_charged();
        let group = bytes.min(WALK_BLOCKS * PARSE_BLOCK_BYTES);
        let bins = if finder == Finder::Tree && walkers > 1 && group >= WALK_ALONE_BYTES {
            BucketTrees::bins_most(walkers, group)
        } else {
            0
        };
        (parses as u64 * scratch) + (width * block_out_bytes(block)) as u64 + bins + build
    }

    /// How many blocks of hints the tree keeps in flight, for a flush of
    /// `blocks` blocks in `segments` segments at `stride` candidates a
    /// position: [`HINT_BUDGET_BYTES`]'s worth, or where
    /// [`Engine::hold_wave`] holds a one-segment flush, the held wave in
    /// whole walk groups, at least one group.
    pub(super) fn hint_width(&self, stride: usize, blocks: usize, segments: usize) -> usize {
        let budget = HINT_BUDGET_BYTES / (PARSE_BLOCK_BYTES * 4 * stride);
        let width = if self.wave != usize::MAX && segments == 1 {
            let held = self.wave / PARSE_BLOCK_BYTES / WALK_BLOCKS * WALK_BLOCKS;
            budget.min(held.max(WALK_BLOCKS))
        } else {
            budget
        };
        width.clamp(1, blocks.max(1))
    }

    /// The carried history's own bytes, which spec G's writer counts as
    /// working memory. The finders' structures are not here: they are
    /// sized from the dictionary and the plan and reported by neither.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.history_most as u64
    }

    /// The bytes [`Engine::finder_bytes`] gives each finder a member of
    /// `len` bytes may be walked by ([`Plan::finders_for`]), summed: an
    /// engine that has met both classes holds both finders. `lone` is
    /// whether the member may be lone, and `sizing` gives the positions a
    /// finder is sized from.
    pub(super) fn finders_bytes(
        &self,
        len: usize,
        lone: bool,
        blocks: usize,
        sizing: impl Fn(Finder) -> usize,
    ) -> u64 {
        let (first, second) = self.own.finders_for(len, lone);
        let bytes = |finder| self.finder_bytes(finder, sizing(finder), blocks);
        bytes(first).saturating_add(second.map_or(0, bytes))
    }

    /// The bytes the finder's structures and the tree's hints hold now,
    /// which [`Engine::held_bytes`] leaves out. Every one of them is
    /// cleared or written whole when it is built, so this is resident
    /// memory and not address space.
    pub(crate) fn structure_bytes(&self) -> u64 {
        let tree = self
            .tree
            .as_ref()
            .map_or(0, |tree| tree.subtrees.len() + tree.newest.len());
        let chains = self
            .chains
            .as_ref()
            .map_or(0, |chains| chains.heads.len() + chains.links.len());
        (4 * (tree + chains + self.hints.len())) as u64
    }

    /// [`Engine::finders_bytes`] for the LARGER of the member's finders
    /// rather than their sum: what an engine that has met one class holds
    /// at least, whichever class it meets.
    pub(super) fn larger_finder_bytes(
        &self,
        len: usize,
        lone: bool,
        blocks: usize,
        sizing: impl Fn(Finder) -> usize,
    ) -> u64 {
        let (first, second) = self.own.finders_for(len, lone);
        let bytes = |finder| self.finder_bytes(finder, sizing(finder), blocks);
        bytes(first).max(second.map_or(0, bytes))
    }

    /// [`Engine::finders_bytes`] for the CHAINS alone, where a member of
    /// `len` bytes may be walked by them; nothing where it may not.
    pub(super) fn chain_finder_bytes(
        &self,
        len: usize,
        lone: bool,
        blocks: usize,
        sizing: impl Fn(Finder) -> usize,
    ) -> u64 {
        let (first, second) = self.own.finders_for(len, lone);
        [Some(first), second]
            .into_iter()
            .flatten()
            .filter(|&finder| finder == Finder::Chain)
            .map(|finder| self.finder_bytes(finder, sizing(finder), blocks))
            .max()
            .unwrap_or(0)
    }

    /// The finder's structures and the tree's hints, in bytes, for a walk
    /// sized from `sizing` positions over `blocks` parse blocks at once:
    /// what `Engine::encode_span` builds, as [`Engine::structure_bytes`]
    /// reads it. A function of the dictionary and the plan.
    pub(super) fn finder_bytes(&self, finder: Finder, sizing: usize, blocks: usize) -> u64 {
        self.finder_bytes_over(finder, sizing, blocks, 1)
    }

    /// [`Engine::finder_bytes`] for a flush of `segments` segments: the
    /// tree's hints are the held wave's for one segment and their whole
    /// budget for more ([`Engine::hint_width`]).
    fn finder_bytes_over(
        &self,
        finder: Finder,
        sizing: usize,
        blocks: usize,
        segments: usize,
    ) -> u64 {
        let slots = match finder {
            Finder::Tree => {
                let stride = self.tree_effort().candidates;
                let width = self.hint_width(stride, blocks, segments);
                self.tree_slots(sizing) + width * PARSE_BLOCK_BYTES * stride
            }
            Finder::Chain => Chains::slots_for(self.dictionary, sizing, self.wave),
        };
        (4 * slots) as u64
    }

    /// The tree's reach with the NARROW ring: the dictionary less the
    /// walk's skew. A member longer than this is `long` ([`Engine::long`]).
    pub(super) fn narrow_reach(&self) -> usize {
        self.dictionary.saturating_sub(TREE_SKEW_BOUND)
    }

    /// The tree's ring (the reach it is built for) and its cyclic length
    /// in positions, for a run sized from `sizing` positions: what
    /// `Engine::encode_span` builds, and what [`Engine::finder_bytes`] and
    /// [`Engine::finder_term`] count, from this one place so the three
    /// cannot drift.
    ///
    /// `long` is whether the run's member is longer than the narrow reach
    /// ([`Engine::long`]); the planning callers, which size a run before
    /// its member is known, take `sizing` past the reach for it, which is
    /// the member's own length for a byte slice and charges a reader's
    /// short member for the wider ring it will not build.
    pub(super) fn tree_geometry(&self, sizing: usize, long: bool) -> (usize, usize) {
        let needed = self.dictionary.min(sizing);
        let effort = self.tree_effort();
        let ring = if effort.wide_ring || (long && full_reach(effort)) {
            tree_ring(needed)
        } else {
            needed
        };
        let cyclic = ring
            .clamp(4 * TREE_SKEW_BOUND, TREE_MAX_WINDOW)
            .next_power_of_two();
        (ring, cyclic)
    }

    /// The tree's four-byte slots for a run sized from `sizing`
    /// positions: two children a position and a head for every
    /// [`TREE_HEADS_PER_WINDOW`] positions, without the hints.
    pub(super) fn tree_slots(&self, sizing: usize) -> usize {
        let (_, cyclic) = self.tree_geometry(sizing, sizing > self.narrow_reach());
        let heads = (cyclic / TREE_HEADS_PER_WINDOW)
            .max(1 << 10)
            .next_power_of_two();
        2 * cyclic + heads
    }

    /// Spec G 3.5's FINDER TERM, in bytes: what the finder this level uses
    /// allocates for a run over `span` positions, at the finder's own
    /// full geometry (unheld, [`Engine::hold_wave`] aside), from the same
    /// functions that size it. Levels 1 to 3: the chains' 2^20 heads and
    /// their links ([`Chains::slots_for`]). Levels 4 and 5: the tree's ten
    /// bytes a ring position ([`Engine::tree_slots`]), the hints not
    /// included, as the spec's table has it.
    pub(crate) fn finder_term(&self, span: usize) -> u64 {
        let span = span.min(SPAN_BYTES);
        let slots = |finder| match finder {
            Finder::Tree => self.tree_slots(span),
            Finder::Chain => Chains::slots_for(self.dictionary, span, usize::MAX),
        };
        // Both finders where the member's class decides which: a run that
        // meets both classes holds both. A member too short to be lone or
        // read is not what this term is asked for.
        let (first, second) = self.own.finders_for(span, false);
        (4 * (slots(first) + second.map_or(0, slots))) as u64
    }

    /// What [`Engine::structure_bytes`] reads once this engine has encoded
    /// one fresh member of at most one parse block: through
    /// [`Engine::encode_whole_run`] when `whole_run`, else through
    /// [`Engine::encode_region`]. A function of the dictionary and the
    /// plan alone, so a writer can charge it before anything is built.
    ///
    /// The difference between the two is the tree's: a whole run sizes it
    /// from the dictionary (the history a carried run may reach), a region
    /// from the member. The chains are sized from the member either way.
    pub(crate) fn one_block_structure_bytes(&self, whole_run: bool) -> u64 {
        self.member_structure_bytes(PARSE_BLOCK_BYTES, whole_run)
    }

    /// [`Engine::one_block_structure_bytes`] for a fresh member of `len`
    /// bytes, of any number of parse blocks: the tree from the history a
    /// carried run may reach when `whole_run` and from the member
    /// otherwise, the chains from the member either way, and the tree's
    /// hints for the member's blocks.
    ///
    /// A member short enough to be LONE is walked by the lone effort's
    /// finder (the chains, at levels 4 and 5 too).
    pub(crate) fn member_structure_bytes(&self, len: usize, whole_run: bool) -> u64 {
        let len = len.clamp(1, SPAN_BYTES);
        self.finders_bytes(
            len,
            true,
            len.div_ceil(PARSE_BLOCK_BYTES),
            |finder| match finder {
                Finder::Tree if whole_run => self.history_cap(len),
                _ => len,
            },
        )
    }

    /// Whether a lone member is walked by a DIFFERENT finder from the
    /// level's (levels 4 and 5), so that an engine which
    /// encodes both lone and longer members holds both finders.
    ///
    /// Not where the level has another effort: its members past the lone
    /// bound are charged both finders already
    /// ([`Engine::member_structure_bytes`]), or the chains alone where they
    /// are too short to be read, which is the lone effort's finder.
    pub(crate) fn lone_finder_differs(&self) -> bool {
        self.own.other.is_none()
            && self
                .own
                .lone
                .is_some_and(|lone| lone.finder != self.own.finder)
    }

    /// The most this engine holds while it encodes ONE fresh member of
    /// `len` bytes, finder, hints and carried history together: from its
    /// slice through [`Engine::encode_region`] when `window` is `None`,
    /// else a `window` at a time through [`Engine::encode_chunk`] (spec G
    /// 3.7.3), whose history runs to [`Engine::history_cap`] before it
    /// slides. An upper bound for a member of any length, exact for the
    /// structures of a region of whole parse blocks.
    pub(crate) fn member_held_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        match window {
            None => {
                let span = len.min(SPAN_BYTES);
                self.finders_bytes(span, true, span.div_ceil(PARSE_BLOCK_BYTES), |_| span)
            }
            Some(window) => {
                let chunk = window.min(len).max(1);
                let cap = self.history_cap(chunk);
                // Only a member of one window can be lone.
                self.finders_bytes(len, chunk >= len, chunk.div_ceil(PARSE_BLOCK_BYTES), |_| {
                    cap
                })
                .saturating_add(cap.min(len) as u64)
            }
        }
    }

    /// [`Engine::member_held_bytes`] with ONE finder charged where the
    /// member's class decides between two ([`Plan::finders_for`]): the
    /// larger of them, the class not being read until the member's head
    /// is ([`Plan::for_member_on`]).
    ///
    /// An engine builds a finder when a member of its class arrives and
    /// not before, so one member leaves it holding one. The sum of both is
    /// what an engine that has met both classes holds, and is no part of
    /// what a run CERTAINLY holds. Counted 3 Oct 2026 under real cgroup
    /// limits:
    /// at level 5 and a 32 MiB dictionary the sum is 680 MiB, tree and
    /// chains, where the run built the chains' 260 MiB alone and stood at
    /// 472 to 476 MiB of process.
    pub(crate) fn member_one_finder_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        match window {
            None => {
                let span = len.min(SPAN_BYTES);
                self.larger_finder_bytes(span, true, span.div_ceil(PARSE_BLOCK_BYTES), |_| span)
            }
            Some(window) => {
                let chunk = window.min(len).max(1);
                let cap = self.history_cap(chunk);
                self.larger_finder_bytes(
                    len,
                    chunk >= len,
                    chunk.div_ceil(PARSE_BLOCK_BYTES),
                    |_| cap,
                )
                .saturating_add(cap.min(len) as u64)
            }
        }
    }

    /// [`Engine::member_one_finder_bytes`] for a caller's NAMED ceiling
    /// (`Run::named_most_bytes`): one finder, the larger, with the tree's
    /// hints at the width a flush of more than one segment builds them
    /// ([`Engine::hint_width`]), which a member fed a window at a time is
    /// staged in. Counted 25 Oct 2026 on macOS at `-m5 -md32m`: 34 MiB of
    /// prose built the tree's 384 MiB where `member_one_finder_bytes`
    /// charges 352, its hints held to the wave of one segment.
    ///
    /// Given the member's `head` (what [`Engine::start_member`] is given),
    /// ONE finder: the one its class takes ([`Engine::member_finder`]),
    /// since an engine builds the finder its member's class calls for and
    /// no other (counted the same day: the 34 MiB of lines of words beside
    /// that prose held the chains' 260 MiB).
    pub(crate) fn member_named_finder_bytes(
        &self,
        len: usize,
        window: Option<usize>,
        head: Option<&[u8]>,
    ) -> u64 {
        let plan = head.map_or(self.own, |head| self.member_plan(head, len as u64));
        let widest = |len: usize, lone: bool, blocks: usize, sizing: usize| {
            let (first, second) = plan.finders_for(len, lone);
            let bytes = |finder| self.finder_bytes_over(finder, sizing, blocks, 2);
            bytes(first).max(second.map_or(0, bytes))
        };
        match window {
            None => {
                let span = len.min(SPAN_BYTES);
                widest(span, true, span.div_ceil(PARSE_BLOCK_BYTES), span)
            }
            Some(window) => {
                let chunk = window.min(len).max(1);
                let cap = self.history_cap(chunk);
                widest(len, chunk >= len, chunk.div_ceil(PARSE_BLOCK_BYTES), cap)
                    .saturating_add(cap.min(len) as u64)
            }
        }
    }

    /// The plan ONE fresh member of `size` bytes takes by its class, read
    /// from its `head` as [`Engine::start_member`] reads it: the same
    /// function of the same bytes on a pool of the same width, so a
    /// writer that reads it before its refusal charges the class the
    /// encode then takes.
    fn member_plan(&self, head: &[u8], size: u64) -> Plan {
        let workers = threads().min(self.workers);
        self.own.for_member_read(head, size, workers).0
    }

    /// The finder [`Engine::member_plan`] gives a member of `size` bytes
    /// whose head is `head`: what the test of its agreement with
    /// [`Engine::start_member`] reads.
    #[cfg(test)]
    pub(crate) fn member_finder(&self, head: &[u8], size: u64) -> Finder {
        self.member_plan(head, size).finder
    }

    /// [`Engine::member_held_bytes`] where the CHAINS walk the member: the
    /// chains and the carried history, or nothing where no class of this
    /// level gives a member of `len` bytes to them. What a run that holds
    /// the chains' wave ([`Engine::hold_chain_width`]) is sized from, since
    /// the wave is no part of a run the tree walks.
    pub(crate) fn member_chain_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        match window {
            None => {
                let span = len.min(SPAN_BYTES);
                self.chain_finder_bytes(span, true, span.div_ceil(PARSE_BLOCK_BYTES), |_| span)
            }
            Some(window) => {
                let chunk = window.min(len).max(1);
                let cap = self.history_cap(chunk);
                let chains = self.chain_finder_bytes(
                    len,
                    chunk >= len,
                    chunk.div_ceil(PARSE_BLOCK_BYTES),
                    |_| cap,
                );
                if chains == 0 {
                    0
                } else {
                    chains.saturating_add(cap.min(len) as u64)
                }
            }
        }
    }
}
