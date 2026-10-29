//! The plan: what a level asks of the match finder and the parse, and how
//! a member, a solid run or a floor changes it.

use super::*;

impl Other {
    /// Whether a member whose head read `reading` takes this effort; for
    /// a run's, whether the run does, by its first member's.
    pub(super) fn takes(self, reading: Option<class::Reading>) -> bool {
        // The chains' class: no reading, far links under the cut-off, or
        // (the second statistic) long matches enough.
        let chains = |cut: u32| {
            reading.is_none_or(|reading| {
                reading.per_mille() < cut
                    || self.long.is_some_and(|long| reading.long_matches() >= long)
            })
        };
        match self.takes {
            Takes::Under(cut) => chains(cut),
            Takes::RunAtOrOver(cut) => !chains(cut),
        }
    }

    /// Whether the class is a solid run's, taken once by its first member.
    pub(super) fn is_runs(self) -> bool {
        matches!(self.takes, Takes::RunAtOrOver(_))
    }
}

/// How many chain links level 5's lazy parse follows on a member of the
/// chains' class: level 4's 64 and a quarter.
///
/// 128 links were timed first, and on x86-64 (16 threads, K=3, to the
/// archive on disk, 1 Oct 2026) a 139 MB
/// library at one thread took 0.94 of the tree's speed there. At 80 no
/// member of the class timed on either architecture was slower than the
/// tree at any width (one thread, four, the default): on x86-64 the two
/// libraries 1.20, 1.59, 1.92 and 1.36, 1.85, 2.67, source in one file
/// 1.34 to 2.17, generated code 2.25, 2.70, 2.58; on aarch64 (20 cores)
/// 1.59 to 2.94 on the real members and 2.50, 2.75, 4.24 on generated
/// code. 4.2 GB of real binaries at the default width went from 60.2 s
/// under the tree to 38.4 s at 128 links and 34.7 s at 80 (reference
/// `rar` 59.1 s). So 80 is the pick of 1 Oct 2026, wall
/// first. The thin end of the ladder at this depth: that set writes 0.042
/// percent less than level 4 writes, so a change that gains half a tenth
/// of a percent at 64 links re-counts it.
pub(crate) const LEVEL5_LINKS: u32 = 80;

/// How many chain links level 5's lazy parse follows in a SOLID run:
/// level 4's 64 and an eighth.
///
/// A run of small files is not read for a class (its first member is
/// under a megabyte), so its depth has to suit prose as well as source.
/// Timed against the one-slot tree at one thread, four
/// and the default width (K=3, to the archive on disk,
/// 1 Oct 2026): on aarch64 (20 cores) a
/// solid set of dense prose took 1.03, 0.74 and 0.81 of the tree's speed
/// at 128 links, 1.24, 0.91 and 0.99 at 96 and 1.38, 1.04 and 1.15 at 80;
/// on x86-64 (16 threads) the same set at 80 read 0.96 and then 0.99 at
/// one thread. At 72 it is 1.08, 1.29 and 1.38 on x86-64 and 1.46, 1.12
/// and 1.21 on aarch64, with solid source trees at 1.3 to 3.2. 72 is the
/// deepest at which no solid set timed was slower than the tree at any
/// width on either architecture (the pick of 1 Oct 2026,
/// wall first), and it keeps level 5 under level 4's 64 links by 0.03 to
/// 0.26 percent on real solid sets. The thin end: logs sit at about 0.03
/// percent and 4.2 GB of real binaries at 0.02, so a change that gains
/// a hundredth of a percent at 64 links re-counts them.
pub(crate) const LEVEL5_SOLID_LINKS: u32 = 72;

/// Level 5 takes the chains on a member whose head reads under this many
/// thousandths of a far link a byte.
pub(crate) const LEVEL5_CHAINS_UNDER: u32 = 7_000;

/// Level 5 takes the chains on a member whose head holds this many long
/// matches or more, whatever its far links read: the class's second
/// statistic (decided 2 Oct 2026 on the timed table of both
/// architectures; `WriteOptions::level5_far_links_only` is the way back).
///
/// Far links a byte cannot tell a word list from a library near the
/// cut-off: of 29 real members of 1 to 8 MiB reading 7.0 or more, the
/// chains were the faster finder on 18, and of 11 of 8 to 64 MiB on 9
/// (four 40 MiB compiler binaries, shader archives). Timed on both
/// architectures (x86-64 at 16 threads, aarch64 at 20 cores, to the
/// archive on disk, K=5 with a null,
/// 2 Oct 2026), the members the
/// tree is right for (word lists, dictionaries, model tables) held 0 to
/// 402 long matches in the head and the members the chains win held 1,150
/// and up. One member between, a 1.2 MiB table holding 1,020, was 0.94 of
/// the tree's speed at the default width on aarch64, so the figure sits
/// just over it. The members it moves were, in sum at one thread, four
/// and the default width, 1.57, 1.75 and 1.76 times faster under 8 MiB and
/// 1.98, 2.42 and 2.90 over it on x86-64, and 1.76, 1.68, 1.49 and 2.42,
/// 2.12, 2.54 on aarch64; none was slower at any width on either (the
/// worst 1.07); for 0.76 and 0.20 percent more bytes.
pub(crate) const LEVEL5_CHAINS_LONG: u32 = 1_024;

/// The class rule's dials in force: level 5's cut-off, and the links of
/// level 5's chains on a member and in a solid run. The shipped ones, or
/// in a build with the `reach-knob` feature `RARKIT_L5_CLASS=<thousandths>`,
/// `RARKIT_L5_LINKS=<n>`, `RARKIT_L5_SOLID_LINKS=<n>` and
/// `RARKIT_L5_LONG_CUT=<n>`, so that a count's
/// arms (the tree for every member, the chains for every member, the rule
/// between, a depth) are one binary. No shipped build reads them.
#[derive(Clone, Copy)]
pub(super) struct ClassDials {
    pub(super) level5_under: u32,
    pub(super) level5_links: u32,
    pub(super) level5_solid_links: u32,
    pub(super) level5_long: u32,
}

pub(super) fn class_dials() -> ClassDials {
    let shipped = ClassDials {
        level5_under: LEVEL5_CHAINS_UNDER,
        level5_links: LEVEL5_LINKS,
        level5_solid_links: LEVEL5_SOLID_LINKS,
        level5_long: LEVEL5_CHAINS_LONG,
    };
    #[cfg(feature = "reach-knob")]
    {
        static DIALS: OnceLock<ClassDials> = OnceLock::new();
        *DIALS.get_or_init(|| {
            let read = |name: &str, shipped: u32| {
                std::env::var(name)
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(shipped)
            };
            ClassDials {
                level5_under: read("RARKIT_L5_CLASS", shipped.level5_under),
                level5_links: read("RARKIT_L5_LINKS", shipped.level5_links),
                level5_solid_links: read("RARKIT_L5_SOLID_LINKS", shipped.level5_solid_links),
                level5_long: read("RARKIT_L5_LONG_CUT", shipped.level5_long),
            }
        })
    }
    #[cfg(not(feature = "reach-knob"))]
    shipped
}

/// How many chain links level 3's lazy parse follows (the backward
/// extension's default; it was 64 before the extension).
///
/// With the extension a match found a few bytes in is begun where it
/// really begins, so the chain need not reach a common word's far copy
/// from its first byte, and half the links are enough. Timed 30 Sep 2026
/// on a Zen 4 rental (x86-64, an A/B inside one binary, not a
/// qualified gate figure), against 64 links without the
/// extension: create wall to disk 0.60 to 0.94 on text64, code32, tree5k
/// and small20k solid and bin4g, for 0.994 to 1.000 of the bytes and
/// 1.0025 on code32. `WriteOptions::level3_deep` keeps 64.
pub(crate) const LEVEL3_LINKS: u32 = 32;

/// How many chain links level 4's lazy parse follows: twice level 3's, the
/// depth `WriteOptions::level3_deep` gives level 3. More buys little: 128
/// links were timed at 1.01 of reference `rar`'s wall on code32 at one
/// thread where 64 are 1.55 (SPEC-H3 8.1).
pub(crate) const LEVEL4_LINKS: u32 = 64;

/// Where the tree's descent is cut under the lazy parse: level 5's own
/// plan, and level 4's under `WriteOptions::level4_tree`.
pub(crate) const LEVEL5_CUT: u32 = 16;

pub(crate) const LEVEL4_TREE_CUT: u32 = 12;

/// The backward extension's limit for a parse over `finder`.
///
/// **On at levels 3 to 5**, over the chains (levels 3 and 4) and over the
/// tree (level 5, and level 4 under [`Plan::tree_level4`]);
/// levels 1 and 2 take it only by [`Plan::extend_low`], and a lone
/// member's effort and a spelled plan never. Counted 30 Sep 2026 by the
/// text reach research:
/// what level 3 misses against reference `rar` on text is mostly the HEAD
/// of a match its chain already reaches from a few bytes into it, and
/// beginning an offered match earlier recovers it (level 3's payload 0.939
/// to 0.960 of what it was at a 2 MiB dictionary, the lazy parse's 0.946
/// to 0.974 at levels 1 and 2).
///
/// **The tree took it on 1 Oct 2026, for the ladder** (SPEC-H3 8.1: a
/// higher level never writes more than the one below). Under the OPTIMAL
/// parse the tree's answers already start where a match starts and the
/// extension bought 0.03 to 0.11 percent, so it was left off. Under the
/// LAZY parse over one hint slot they do not: the parse asks the
/// tree only where it stands, a line that repeats an earlier one but for a
/// few bytes is entered a few bytes late, and level 3, which had the
/// extension, wrote LESS than levels 4 and 5 on real line-structured
/// input (source code, logs, tables: level 4 up to 1.17 percent over
/// level 3 on a 36 MB member, measured 1 Oct 2026).
/// With it the lazy tree plans retire 0.993 to 1.015 of the instructions
/// for 0.05 to 1.2 percent fewer bytes on the gate corpora. The optimal
/// plans the options keep take none ([`Plan::optimal_tree`]).
///
/// The FLOOR takes none ([`Plan::floor`]), so the store rule's samples
/// (spec G 3.8.3) keep their one fixed form and level 3's lazy floor
/// its old bytes.
pub(super) fn back_for(finder: Finder) -> usize {
    match finder {
        Finder::Chain => reach_knob().back.unwrap_or(BACK_LIMIT),
        Finder::Tree => reach_knob().back_tree.unwrap_or(BACK_LIMIT),
    }
}

/// The measuring dials of the backward extension's timed runs, read
/// once: `RARKIT_BACK=<n>` sets its limit at every chain effort (0 turns it
/// off), `RARKIT_L3_DEPTH=<n>` level 3's chain depth in whichever form level
/// 3 takes (the lazy parse, 64 links; or with `RARKIT_L3_OPTIMAL=1`
/// the optimal parse, 8 links), and `RARKIT_BACK_TREE=<n>` the
/// extension over the tree at the lazy plans of levels 4 and 5 (0 turns
/// it off, which is those levels before 1 Oct 2026), and
/// `RARKIT_TREE_WALKERS=<n>` the cap on the tree walk's threads in place of
/// [`tree_walkers_most`]'s (it moves no byte). (`RARKIT_L4_LAZY`, which
/// stood in for the lazy level 4 in those timed rows, went when it
/// landed: the lazy tree plan is level 4's own.) Only a build with
/// the `reach-knob` feature reads them, so that the arms are timed inside
/// one binary; no shipped build does. A limit above `lz::BACK_LIMIT`
/// still takes back literals that far, but the lazy parse keeps only the
/// matches that can lie within `BACK_LIMIT` bytes.
#[derive(Clone, Copy, Default)]
pub(super) struct ReachKnob {
    pub(super) back: Option<usize>,
    pub(super) level3_depth: Option<u32>,
    pub(super) back_tree: Option<usize>,
    pub(super) tree_walkers: Option<usize>,
}

pub(super) fn reach_knob() -> ReachKnob {
    #[cfg(feature = "reach-knob")]
    {
        static KNOB: OnceLock<ReachKnob> = OnceLock::new();
        *KNOB.get_or_init(|| ReachKnob {
            back: std::env::var("RARKIT_BACK")
                .ok()
                .and_then(|v| v.parse().ok()),
            level3_depth: std::env::var("RARKIT_L3_DEPTH")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&d: &u32| d > 0),
            back_tree: std::env::var("RARKIT_BACK_TREE")
                .ok()
                .and_then(|v| v.parse().ok()),
            tree_walkers: std::env::var("RARKIT_TREE_WALKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&n: &usize| n > 0),
        })
    }
    #[cfg(not(feature = "reach-knob"))]
    ReachKnob::default()
}

impl Lone {
    /// Level 3's own lone effort, and levels 4 and 5's by default since
    /// 30 Sep 2026: the lazy parse over the chains, 64 links deep, stopped
    /// at a 256 byte match.
    pub(crate) const LAZY: Lone = Lone {
        bytes: PARSE_BLOCK_BYTES,
        parse: Parse::Lazy,
        finder: Finder::Chain,
        depth: 64,
        enough: 256,
    };
    /// What levels 4 and 5 give a lone member when the user switches
    /// `WriteOptions::small_member_lazy` off, and gave it by default
    /// until 30 Sep 2026: level 3's own plan, the optimal parse
    /// over the chains, 8 links deep, stopped at a 64 byte match.
    pub(crate) const OPTIMAL_CHAIN: Lone = Lone {
        bytes: PARSE_BLOCK_BYTES,
        parse: Parse::Optimal,
        finder: Finder::Chain,
        depth: 8,
        enough: 64,
    };
}

impl Plan {
    /// The plan spec G's level `level` maps to.
    pub(crate) fn for_level(level: u8) -> Plan {
        // RETUNED 19 Sep 2026 against the aim - "a good option of speed
        // vs ratio for the user's requirements" - which makes the LEVELS
        // the product and a rung that buys nothing a defect. The sweep
        // behind it is a bench script over six corpora of
        // real shapes (a source tree, Mach-O executables, already
        // compressed media, a many small files solid set, this
        // repository's own tree, and the create legs' text); the frontier
        // it drew, and the before and after ladders, were recorded with
        // it.
        //
        // **What was wrong with the ladder this replaces.** Its five rungs
        // cost 1.00x, 3.25x, 10.79x, 14.18x and 16.44x level 1's CPU, so
        // its last two steps were 1.31x and 1.16x: three of five rungs sat
        // within a factor of two at the top and the bottom half of the
        // range had nothing in it. Worse, two rungs did not pay:
        //
        // - level 3 (`optimal:chain:24`) was OFF the measured frontier on
        //   the two largest corpora - the tree at cut 8 is both cheaper
        //   and smaller there, by 2.2x the CPU and 1.4% on the create
        //   legs' text - so a user choosing it paid for nothing;
        // - level 5 (`optimal:tree:64`) was 1.04x level 5-at-cut-32's CPU
        //   for 0.01 points of ratio, which is the same defect at the top;
        // - and level 2 cost 1.1x to 2.6x reference `rar`'s OWN level 2
        //   CPU while writing up to 5.3% more bytes, which is losing on
        //   both axes at once.
        //
        // **What this ladder is.** Three things the sweep settled, none of
        // them what the ladder before it assumed:
        //
        // 1. **The lazy parse over chains is the whole low end.** It is on
        //    the frontier at every depth from 1 to 32 on every corpus, and
        //    the optimal parse is not worth its price below about depth 8.
        //    So levels 1 and 2 are both the lazy parse and differ only in
        //    how deep they look, and both now cost LESS CPU than reference
        //    `rar` at the same level on every corpus measured (0.67x to
        //    0.95x), which is the trade a low level is for.
        // 2. **The optimal parse earns level 3 over chains, and the tree
        //    earns level 4.** The tree's answers are better, but its walk
        //    takes every position whether the parse wants it or not, and
        //    below level 4's budget that overhead buys less than the
        //    chains' depth does.
        // 3. **The tree's cut of 32 is the top**, not 64: 64 was 1.04x the
        //    CPU for 0.01 points, and 128 less than that again.
        //
        // The result is 1.00x, 1.78x, 5.59x, 10.66x and 15.78x level 1's
        // CPU - steps of 1.78x, 3.14x, 1.91x and 1.48x - at 18.3%, 12.4%,
        // 8.0%, 4.0% and 0.0% over the smallest archive any plan on the
        // frontier reached, which is four size steps of 5.9, 4.4, 3.9 and
        // 4.0 points. Every rung is on the measured frontier and none is
        // dominated by another.
        //
        // **What it costs, stated rather than buried**: levels 2 and 3
        // write more bytes than the rungs that stood in their place, by up
        // to 3.7 points, and the ratio points they vacate are covered by
        // the rung above (this ladder's level 4 is both CHEAPER and
        // SMALLER than the old level 3 on the create legs' text, so that
        // one is not a trade at all). Against reference `rar` at the same
        // level this ladder is up to 8.6% larger at level 2 and 7.7% at
        // level 3, where it is 0.30x to 1.12x that level's CPU: the
        // reference's own ladder is top heavy, its level 2 already sitting
        // near its best, so a ladder spread evenly over a WIDER range must
        // be behind it in the middle and ahead of it at both ends. Levels
        // 1 and 5 are the ends: level 1 is 0.1% to 18.8% smaller than the
        // reference's level 1 at two thirds of its CPU, and level 5 is
        // 4.5% smaller than the reference's level 5 on text.
        //
        // What a block with nothing in it to find costs is not on this
        // ladder at all: [`Plan::floor`] and `encode::sample` take that
        // off every level above the floor, worth 2.0x to 3.7x the CPU on
        // incompressible bytes for no measurable archive.
        //
        // **Level 3 is the lazy parse 64 links deep** (decided
        // 30 Sep 2026, conditional on timed rows): it is the
        // effort level 3's lone members already had, and
        // counted against the optimal parse over 8 links it wrote 0.995 to
        // 0.999 of the payload on the solid trees for 0.21 to 0.46 of the
        // instructions, 1.013 on code32 for 0.22 and 0.968 on text64 for
        // 0.37.
        // [`Plan::optimal_level3`] is the user's way back to the plan it
        // replaced, `optimal:chain:8:64`. With the backward extension the
        // lazy parse follows [`LEVEL3_LINKS`] links, not 64;
        // [`Plan::deep_level3`] keeps 64.
        //
        // **Levels 4 and 5** (decided 30 Sep 2026: "for
        // the level 5 issue, we need a user option to support both, but
        // default to the option that is a faster wall, as always"; SPEC-H3
        // 8.1): the LAZY parse over the tree, its descent cut at 12 and 16,
        // keeping ONE hint slot a position (the longest match the descent
        // found). The optimal parse over the tree cost about as much CPU as
        // reference `rar`'s whole level 5 on a big member, for 3 to 5
        // percent of bytes over the lazy parse on the same tree; the walk
        // is then the cost, and the cut its dial. Counted in the research
        // work (measured 30 Sep 2026),
        // level 5 on code32 at one thread
        // 127.5 G to 49.3 G instructions on x86-64 for 5.8 percent more
        // bytes, still under reference `rar`'s; level 4 moves with it so
        // that it stays the faster rung and level 5 the smaller. The
        // optimal parse the levels had before is [`Plan::optimal_tree`],
        // behind `WriteOptions::level4_optimal` and `level5_optimal`.
        //
        // **Level 1 is the fast parse** (set 30 Sep
        // 2026: a cheaper level 1 is the default where timed rows on both
        // architectures show the faster wall, with an option; decided 1
        // Oct 2026 on those rows): chains keyed on six
        // bytes, one link, the four held distances first, a static price,
        // greedy, entropy blocks cut blind at 64 KiB. Level 1 as it stood,
        // the lazy parse three links deep over four byte chains with the
        // priced cut, lost to reference `rar` 7.23's `-m1` at one to four
        // threads on single files (0.47x to 0.69x of its wall at one
        // thread on a Zen 4, 0.45x on bin4g on the M5 Ultra), because rar's
        // level 1 retires a quarter of the instructions. Timed on both
        // architectures in quiet timed runs, to the archive on disk, the
        // fast parse takes 0.40x to 0.46x of that level 1's wall at one
        // thread on single files and beats rar on every row but one (bin4g
        // at one thread on aarch64, 0.92x), for +0.2 percent of archive on
        // text64, +2.7 on code32, +5.1 on small20k, +5.6 on tree5k and
        // +4.3 on bin4g, which still sits under rar's `-m1` on code and
        // on bin4g (measured 30 Sep 2026).
        // [`Plan::priced_level1`] is the user's way
        // back. The plan's `depth` and `enough` are what an empty block's
        // floor scan asks of the same chains; the parse itself follows one
        // link and reads neither.
        //
        // **Level 4 walks the CHAINS since 1 Oct 2026** (decided
        // on a quiet timed table under the standing rule,
        // "default to the option that is a faster wall"; SPEC-H3 8.1,
        // "LEVEL 4 RUNS THE CHAINS"): level 3's lazy parse over level 3's
        // chains at twice its depth, [`LEVEL4_LINKS`], with the backward
        // extension. The tree searches at every position while the lazy
        // parse reads a hint at about one position in five to ten; the
        // chains search only where the parse asks. Timed on aarch64 (20
        // cores, walls to the archive on disk) code32 at one thread went
        // from 3.85 s to 1.62 s and a solid tree of small files from 8.75 s
        // to 2.28 s, for 1.8 percent more bytes on code32 and fewer on the
        // trees. So the ladder's upper half is one finder under one parse
        // at two depths, and then level 5, the tree. [`Plan::tree_level4`]
        // (`WriteOptions::level4_tree`) keeps the tree at level 4.
        //
        // **Level 5 goes BY CLASS since 1 Oct 2026**
        // (SPEC-H3 8.1, [`Other`]). The
        // plan below is level 5's OWN, the lazy tree, and it is what a
        // member takes whose head reads many far links a byte (prose,
        // generated text): there the tree is the faster finder at width.
        // Every other member that is not lone takes the level's other
        // effort, the same chains one step deeper than level 4's, and a
        // solid run takes its first member's class for every member of it
        // ([`Plan::solid_run`]). On a 4 GiB set
        // of real binaries at the default width on a Zen 4 (16 threads,
        // to the archive on disk) level 5 went from 60.1 s, level with
        // reference `rar`'s 59.1 s, to 38.4 s. [`Plan::tree_level5`]
        // (`WriteOptions::level5_tree`) keeps the tree for every member.
        let (parse, finder, depth, enough) = match level {
            0 | 1 => (Parse::Fast, Finder::Chain, 1, 32),
            2 => (Parse::Lazy, Finder::Chain, 12, 64),
            3 => (
                Parse::Lazy,
                Finder::Chain,
                reach_knob().level3_depth.unwrap_or(LEVEL3_LINKS),
                256,
            ),
            4 => (Parse::Lazy, Finder::Chain, LEVEL4_LINKS, 256),
            _ => (Parse::Lazy, Finder::Tree, LEVEL5_CUT, 0),
        };
        Plan {
            parse,
            finder,
            depth,
            // The lazy parse prices one candidate a position well: two
            // slots cost 3 percent CPU for 0.01 percent of bytes on code32.
            // The hint buffer then holds four times the blocks in the same
            // budget, which is a width and never a byte.
            candidates: match (parse, finder) {
                (Parse::Lazy, Finder::Tree) => 1,
                _ => TREE_CANDIDATE_SLOTS,
            },
            enough,
            dials: OptimalDials::FULL,
            // Level 3, and levels 4 and 5: a
            // whole non-solid member of at most one parse block. At levels
            // 4 and 5 its effort is level 3's lone one
            // (decided 30 Sep 2026, "wall is always what matters
            // most"): measured with the switch, small20k -m5 took 2.4x
            // less CPU at every width and tree5k -m5 39% less, for 0.12%
            // and 0.24% more archive, both still under rar 7.23's -m5
            // (measured 30 Sep 2026). `optimal_small_members` is the user's
            // way back to the earlier default.
            lone: match level {
                3..=5 => Some(Lone::LAZY),
                _ => None,
            },
            wide_ring: false,
            full_reach: finder == Finder::Tree,
            // The chain levels. The tree levels walk every position
            // whatever the parse, so the scan buys them little (it
            // stays off at levels 4 and 5).
            scans_floor: finder == Finder::Chain,
            // Level 3's thin blocks ([`Plan::for_thin_block`]).
            scans_thin: level == 3,
            empty_stride: true,
            // Levels 1 and 2 keep the extension OFF by default: timed on
            // both architectures it was level on x86-64 and 1 to 3 percent
            // slower on aarch64 for 2.3 to 5.0 percent fewer bytes, so the
            // faster wall is the default and [`Plan::extend_low`]
            // (`WriteOptions::low_levels_extend`) the option (decided
            // under the standing rule, 30 Sep 2026).
            back: match level {
                0..=2 => reach_knob().back.unwrap_or(0),
                _ => back_for(finder),
            },
            far_links: None,
            pair: Pairing::shipped(),
            // **Level 5 by class** (decided 1 Oct 2026,
            // SPEC-H3 8.1; [`Other`]): level 5
            // takes the chains at [`LEVEL5_LINKS`] where a member's head
            // reads few far links. Level 4 has one effort.
            other: match level {
                5.. => Some(Other {
                    finder: Finder::Chain,
                    depth: class_dials().level5_links,
                    candidates: TREE_CANDIDATE_SLOTS,
                    enough: 256,
                    full_reach: false,
                    scans_floor: true,
                    back: back_for(Finder::Chain),
                    takes: Takes::Under(class_dials().level5_under),
                    long: Some(class_dials().level5_long),
                }),
                _ => None,
            },
        }
    }

    /// The level's other effort as a plan of its own, where it has one:
    /// the lazy parse over the other finder, the lone effort kept.
    pub(crate) fn other(self) -> Option<Plan> {
        self.other.map(|other| Plan {
            parse: Parse::Lazy,
            finder: other.finder,
            depth: other.depth,
            candidates: other.candidates,
            enough: other.enough,
            full_reach: other.full_reach,
            scans_floor: other.scans_floor,
            back: other.back,
            other: None,
            ..self
        })
    }

    /// The plan a whole member of `size` bytes takes, where `head` is its
    /// first bytes (at least `class::HEAD_BYTES` of them where it is that
    /// long): the level's own, or its other effort by the member's class.
    ///
    /// A pure function of the plan, the size and the head's bytes, so a
    /// member's class cannot move with the machine, the thread count, the
    /// payload's kind or which thread encodes it. The head is read only
    /// where the answer needs it: a level with no other effort, a lone
    /// member and a member under a megabyte read nothing.
    #[cfg(test)]
    pub(crate) fn for_member(self, head: &[u8], size: u64) -> Plan {
        self.for_member_on(head, size, 1)
    }

    /// [`Plan::for_member`] with the head read on up to `workers` threads
    /// of the caller's pool (`class::of_head_wide`): the same reading and
    /// so the same plan at any width; only the wall it takes moves.
    #[cfg(test)]
    pub(crate) fn for_member_on(self, head: &[u8], size: u64, workers: usize) -> Plan {
        self.for_member_read(head, size, workers).0
    }

    /// [`Plan::for_member_on`], and beside the plan the head's reading
    /// where the head was read and the member KEPT the level's own plan by
    /// it (`None` for every other member: one not read, and one that took
    /// the other effort). The reading moves no byte past the plan it
    /// chose; the engine sizes a width from it
    /// ([`Engine::start_member`]).
    pub(super) fn for_member_read(
        self,
        head: &[u8],
        size: u64,
        workers: usize,
    ) -> (Plan, Option<class::Reading>) {
        let Some(other) = self.other else {
            return (self, None);
        };
        if self.lone.is_some_and(|lone| size <= lone.bytes as u64) {
            return (self, None);
        }
        let reading = if size >= class::HEAD_BYTES as u64 {
            class::of_head_wide(head, workers)
        } else {
            None
        };
        if other.takes(reading) {
            (self.other().expect("the plan has another effort"), None)
        } else {
            (
                Plan {
                    other: None,
                    ..self
                },
                reading,
            )
        }
    }

    /// Whether [`Plan::for_member`] reads the head of a member of `size`
    /// bytes, so that a writer pulls a reader's head only where it is read.
    pub(crate) fn reads_head(self, size: u64) -> bool {
        self.other.is_some()
            && size >= class::HEAD_BYTES as u64
            && !self.lone.is_some_and(|lone| size <= lone.bytes as u64)
    }

    /// The finders a whole member of `len` bytes may be walked by, the
    /// level's own first: one, or both where the member's class decides
    /// ([`Plan::for_member`]). What an engine is charged for before the
    /// member's bytes are read.
    ///
    /// `lone` is whether a member that short may be lone at all: one fed
    /// a window at a time in more windows than one never is.
    pub(super) fn finders_for(self, len: usize, lone: bool) -> (Finder, Option<Finder>) {
        let is_lone = lone && self.lone.is_some_and(|lone| len <= lone.bytes);
        let own = if is_lone {
            self.finder_for(len)
        } else {
            self.finder
        };
        let Some(other) = self.other else {
            return (own, None);
        };
        if is_lone {
            return (own, None);
        }
        if other.is_runs() {
            // A member of a solid run follows its run's class whatever its
            // own length, and an engine may meet a run of each class.
            return (own, Some(other.finder));
        }
        if len < class::HEAD_BYTES {
            // Too short to be read: whichever effort takes the unread.
            return (if other.takes(None) { other.finder } else { own }, None);
        }
        (own, Some(other.finder))
    }

    /// The effort a lone member is parsed at, where the level has one.
    pub(super) fn lone(self) -> Option<Plan> {
        self.lone.map(|lone| Plan {
            parse: lone.parse,
            finder: lone.finder,
            depth: lone.depth,
            enough: lone.enough,
            // A lone member keeps its effort exactly as it was
            // set: counted on small20k non-solid (every member
            // lone) the extension was 0.9994 of the bytes for 1.028 of the
            // instructions, a cost the rule "smaller only if wall is no
            // worse" does not take untimed.
            back: 0,
            ..self
        })
    }

    /// The user option `WriteOptions::small_member_lazy` set to
    /// `false`: levels 4 and 5 give a lone member level 3's OPTIMAL chain
    /// parse ([`Lone::OPTIMAL_CHAIN`], the earlier default) instead of
    /// the lazy one. It reaches levels 4 and 5 only, whichever finder the
    /// level's own plan walks (level 4's is the chains since 1 Oct 2026);
    /// every other plan is as it was (level 3's lone stays lazy).
    pub(crate) fn optimal_small_members(self, level: u8) -> Plan {
        Plan {
            lone: match self.lone {
                Some(lone) if lone == Lone::LAZY && level >= 4 => Some(Lone::OPTIMAL_CHAIN),
                other => other,
            },
            ..self
        }
    }

    /// The user option `WriteOptions::level4_tree`: level 4's plan for a
    /// member that is not lone as it was before level 4 went to the
    /// chains, the LAZY parse over the tree, its descent cut at
    /// [`LEVEL4_TREE_CUT`], one hint slot (two in a solid run,
    /// [`Plan::solid_run`]), the full reach, the lazy floor and the
    /// backward extension. It writes 0.3 to 0.7 percent less on prose
    /// than the chains do, for a slower wall. The caller applies it to
    /// level 4's plan only, before [`Plan::optimal_tree`], which
    /// overrides it.
    pub(crate) fn tree_level4(self) -> Plan {
        Plan {
            parse: Parse::Lazy,
            finder: Finder::Tree,
            depth: LEVEL4_TREE_CUT,
            candidates: 1,
            enough: 0,
            full_reach: true,
            scans_floor: false,
            back: back_for(Finder::Tree),
            other: None,
            ..self
        }
    }

    /// The user option `WriteOptions::level5_far_links_only`: level 5's
    /// class without its SECOND statistic, as it was before 2 Oct 2026. By
    /// default a member (or a solid run's first member) whose head reads
    /// [`LEVEL5_CHAINS_UNDER`] far links or more takes the chains all the
    /// same where the head holds [`LEVEL5_CHAINS_LONG`] long matches or
    /// more; with this, every such member keeps the tree. Nothing else
    /// moves either way: a member reading under the cut-off, an unread
    /// one, a lone one and every other level write what they wrote. The
    /// caller applies it to level 5's plan only, before
    /// [`Plan::tree_level5`] and [`Plan::optimal_tree`], which leave
    /// nothing for it to decide.
    pub(crate) fn far_links_only_level5(self) -> Plan {
        Plan {
            other: self.other.map(|other| Other {
                long: None,
                ..other
            }),
            ..self
        }
    }

    /// The user option `WriteOptions::level5_tree`: level 5 keeps the tree
    /// for every member that is not lone, of a solid run or not, as it did
    /// before level 5 went by class. The caller applies it to level 5's
    /// plan only, before [`Plan::optimal_tree`], which overrides it.
    pub(crate) fn tree_level5(self) -> Plan {
        Plan {
            other: None,
            ..self
        }
    }

    /// The user options `WriteOptions::level4_optimal` and
    /// `WriteOptions::level5_optimal`: level `level`'s plan for a member
    /// that is not lone as it was before 30 Sep 2026, the OPTIMAL parse over
    /// the tree with four hint slots, cut at 8 at level 4 and at 32 at
    /// level 5, the narrow ring, the lazy floor, and no backward extension
    /// (the optimal parse reads [`Plan::back`] too, and these plans never
    /// had it). The plan's lone effort is kept, so the level writes exactly
    /// its old bytes whatever its default plan has become since. The
    /// WRITER applies it where the level is known; levels 1 to 3 are
    /// returned as they are.
    pub(crate) fn optimal_tree(self, level: u8) -> Plan {
        let depth = match level {
            0..=3 => return self,
            4 => 8,
            _ => 32,
        };
        Plan {
            parse: Parse::Optimal,
            finder: Finder::Tree,
            depth,
            candidates: TREE_CANDIDATE_SLOTS,
            enough: 0,
            full_reach: false,
            scans_floor: false,
            back: 0,
            other: None,
            ..self
        }
    }

    /// A SOLID run's plan, which the writer sets where it builds a solid
    /// run's encoder: the wide ring and the kept index ([`Plan::wide_ring`]),
    /// and at LEVEL 4's lazy tree plan ([`Plan::tree_level4`],
    /// the option since level 4's default went to the chains) TWO hint
    /// slots a position in place of one.
    ///
    /// The second slot is the ladder's (decided 1 Oct 2026,
    /// SPEC-H3 8.1): once the backward extension gave
    /// level 3 its solid reach, level 4's one-slot tree plan wrote MORE
    /// than level 3 on a solid tree of small files (tree5k -s 8,485,578
    /// bytes against 8,481,120) while taking three times its wall, and a
    /// level that loses to the one below on both axes is a defect. Two
    /// slots (the nearest match and the longest) wrote 8,456,495 there for
    /// 3.6 percent more wall.
    ///
    /// LEVEL 5 keeps ONE slot, solid or not. A second slot in a solid run
    /// was built and timed for it on 1 Oct 2026 (to stay under a two-slot
    /// solid level 4) and taken out again the same day: it cost 3.3 to 3.4
    /// percent of wall on a solid tree of small files at one and four
    /// threads (aarch64, 20 cores), and with level 4's solid plan on the
    /// chains, which keep no slot, one slot with the backward extension
    /// already writes less than level 4 on every solid set counted.
    /// The optimal plan
    /// [`Plan::optimal_tree`] gives back is not touched.
    ///
    /// **A solid run has ONE plan, and at level 5 it is the chains at
    /// [`LEVEL5_SOLID_LINKS`] unless its FIRST MEMBER says otherwise** (decided
    /// 1 Oct 2026, SPEC-H3 8.1). A run's finder
    /// carries its index from member to member, so a run has one class,
    /// and it is its first member's, read exactly as a non-solid member is
    /// (that member too starts from no history): a first member of a
    /// megabyte or more whose head reads AT OR OVER [`LEVEL5_CHAINS_UNDER`]
    /// keeps the one-slot tree for the whole run, the level 5 of before;
    /// a first member that reads under it, or is under a megabyte and has
    /// no reading, leaves the run on the chains. So the plan this gives is
    /// the chains with the tree as its other effort
    /// ([`Takes::RunAtOrOver`]), and a run nobody starts through
    /// [`Engine::start_member`] is on the chains.
    ///
    /// Timed against the one-slot tree on both architectures
    /// (measured 1 Oct 2026), 72 links are faster at
    /// every width on every real solid SET sat, prose included (1.12 to
    /// 9.7 times), and slower on two runs of one large member: a sorted
    /// word list (0.80, 0.72, 0.78 on aarch64) and generated far-link text
    /// (0.82 at four threads on aarch64, 0.90 at one on x86-64). The head's
    /// reading does not separate those from prose, so a run is not given a
    /// cut-off of its own: the first member's class sends both back to the
    /// tree, and with them a solid archive of one large prose file, which
    /// then writes what the same file writes outside a solid run.
    ///
    /// The chains a step deeper than level 4's keep the solid rows ordered
    /// where the one-slot tree wrote more than level 4 on solid source
    /// trees. Level 4's solid run is the chains too, its own plan. With
    /// `WriteOptions::level5_tree` ([`Plan::tree_level5`]) the plan has no
    /// other effort and a solid level 5 keeps the tree.
    pub(crate) fn solid_run(self, level: u8) -> Plan {
        let run = match (self.other, self.other()) {
            (
                Some(Other {
                    takes: Takes::Under(cut),
                    long,
                    ..
                }),
                Some(chains),
            ) if level >= 5 && chains.finder == Finder::Chain && self.finder == Finder::Tree => {
                Plan {
                    depth: class_dials().level5_solid_links,
                    other: Some(Other {
                        finder: self.finder,
                        depth: self.depth,
                        candidates: self.candidates,
                        enough: self.enough,
                        full_reach: self.full_reach,
                        scans_floor: self.scans_floor,
                        back: self.back,
                        takes: Takes::RunAtOrOver(cut),
                        long,
                    }),
                    ..chains
                }
            }
            _ => Plan {
                other: None,
                ..self
            },
        };
        let candidates = match (level, run.parse, run.finder) {
            (4, Parse::Lazy, Finder::Tree) => SOLID_LEVEL4_SLOTS,
            _ => run.candidates,
        };
        Plan {
            wide_ring: true,
            candidates,
            ..run
        }
    }

    /// Whether any block of this plan may take the OPTIMAL parse: the
    /// level's own, or a lone member's (a lazy level 5 still hands a lone
    /// member level 3's optimal chain parse when `small_member_lazy` is
    /// off). What the optimal scratch is built and charged for.
    pub(super) fn parses_optimally(self) -> bool {
        self.parse == Parse::Optimal || self.lone.is_some_and(|lone| lone.parse == Parse::Optimal)
    }

    /// The user option `WriteOptions::level3_floor_lazy`: a
    /// block the incompressible sample calls empty takes the floor's LAZY
    /// parse, as level 3 did before the scan, instead of the floor scan.
    ///
    /// It clears [`Plan::scans_floor`] whatever the plan's parse, and the
    /// WRITER applies it to level 3 only (levels 1 and 2 always scan, 4 and
    /// 5 never do), where the level is known: a test of the parse here
    /// would move with the ladder (level 3's parse is lazy by default).
    pub(crate) fn lazy_floor(self) -> Plan {
        Plan {
            scans_floor: false,
            scans_thin: false,
            ..self
        }
    }

    /// The plan without the EMPTY STRIDE (`chain::EMPTY_STRIDE`): every
    /// position of an empty block linked, as before the stride. Level 1's
    /// priced form takes it ([`Plan::priced_level1`]), so that
    /// `WriteOptions::level1_priced` writes level 1 byte for byte as it was
    /// with both writers. The other options whose promise is an archive of
    /// before (`level1_dictionary_2mib`, `level3_dictionary_2mib`,
    /// `store_one_miss`) also promise to move nothing where they do not
    /// act, and none of them acts on a level whose empty blocks the stride
    /// links (level 1's own parse keys its chains on six bytes), so they
    /// keep it.
    pub(crate) fn without_empty_stride(self) -> Plan {
        Plan {
            empty_stride: false,
            ..self
        }
    }

    /// The user option `WriteOptions::level3_optimal`: level 3's
    /// own plan as it first was, the optimal parse over the
    /// chains 8 links deep, stopped at a 64 byte match. Its lone members
    /// keep their lazy effort, and a block carrying a filter
    /// record takes the lazy parse over those 8 links, as before. The
    /// caller applies it to level 3's plan only.
    pub(crate) fn optimal_level3(self) -> Plan {
        Plan {
            parse: Parse::Optimal,
            scans_thin: false,
            finder: Finder::Chain,
            depth: reach_knob().level3_depth.unwrap_or(8),
            enough: 64,
            // The plan as it was, without the extension; a timed run's knob
            // may set it.
            back: reach_knob().back.unwrap_or(0),
            ..self
        }
    }

    /// The user option `WriteOptions::level1_priced`: level 1's
    /// own plan as it was until 1 Oct 2026, the lazy parse over four byte
    /// chains three links deep, stopped at a 32 byte match, with the priced
    /// cut. Byte for byte the level 1 of before. The caller applies it to
    /// level 1's plan only, before [`Plan::extend_low`].
    pub(crate) fn priced_level1(self) -> Plan {
        Plan {
            parse: Parse::Lazy,
            finder: Finder::Chain,
            depth: 3,
            enough: 32,
            ..self
        }
        .without_empty_stride()
    }

    /// How many of a position's first bytes key the chains an engine of
    /// this plan builds: six under the fast parse, four under every other.
    /// Read from the LEVEL's plan, once a run, never from a block's effort:
    /// an empty block's floor scan asks the chains its level built
    /// ([`Plan::for_empty_block`]). The floor itself is a lazy plan
    /// ([`Plan::floor`]), so the store rule's samples, which are packed by
    /// an engine of level 1's floor (spec G 3.8.3), keep their four byte
    /// chains and no member's verdict moves.
    pub(crate) fn chain_key(self) -> usize {
        match self.parse {
            Parse::Fast => KEY_WIDE,
            Parse::Lazy | Parse::Optimal | Parse::Scan | Parse::ThinScan => KEY_SHORT,
        }
    }

    /// The backward extension's user option at levels 1 and 2,
    /// `WriteOptions::low_levels_extend`: their lazy parse begins an offered
    /// match where it really begins ([`back_for`]), for 2.3 to 5.0 percent
    /// fewer bytes and up to 3 percent more create wall on aarch64. The
    /// caller applies it to levels 1 and 2 only. Level 1's fast parse has
    /// no extension and reads nothing of it: at level 1 the option reaches
    /// the priced form alone ([`Plan::priced_level1`]).
    pub(crate) fn extend_low(self) -> Plan {
        Plan {
            back: back_for(self.finder),
            ..self
        }
    }

    /// The backward extension's user option, `WriteOptions::level3_deep`:
    /// level 3's lazy parse over its chains 64 links deep, the first
    /// plan, instead of [`LEVEL3_LINKS`]. The caller applies it to level 3's
    /// plan only, before `optimal_level3`, which overrides it.
    pub(crate) fn deep_level3(self) -> Plan {
        Plan {
            depth: reach_knob().level3_depth.unwrap_or(64),
            scans_thin: false,
            ..self
        }
    }

    /// `WriteOptions::far_link_budget`: every chain search of this plan
    /// follows at most `budget` candidates farther than 2 MiB back
    /// (`chain::FAR_FROM`). It moves bytes only where the dictionary is
    /// longer than that; at 2 MiB and under no candidate is far.
    pub(crate) fn far_links(self, budget: u32) -> Plan {
        Plan {
            far_links: Some(budget),
            ..self
        }
    }

    /// The finder a member of `len` bytes, whole and from no history, is
    /// walked by: the lone effort's where the member is lone, else the
    /// level's.
    pub(super) fn finder_for(self, len: usize) -> Finder {
        match self.lone {
            Some(lone) if len <= lone.bytes => lone.finder,
            _ => self.finder,
        }
    }

    /// The FLOOR effort: what a parse block with nothing in it to find is
    /// parsed at instead of the level's own plan.
    ///
    /// The lazy parse at the shallowest search, over whichever finder the
    /// level already built. The finder does not change, and could not: a
    /// finder's index has to take every position of the span whether or
    /// not a block's parse looks at it, so what a sample can drop is the
    /// SEARCH and the deliberation, never the indexing. That is where the
    /// cost is anyway - measured on `media16`, dropping to this floor is
    /// 3.6 times less CPU at the chain levels for 0.2% more archive, and
    /// on `random16` it is 3.2 times less for nothing at all.
    ///
    /// The writer's store decision packs its samples at this effort too
    /// (spec G 3.8.3, `write::engine`'s `samples_say_store`).
    pub(crate) fn floor(self) -> Plan {
        Plan {
            parse: Parse::Lazy,
            depth: 1,
            enough: 32,
            back: 0,
            ..self
        }
    }

    /// What a block the incompressible sample calls empty is PARSED at.
    ///
    /// At LEVELS 1 TO 3, the ladder's chain levels, that is [`Plan::floor`]'s
    /// one link over the level's finder walked by the FLOOR SCAN
    /// (`lz::floor_scan`) instead of the lazy parse: levels 1 and 2
    /// since 30 Sep 2026, and level 3
    /// too (decided 30 Sep 2026: "wall is always what matters
    /// most. but if necessary have user options to select behavior
    /// differently"). The floor's lazy parse still searched every position
    /// of a block that has nothing in it, and on media that search is most
    /// of the CPU: counted 30 Sep 2026 on a Zen 4 rental (x86-64) over 1 GiB
    /// of a 12 GiB member, 4,091 of its 4,096 blocks went to the floor and
    /// level 1 took 69.8 CPU s where the scan takes 17.0, for an archive
    /// 82,872 bytes SMALLER, because the short matches the lazy parse takes
    /// in such bytes cost more bits than the literals they replace; timed
    /// at level 3 the big member went from 50.4 to 28.4 s (measured
    /// 30 Sep 2026).
    ///
    /// The price is on mixed media: about 0.7 percent of archive on the
    /// ladder's `media16`, which at level 3 turns a size level with
    /// reference `rar` into a larger one. `WriteOptions::level3_floor_lazy`
    /// ([`Plan::lazy_floor`]) buys it back at level 3. LEVELS 4 AND
    /// 5 keep the lazy floor: their tree walk takes every position whatever
    /// the parse. [`Plan::floor`] itself is unchanged, and so is everything
    /// else that packs at it: the store rule's samples (spec G 3.8.3) are
    /// still packed by the lazy parse, so no member's verdict moves. A
    /// bench build takes `RARKIT_FLOOR_PARSE=lazy` or `=scan` to parse the
    /// floor one way at every level, and `RARKIT_FLOOR_SCAN=<stride>:<least>`
    /// for the scan's geometry, which is how the arms are timed in one
    /// binary.
    pub(super) fn for_empty_block(self) -> Plan {
        let floor = self.floor();
        let scans = match floor_parse() {
            FloorParse::Shipped => self.scans_floor,
            FloorParse::Lazy => false,
            FloorParse::Scan => true,
        };
        if scans {
            Plan {
                parse: Parse::Scan,
                ..floor
            }
        } else {
            floor
        }
    }

    /// What a block the incompressible sample reads THIN is PARSED at
    /// where the plan scans thin blocks (level 3, [`Plan::scans_thin`]):
    /// the floor scan of [`Plan::floor`] asked at every position for a
    /// match of five bytes or more over `links` chain links
    /// (`lz::THIN_SCAN_STRIDE`, `lz::THIN_SCAN_LEAST`,
    /// `lz::THIN_SCAN_LINKS`), instead of the level's lazy parse
    /// [`LEVEL3_LINKS`] deep.
    ///
    /// A thin block (`sample::thin`) has a little to find, mostly short:
    /// on 1 GiB of a big member at level 3 on one CPU, 1,005 of 4,096 blocks read
    /// 24 to 248 per mille and their lazy parse was about half the wall
    /// (counted 14 Oct 2026 on a Zen 4 rental, x86-64).
    pub(super) fn for_thin_block(self, links: u32) -> Plan {
        Plan {
            parse: Parse::ThinScan,
            depth: links,
            ..self.floor()
        }
    }

    /// Whether this plan is already at or under the floor, so that a
    /// sample could not save anything and is not worth taking.
    ///
    /// **No shipped level is**, level 1 included. Its priced form looks
    /// three links deep where the floor looks one, and dropping that to
    /// the floor on incompressible bytes was measured at 2.00x its CPU on
    /// `random16` and 1.48x on `media16` for no archive worth the name;
    /// the fast parse looks at every position where the floor scan asks at
    /// one in sixteen, and was measured with the sample taken.
    /// The guard is here for the plans that are not on the ladder - the
    /// floor itself, and the shallow points `Plan::spelled` reaches in a
    /// sweep - so that they do not pay for a verdict that cannot change
    /// what they do.
    pub(super) fn at_floor(self) -> bool {
        self.parse == Parse::Lazy && self.depth <= Plan::floor(self).depth
    }

    /// [`Plan::floor`] and [`Plan::at_floor`], for the tests that hold
    /// the ladder's shape to account. Both are private to the driving
    /// loop otherwise, because nothing else has any business choosing an
    /// effort.
    #[cfg(test)]
    pub(crate) fn floor_for_test(self) -> Plan {
        self.floor()
    }

    #[cfg(test)]
    pub(crate) fn at_floor_for_test(self) -> bool {
        self.at_floor()
    }

    /// A plan spelled out, for the LEVEL LADDER's sweeps:
    /// `<fast|lazy|optimal>:<chain|tree>:<depth>:<enough>[:<jump>:<rungs>]`,
    /// the last two the optimal parse's [`OptimalDials`], at most
    /// [`OptimalDials::FULL`]'s jump. `fast` is level 1's parse and takes
    /// the chains only; its depth and enough are the floor scan's.
    ///
    /// The ladder is retuned by measuring points that are not shipped, and
    /// rebuilding the crate for each point of a sweep of thirty makes the
    /// sweep something nobody runs twice. This parses one point instead, so
    /// a bench script can walk the dials with one binary.
    ///
    /// It is behind `bench-internals`, which no shipped build enables, and
    /// it reads nothing from the environment: the caller names the point.
    /// Whatever a sweep lands on is then written into [`Plan::for_level`]
    /// above, and the shipped ladder is that function and only that
    /// function.
    #[cfg(feature = "bench-internals")]
    pub(crate) fn spelled(text: &str) -> Option<Plan> {
        let mut fields = text.split(':');
        let parse = match fields.next()? {
            "fast" => Parse::Fast,
            "lazy" => Parse::Lazy,
            "optimal" => Parse::Optimal,
            _ => return None,
        };
        let finder = match fields.next()? {
            "chain" => Finder::Chain,
            "tree" if parse != Parse::Fast => Finder::Tree,
            _ => return None,
        };
        let depth = fields.next()?.parse().ok()?;
        let enough = fields.next()?.parse().ok()?;
        let mut dials = OptimalDials::FULL;
        if let Some(jump) = fields.next() {
            dials.jump = jump.parse().ok()?;
            dials.rungs = fields.next()?.parse().ok()?;
            if dials.jump < 2 || dials.jump > OptimalDials::FULL.jump {
                return None;
            }
        }
        if fields.next().is_some() {
            return None;
        }
        Some(Plan {
            parse,
            finder,
            depth,
            candidates: TREE_CANDIDATE_SLOTS,
            enough,
            dials,
            lone: None,
            wide_ring: false,
            // A sweep's point as the ladder was before the non-solid wide
            // ring: a caller that wants it sets it.
            full_reach: false,
            scans_floor: finder == Finder::Chain,
            scans_thin: false,
            empty_stride: true,
            // A spelled plan is the raw plan, without the extension; a
            // sweep sets `back` itself.
            back: 0,
            far_links: None,
            pair: Pairing::shipped(),
            other: None,
        })
    }
}

/// What a block carrying a filter record is parsed at
/// (`Engine::effort_for`). `Shipped` is the only value outside a bench
/// build; a bench build takes `RARKIT_FILTER_EFFORT=level|lazy|floor` to
/// set it for every level, which is how the per-level choice
/// is measured.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FilteredEffort {
    /// Level 3 lazy, every other level its own plan.
    Shipped,
    // The record, reachable only through the bench knob.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    Level,
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    Lazy,
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    Floor,
}

/// How a block the incompressible sample calls empty is parsed
/// ([`Plan::for_empty_block`]). `Shipped` is the only value outside a
/// bench build; a bench build takes `RARKIT_FLOOR_PARSE=lazy|scan` to
/// parse it one way at every level.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FloorParse {
    /// The floor scan at levels 1 to 3 ([`Plan::scans_floor`]), the lazy
    /// floor at levels 4 and 5.
    Shipped,
    // The arms, reachable only through the bench knob.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    Lazy,
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    Scan,
}

pub(super) fn floor_parse() -> FloorParse {
    #[cfg(feature = "bench-internals")]
    {
        static PARSE: OnceLock<FloorParse> = OnceLock::new();
        *PARSE.get_or_init(|| match std::env::var("RARKIT_FLOOR_PARSE").as_deref() {
            Ok("lazy") => FloorParse::Lazy,
            Ok("scan") => FloorParse::Scan,
            _ => FloorParse::Shipped,
        })
    }
    #[cfg(not(feature = "bench-internals"))]
    FloorParse::Shipped
}

/// The floor scan's stride and least match: `lz::SCAN_STRIDE` and
/// `lz::SCAN_LEAST`, or in a bench build `RARKIT_FLOOR_SCAN=<stride>:<least>`.
pub(super) fn scan_geometry() -> (usize, usize) {
    #[cfg(feature = "bench-internals")]
    {
        static GEOMETRY: OnceLock<(usize, usize)> = OnceLock::new();
        *GEOMETRY.get_or_init(|| {
            std::env::var("RARKIT_FLOOR_SCAN")
                .ok()
                .and_then(|v| {
                    let (stride, least) = v.split_once(':')?;
                    Some((stride.parse().ok()?, least.parse().ok()?))
                })
                .filter(|&(stride, least): &(usize, usize)| stride > 0 && least >= 4)
                .unwrap_or((SCAN_STRIDE, SCAN_LEAST))
        })
    }
    #[cfg(not(feature = "bench-internals"))]
    (SCAN_STRIDE, SCAN_LEAST)
}

/// The thin scan's dials ([`Plan::for_thin_block`]): which readings are
/// thin, and the scan's stride, least match and links.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct ThinScan {
    /// A reading under this is thin (`sample::THIN_UNDER_PER_MILLE`); 0
    /// is none.
    pub(super) under: u32,
    pub(super) stride: usize,
    pub(super) least: usize,
    pub(super) links: u32,
    /// Whether a stride of one asks two positions at a time
    /// (`lz::thin_scan`); the same tokens either way.
    pub(super) paired: bool,
}

/// [`ThinScan`] as shipped, or in a build with `writer-knobs`
/// `RARKIT_THIN_SCAN=<under>:<stride>:<least>:<links>[:<paired 0|1>]`
/// (`off` for none),
/// which is how the arms are timed in one binary.
pub(super) fn thin_scan() -> ThinScan {
    static DIALS: OnceLock<ThinScan> = OnceLock::new();
    *DIALS.get_or_init(|| {
        let shipped = ThinScan {
            under: sample::THIN_UNDER_PER_MILLE,
            stride: THIN_SCAN_STRIDE,
            least: THIN_SCAN_LEAST,
            links: THIN_SCAN_LINKS,
            paired: true,
        };
        let Ok(word) = crate::knob::writer_var("RARKIT_THIN_SCAN") else {
            return shipped;
        };
        if word == "off" {
            return ThinScan {
                under: 0,
                ..shipped
            };
        }
        let fields: Vec<&str> = word.split(':').collect();
        let paired = match fields.get(4) {
            None | Some(&"1") => Some(true),
            Some(&"0") => Some(false),
            Some(_) => None,
        };
        match fields[..] {
            [under, stride, least, links] | [under, stride, least, links, _] => (|| {
                Some(ThinScan {
                    under: under.parse().ok()?,
                    stride: stride.parse().ok().filter(|&s: &usize| s > 0)?,
                    least: least.parse().ok().filter(|&l: &usize| l >= 4)?,
                    links: links.parse().ok().filter(|&l: &u32| l > 0)?,
                    paired: paired?,
                })
            })()
            .unwrap_or(shipped),
            _ => shipped,
        }
    })
}

pub(super) fn filtered_effort() -> FilteredEffort {
    #[cfg(feature = "bench-internals")]
    {
        static EFFORT: OnceLock<FilteredEffort> = OnceLock::new();
        *EFFORT.get_or_init(|| match std::env::var("RARKIT_FILTER_EFFORT").as_deref() {
            Ok("floor") => FilteredEffort::Floor,
            Ok("lazy") => FilteredEffort::Lazy,
            Ok("level") => FilteredEffort::Level,
            _ => FilteredEffort::Shipped,
        })
    }
    #[cfg(not(feature = "bench-internals"))]
    FilteredEffort::Shipped
}
