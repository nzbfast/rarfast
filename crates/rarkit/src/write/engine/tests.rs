//! The run's own unit tests: the bar a member of few stretches takes the
//! segment team by.

use super::*;

#[cfg(all(test, feature = "parallel"))]
mod few_stretches {
    use super::few_stretches_take_the_team;

    /// Levels 2 and 3, which share one row.
    fn takes(stretches: usize, blocks: usize, pool: usize, afforded: usize) -> bool {
        let at3 = few_stretches_take_the_team(3, stretches, blocks, pool, afforded);
        assert_eq!(
            at3,
            few_stretches_take_the_team(2, stretches, blocks, pool, afforded)
        );
        at3
    }

    /// The rows the bar was placed by, as (stretches, blocks of a window,
    /// pool threads, engines afforded): the member's windows must be able
    /// to fill the pool, and the team as afforded is no smaller than its
    /// window asks: four engines at 2 MiB windows, three at 4 MiB, two
    /// at 8 MiB.
    #[test]
    fn a_member_of_few_stretches_takes_the_team_by_its_blocks_and_its_afforded_engines() {
        // A 64 MiB member at 2 and 4 MiB windows on 36 and 64 threads:
        // 32 blocks in flight never fill the pool.
        assert!(!takes(4, 8, 36, 4));
        assert!(!takes(4, 8, 64, 4));
        assert!(!takes(2, 16, 64, 2));
        // A 128 MiB member: eight stretches of 2 MiB windows fill 36 and
        // 64 threads; two stretches of 8 MiB windows fill 64.
        assert!(takes(8, 8, 36, 8));
        assert!(takes(8, 8, 64, 8));
        assert!(takes(2, 32, 64, 2));
        // A 1 GiB member at 8 MiB windows: sixteen stretches.
        assert!(takes(16, 32, 64, 16));
        // The same members where the memory affords fewer engines, on 64
        // and on 36 threads alike: at 2 MiB windows three are refused and
        // four are not; at 4 MiB two are refused and three are not; at
        // 8 MiB two are a team.
        for pool in [36, 64] {
            assert!(!takes(16, 8, pool, 2) && !takes(16, 8, pool, 3));
            assert!(takes(16, 8, pool, 4));
            assert!(!takes(8, 16, pool, 2));
            assert!(takes(8, 16, pool, 3));
            assert!(takes(4, 32, pool, 2));
            // One engine is never a team.
            assert!(!takes(16, 8, pool, 1) && !takes(4, 32, pool, 1));
        }
        // A window under 2 MiB has no row: the member of few stretches
        // stays the one engine's, however many it has.
        assert!(!takes(7, 4, 8, 7) && !takes(6, 1, 8, 6) && !takes(20, 4, 64, 20));
        // The pool's width does not move the engine count: on 96 and on
        // 192 threads the same four, three and two.
        for pool in [96, 192] {
            assert!(!takes(24, 8, pool, 3) && takes(24, 8, pool, 4));
            assert!(!takes(24, 16, pool, 2) && takes(24, 16, pool, 3));
            assert!(takes(24, 32, pool, 2));
        }
        // Levels 4 and 5 ask one engine more of 2 MiB windows, and the
        // same of 4 and 8 MiB.
        for level in [4u8, 5] {
            assert!(!few_stretches_take_the_team(level, 16, 8, 64, 4));
            assert!(few_stretches_take_the_team(level, 16, 8, 64, 5));
            assert!(!few_stretches_take_the_team(level, 8, 16, 64, 2));
            assert!(few_stretches_take_the_team(level, 8, 16, 64, 3));
            assert!(few_stretches_take_the_team(level, 4, 32, 64, 2));
            assert!(!few_stretches_take_the_team(level, 4, 8, 64, 4));
            assert!(!few_stretches_take_the_team(level, 20, 4, 64, 20));
        }
    }
}

#[cfg(all(test, feature = "parallel"))]
mod team_cores {
    use super::segment_engines;

    /// The rule by cores (`segment_engines`): level 1 from sixteen
    /// physical cores, levels 2 to 5 from twenty (an M1 Ultra's, 16
    /// performance and 4 efficiency), an engine to two cores, at most 24.
    /// A sixteen-core machine keeps one engine above level 1. No pool and
    /// no memory: a function of its two arguments.
    #[test]
    fn the_team_s_engines_by_level_and_cores() {
        assert_eq!(segment_engines(1, 15), 1);
        assert_eq!(segment_engines(1, 16), 8);
        for level in 2u8..=5 {
            assert_eq!(segment_engines(level, 16), 1, "-m{level} on 16 cores");
            assert_eq!(segment_engines(level, 19), 1, "-m{level} on 19 cores");
            assert_eq!(segment_engines(level, 20), 10, "-m{level} on 20 cores");
            assert_eq!(segment_engines(level, 32), 16, "-m{level} on 32 cores");
            assert_eq!(segment_engines(level, 192), 24, "-m{level} on 192 cores");
        }
        assert_eq!(segment_engines(0, 64), 1, "a stored member has no team");
    }
}
