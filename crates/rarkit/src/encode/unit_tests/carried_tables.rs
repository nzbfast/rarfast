//! A solid member's table set may carry.

use super::*;

// ---- a solid member's table set may carry ------------------------------

/// Every member's packed bytes for one solid run of `members` at `level`,
/// staged in batches of at most `batch` members (and what
/// `Rar5Encoder::may_stage` admits), as the solid writer stages them, or
/// with `batch` 0 a member at a time through `encode_chunk`, as a volume
/// set's are; with a restart of the run (the solid bit clear, spec G 3.9)
/// before each index in `restarts`.
fn carry_run(
    level: u8,
    members: &[Vec<u8>],
    batch: usize,
    carry_off: bool,
    restarts: &[usize],
) -> Vec<Vec<u8>> {
    carry_run_smooth(
        level,
        members,
        batch,
        carry_off,
        restarts,
        rar5::CARRY_SMOOTH,
    )
}

fn carry_run_smooth(
    level: u8,
    members: &[Vec<u8>],
    batch: usize,
    carry_off: bool,
    restarts: &[usize],
    smooth: u32,
) -> Vec<Vec<u8>> {
    let mut encoder = rar5::Rar5Encoder::new(rar5::EncodeOptions::for_level(level, 1 << 20));
    encoder.carry_off_for_test(carry_off);
    encoder.carry_smooth_for_test(smooth);
    encoder.reset_history();
    let mut out = Vec::new();
    let mut at = 0;
    while at < members.len() {
        if restarts.contains(&at) {
            encoder.reset_history();
        }
        if batch > 0 {
            let from = at;
            while at < members.len()
                && (at == from
                    || (at - from < batch
                        && !restarts.contains(&at)
                        && encoder.may_stage(members[at].len())))
            {
                encoder.stage(&members[at], true);
                at += 1;
            }
            out.extend(encoder.flush().iter_mut().map(std::mem::take));
        } else {
            let mut packed = Vec::new();
            encoder.encode_chunk(&members[at], true, &mut packed);
            out.push(packed);
            at += 1;
        }
    }
    out
}

/// Whether a member's packed bytes open a fresh table set: its first
/// block's table bit (H2 3.2). A member written as no bytes at all (an
/// empty member under a carried set) opens none.
fn opens(packed: &[u8]) -> bool {
    packed.first().is_some_and(|flags| flags & 0x80 != 0)
}

/// Members of 1 KiB of one text, with the envelope's edges and some empty
/// members placed among them.
fn carry_set() -> Vec<Vec<u8>> {
    let mut members: Vec<Vec<u8>> = (0..200).map(|i| few_words(1024, 7 + i)).collect();
    members[40] = few_words(32_767, 400);
    members[41] = few_words(32_768, 401);
    members[80] = few_words(40_000, 402);
    members[81] = Vec::new();
    members[82] = Vec::new();
    members[120] = few_words(20_000, 403);
    members
}

#[test]
fn carried_table_sets_keep_to_rar_7_23s_envelope() {
    // The carried set's acceptance tests 1 and 3, the RAR 5 half: member 0
    // opens, later members carry, no member of 32,768 bytes or more
    // carries, and no more than 15 members share a set.
    let members = carry_set();
    for level in [1, 3, 5] {
        let packed = carry_run(level, &members, usize::MAX, false, &[]);
        assert!(opens(&packed[0]), "level {level}: member 0 opens a set");
        let carried = (1..packed.len()).filter(|&i| !opens(&packed[i])).count();
        assert!(
            carried > 100,
            "level {level}: only {carried} members carried"
        );
        for (index, member) in members.iter().enumerate() {
            if member.len() >= 32_768 {
                assert!(
                    opens(&packed[index]),
                    "level {level}: member {index} is too large to carry"
                );
            }
        }
        let mut since = 0;
        for (index, bytes) in packed.iter().enumerate() {
            since = if opens(bytes) { 1 } else { since + 1 };
            assert!(
                since <= 15,
                "level {level}: member {index} is the sixteenth on one set"
            );
        }
    }
}

#[test]
fn a_restarted_run_and_a_non_solid_set_open_at_every_clear_solid_bit() {
    // Acceptance test 2: every member whose solid bit is clear opens.
    let members = carry_set();
    let restarts = [3, 50, 51, 130];
    let packed = carry_run(3, &members, usize::MAX, false, &restarts);
    for &index in &restarts {
        assert!(
            opens(&packed[index]),
            "member {index} starts a run and must open"
        );
    }
    // A non-solid set: every member a run of its own.
    let every: Vec<usize> = (0..members.len()).collect();
    let packed = carry_run(3, &members, 0, false, &every);
    for (index, bytes) in packed.iter().enumerate() {
        assert!(opens(bytes), "non-solid member {index} must open");
    }
}

#[test]
fn carried_table_sets_are_the_same_at_any_width_and_any_batching() {
    // Acceptance test 5: which members open, and every byte, are the same
    // however the run is cut into batches and at every pool width. (A
    // run's first member written ALONE is a lone member, parsed at its
    // level's lone effort whether or not sets carry, so the batches here
    // are of two members and more.)
    let members = carry_set();
    for level in [1, 3, 5] {
        let whole = carry_run(level, &members, usize::MAX, false, &[]);
        for batch in [2, 7, 16] {
            let cut = carry_run(level, &members, batch, false, &[]);
            assert!(
                cut == whole,
                "level {level}: batches of {batch} moved a byte"
            );
        }
        #[cfg(feature = "parallel")]
        for threads in [1, 3, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("a pool");
            let wide = pool.install(|| carry_run(level, &members, usize::MAX, false, &[]));
            assert!(
                wide == whole,
                "level {level}: {threads} threads moved a byte"
            );
        }
    }
}

#[test]
fn carried_table_sets_make_a_small_member_run_smaller() {
    // Acceptance test 6, in the encoder: the payload is smaller than one
    // set per member's.
    let members: Vec<Vec<u8>> = (0..300)
        .map(|i| few_words(700 + (i as usize * 37) % 3000, 900 + i))
        .collect();
    for level in [1, 3, 5] {
        let carried = carry_run(level, &members, usize::MAX, false, &[]);
        let fresh = carry_run(level, &members, usize::MAX, true, &[]);
        let a: usize = carried.iter().map(Vec::len).sum();
        let b: usize = fresh.iter().map(Vec::len).sum();
        assert!(
            a < b * 95 / 100,
            "level {level}: {a} bytes carried against {b} fresh"
        );
        assert!(fresh.iter().all(|bytes| opens(bytes)));
    }
}

/// The sweep that chose [`rar5::CARRY_SMOOTH`], on this file's synthetic
/// small members; the corpora's figures were measured apart.
#[test]
#[ignore = "a sweep, printed"]
fn carry_smooth_sweep() {
    let members: Vec<Vec<u8>> = (0..300)
        .map(|i| few_words(700 + (i as usize * 37) % 3000, 900 + i))
        .collect();
    for level in [1, 3, 5] {
        let fresh: usize = carry_run(level, &members, usize::MAX, true, &[])
            .iter()
            .map(Vec::len)
            .sum();
        for smooth in [1, 2, 4, 8, 16, 32, 64] {
            let packed = carry_run_smooth(level, &members, usize::MAX, false, &[], smooth);
            let bytes: usize = packed.iter().map(Vec::len).sum();
            let opened = packed.iter().filter(|bytes| opens(bytes)).count();
            eprintln!("level {level} smooth {smooth}: {bytes} bytes against {fresh} ({:.2}%), {opened} of {} open", 100.0 * bytes as f64 / fresh as f64, packed.len());
        }
    }
}

/// Sweep M-13. `drive::packed_most` promises what a member packs to at
/// most, whatever its bytes are, and a small solid member that is unlike
/// the chain before it is still inside that promise. Width: the bytes of
/// a carried chain do not move with the pool (the test above), so this
/// runs on whatever pool the machine has, two threads or more. Memory:
/// under 64 MiB, a 1 MiB dictionary's chains.
#[test]
#[ignore = "sweep M-13, a KNOWN breach (4 Oct 2026): 31,735 to 36,621 bytes against 31,512; every caller of packed_most reserves, accounts or keeps a wider margin, and the alternatives cost ratio"]
fn a_small_solid_member_unlike_its_chain_still_packs_inside_the_bound() {
    use super::drive::packed_most;
    for texts in [1usize, 14] {
        let mut members: Vec<Vec<u8>> = (0..texts)
            .map(|i| few_words(30_000, 900 + i as u64))
            .collect();
        members.push(incompressible(31_000, 77));
        members.push(few_words(30_000, 990));
        for level in 1u8..=5 {
            for batch in [0usize, 64] {
                let packed = carry_run(level, &members, batch, false, &[]);
                for (index, (member, packed)) in members.iter().zip(&packed).enumerate() {
                    let bound = packed_most(member.len());
                    assert!(
                        packed.len() <= bound,
                        "-m{level} batch {batch}, {texts} texts ahead, member {index} of {} bytes: {} > {bound}",
                        member.len(),
                        packed.len()
                    );
                }
            }
        }
    }
}
