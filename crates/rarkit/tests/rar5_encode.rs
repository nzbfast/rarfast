//! Spec H3 section 9.2: the RAR 5 encoder's output is ADMITTED by
//! reference `unrar` 7.23 and extracted byte for byte.
//!
//! That assertion is required and not a nice to have. An encoder and a
//! decoder that agree with each other and not with the format is the
//! defect open question 1 records, and it went unnoticed for as long as
//! the fixtures came from the same engine. Until spec H2's decoder is on
//! `main` there is no round trip through rarkit itself, so this is the
//! whole verdict.

mod support {
    pub mod rar5build;
}

use rarkit::internals::{rar20, rar5};
use std::io::Write;
use std::process::Command;
use support::rar5build::{archive, Member};

/// The dictionary every case here uses: 128 KiB, exponent zero.
const DICTIONARY: u32 = 128 * 1024;

/// Whether reference `unrar` is on PATH. Without it the admission test
/// cannot run, and the spec says so rather than passing quietly.
fn unrar() -> Option<String> {
    let found = Command::new("unrar").arg("-iver").output().ok()?;
    found
        .status
        .success()
        .then(|| String::from_utf8_lossy(&found.stdout).trim().to_string())
}

/// Encode `input`, wrap it in the smallest archive that can carry it,
/// hand it to reference `unrar`, and compare what comes out.
fn admitted(name: &str, input: &[u8], level: u8) {
    let Some(_) = unrar() else {
        eprintln!("reference unrar is not on PATH: {name} not admitted");
        return;
    };
    let packed = rar20::rar5_encode(input, level, DICTIONARY);
    let bytes = archive(&[Member {
        name: "MEMBER.BIN",
        unpacked: input,
        packed: &packed,
        dictionary_exponent: 0,
        method: 3,
        solid: false,
    }]);

    let dir = std::env::temp_dir().join(format!("rarkit-h3-{name}-{level}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    let path = dir.join("test.rar");
    std::fs::File::create(&path)
        .expect("the archive")
        .write_all(&bytes)
        .expect("written");

    let run = Command::new("unrar")
        .arg("x")
        .arg("-y")
        .arg(&path)
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    assert!(
        run.status.success(),
        "{name} level {level}: unrar refused the archive\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let out = std::fs::read(dir.join("MEMBER.BIN")).expect("the extracted member");
    assert_eq!(out.len(), input.len(), "{name} level {level}: wrong length");
    assert_eq!(out, input, "{name} level {level}: wrong bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A deterministic pseudo random generator, so no case depends on system
/// entropy and every failure reproduces.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect()
}

#[test]
fn an_empty_member_is_admitted() {
    admitted("empty", b"", 3);
}

#[test]
fn a_single_byte_is_admitted() {
    admitted("one", b"A", 3);
}

#[test]
fn one_repeated_byte_is_admitted() {
    // One byte value over and over: an alphabet here is used for a single
    // symbol, the case SPEC-H3 6.3 item 1 closes with a symbol never sent.
    admitted("runs", &vec![b'A'; 70_000], 3);
}

#[test]
fn text_is_admitted_at_every_level() {
    let input = rarkit_testdata::chatter(0x7072, 400_000);
    for level in [1u8, 3, 5] {
        admitted("text", &input, level);
    }
}

#[test]
fn incompressible_bytes_are_admitted() {
    admitted("noise", &noise(300_000, 7), 3);
}

#[test]
fn a_member_longer_than_one_entropy_block_is_admitted() {
    // Several blocks in the chain, so the last flag and the block walk
    // are both exercised.
    let mut input = rarkit_testdata::chatter(0x7072, 900_000);
    input.extend_from_slice(&noise(200_000, 11));
    admitted("multiblock", &input, 3);
}

#[test]
fn members_with_incompressible_stretches_or_long_repeats_are_admitted_at_every_level() {
    // The shape the packed block ceiling exists for (SPEC-H3 6.2 as
    // counted in the unrar-friendly work): incompressible stretches of
    // several parse blocks between text, which now leave as several
    // blocks each under the ceiling rather than one block per parse block.
    let mut input = rarkit_testdata::chatter(3, 300_000);
    input.extend_from_slice(&noise(800_000, 5));
    input.extend_from_slice(&rarkit_testdata::chatter(9, 300_000));
    input.extend_from_slice(&noise(300_000, 13));
    let repetitive: Vec<u8> = (0..1_200_000u32)
        .map(|i| b"abcab"[(i % 5) as usize])
        .collect();
    for level in 1u8..=5 {
        admitted("mixed", &input, level);
        admitted("repetitive", &repetitive, level);
    }
}

#[test]
fn far_matches_across_the_bonus_bands_are_admitted() {
    // Distances in each of the three bonus bands, so a forgotten bonus
    // subtraction writes matches short and unrar reports a data error.
    let mut input = Vec::new();
    let seed = rarkit_testdata::chatter(0x7072, 600);
    input.extend_from_slice(&seed);
    for gap in [0x80usize, 0x1000, 0x8000, 0x50000] {
        input.extend_from_slice(&noise(gap, gap as u32));
        input.extend_from_slice(&seed);
    }
    admitted("bonus", &input, 5);
}

#[test]
fn the_same_input_and_options_give_byte_identical_output() {
    // API promise 6, which section 4 restates as a promise and not a
    // target, and section 9.2 pins at 1, 2, 4 and 8 threads. The input is
    // longer than several parse blocks, so the finder's walkers, the
    // chains' inserting pass and the blocks in flight all really do run
    // beside one another at the wider counts.
    let mut input = rarkit_testdata::chatter(4, 2_500_000);
    input.extend_from_slice(&noise(300_000, 3));
    input.extend_from_slice(&rarkit_testdata::chatter(6, 1_500_000));
    for level in [1u8, 3, 5] {
        let first = rar20::on_threads(1, || rar20::rar5_encode(&input, level, DICTIONARY));
        for threads in [2usize, 4, 8] {
            let again =
                rar20::on_threads(threads, || rar20::rar5_encode(&input, level, DICTIONARY));
            assert!(
                again == first,
                "level {level}: {threads} threads wrote different bytes from one"
            );
        }
        assert!(
            rar20::rar5_encode(&input, level, DICTIONARY) == first,
            "level {level}: the default pool wrote different bytes from one thread"
        );
    }
}

#[test]
fn an_encoder_reused_for_a_second_member_writes_what_a_fresh_one_does() {
    // Section 8.3, structural requirement 2: the encoder keeps its memory
    // between members. What it keeps must not reach the bytes.
    let first = rarkit_testdata::chatter(21, 1_400_000);
    let second = rarkit_testdata::chatter(22, 700_000);
    let third = noise(50_000, 23);
    for level in [1u8, 3, 5] {
        let each = rar20::rar5_encode_each(&[&first, &second, &third, &second], level, DICTIONARY);
        for (got, input) in each.iter().zip([&first, &second, &third, &second]) {
            assert!(
                *got == rar20::rar5_encode(input, level, DICTIONARY),
                "level {level}: a reused encoder wrote different bytes"
            );
        }
    }
}

#[test]
fn the_archive_size_for_a_fixed_corpus_is_recorded() {
    // Section 9.2: the ratio goes in a test as a NUMBER, so a change that
    // trades ratio for wall shows up in the diff rather than in a bench
    // run nobody ran. Raise or lower these deliberately.
    let input = rarkit_testdata::chatter(5, 1 << 20);
    let sizes: Vec<usize> = [1u8, 2, 3, 4, 5]
        .iter()
        .map(|&level| rar20::rar5_encode(&input, level, DICTIONARY).len())
        .collect();
    assert!(
        sizes.windows(2).all(|pair| pair[0] >= pair[1]),
        "a higher level must not compress worse: {sizes:?}"
    );
    // The figures this encoder produces today on this corpus, exactly:
    // the output is a function of the input and the options alone, so
    // they hold on every platform and at every thread count.
    assert_eq!(sizes, RECORDED_SIZES, "the recorded archive sizes moved");
    // What levels 4 and 5 wrote before the lazy tree parse, and their options
    // still write: the optimal parse over the tree.
    for (plan, size) in [("optimal:tree:8:0", 163553), ("optimal:tree:32:0", 148828)] {
        let old = rar20::rar5_encode_spelled(&input, plan, DICTIONARY).expect("a plan");
        assert_eq!(old.len(), size, "{plan}");
    }
}

/// What the megabyte of shared test text, `chatter(5, 1 << 20)`, packs to at levels 1 to 5 with a 128 KiB
/// dictionary.
///
/// Moved 19 Sep 2026 when `REACH_HELD_BACK` was removed from
/// `src/encode/drive.rs`: the encoder held its reach 64 bytes short of the
/// dictionary while spec H2's decoder could not read the last of it, and
/// now reaches the whole of it again. Levels 2, 3 and 4 gain 1, 15 and 9
/// bytes; level 5 LOSES 47. That is not a regression in the parse and
/// nothing was traded for it: 64 more bytes of reach move a handful of
/// matches into longer distance slots, and at level 5 the alphabet those
/// slots are priced against shifts by more than the matches save. It is
/// 0.02% either way on a megabyte, and holding the reach back to recover
/// it would put the defect's workaround back for nothing.
///
/// **Moved 19 Sep 2026 by the LEVEL LADDER retune** (`Plan::for_level`). Levels 2, 3
/// and 4 write MORE here and it is deliberate: the old ladder's last two
/// steps were 1.31x and 1.16x its level 1's CPU where its first was
/// 3.25x, so the middle of the range was empty and its level 3 was off
/// the measured frontier entirely. The retuned ladder is four steps of
/// 1.78x, 3.14x, 1.91x and 1.48x, and this corpus - a megabyte of
/// word-shuffled text at the smallest dictionary the format has - is the
/// shape the retune costs the most on, because it has no long range
/// structure for the cheaper rungs' chains to find. On the six corpora of
/// the ladder script the same change is worth 2.0x to 3.7x the CPU on
/// incompressible bytes and removes a dominated rung; on this one it is
/// +7.0% at level 2, +8.1% at level 3 and +9.5% at level 4, with levels 1
/// and 5 unmoved.
///
/// **Moved 30 Sep 2026** (level 3 is the lazy parse 64
/// chain links deep, `Plan::for_level`): level 3 writes 240,949 to 227,006
/// bytes (-5.79 percent), the other levels unmoved. On this corpus, word
/// shuffled text whose repeats sit far apart, the deeper chain walk finds
/// matches the optimal parse's 8 links did not reach. That change was
/// CONDITIONAL on its timed runs; `WriteOptions::level3_optimal` writes
/// the old figure.
///
/// **Moved 30 Sep 2026 by the BACKWARD EXTENSION** (`lz::BACK_LIMIT`, a
/// parse begins an offered chain match where it really begins) and level
/// 3's lazy parse at `drive::LEVEL3_LINKS` (32) links instead of 64, the
/// default chosen (the faster
/// wall, timed on both architectures): level 3 writes 227,006 to 233,797
/// (+2.99 percent), since half the links reach fewer of this corpus's far
/// repeats, and is still above level 4; the other levels are unmoved
/// (levels 1 and 2 keep the extension off by default).
/// `WriteOptions::level3_deep` (64 links with the extension) writes
/// 223,083, and `WriteOptions::low_levels_extend` 261,152 and 248,759 at
/// levels 1 and 2. On the timed corpora level 3's default is 6 to 42
/// percent less create wall than 64 links for 0.994 to 1.000 of the bytes
/// (1.0025 on code32), measured 30 Sep 2026.
///
/// **Moved 1 Oct 2026**: levels 4 and 5 take the lazy parse
/// over the tree (cut 12 and 16, one hint slot, the full reach) in place
/// of the optimal parse, for 1.1x to 2.3x less create wall: level 4 writes
/// 216,610 to 217,559 and level 5 196,751 to 208,903 here, both still under level 3. The old
/// figures are what `WriteOptions::level4_optimal` / `level5_optimal`
/// write (`optimal:tree:8:0` and `optimal:tree:32:0`), checked below.
///
/// **Moved 1 Oct 2026** (level 1 is the fast parse over
/// chains keyed on six bytes, `Plan::for_level`): level 1 writes 269,509
/// to 261,147 bytes (-3.10 percent), still above level 2; levels 2 to 5
/// are unmoved by it. On this corpus, word shuffled text whose repeats sit far
/// apart, a six byte chain's nearest position is a better match than the
/// three nearest of a four byte chain; on the timed corpora the fast
/// parse writes 0.2 to 5.6 percent MORE than the level 1 it replaces, for
/// 0.40x to 0.76x of its create wall
/// (measured 30 Sep 2026).
/// `WriteOptions::level1_priced` writes the old figure, and
/// `tests/level1_parse.rs` holds it and levels 2 to 5 to their bytes of
/// before the change.
///
/// **Moved 1 Oct 2026 by the ladder's order** (SPEC-H3 8.1, "LEVEL 4 RUNS
/// THE CHAINS" and "Levels 4 and 5 take the BACKWARD EXTENSION"): level 4
/// is level 3's lazy parse over the chains at 64 links with the backward
/// extension, 217,559 to 223,083 here (this corpus is word shuffled text,
/// where the chains give up bytes for their wall;
/// `WriteOptions::level4_tree` keeps the tree), and level 5's lazy tree
/// plan takes the extension, 208,903 to 208,227.
/// Levels 1 to 3 are unmoved, and the order holds.
///
/// **Moved 1 Oct 2026 by LEVEL 5 BY CLASS** (SPEC-H3 8.1, `Plan::for_level`
/// and `encode::class`): this megabyte's head reads under the level's
/// cut-off, so level 5 writes it over the chains at 80 links, 208,227 to
/// 220,299 (5.8 percent more, for the chains' wall; word shuffled text is
/// where the chains give up most, and `WriteOptions::level5_tree` keeps
/// the tree). Levels 1 to 4 are unmoved, and the order holds: level 5 is
/// under level 4 by 1.2 percent.
///
/// **Taken again 11 Oct 2026, on new test text.** The megabyte is the
/// shared test data makers' now and every figure here was taken from
/// that day's build, whose engine had not moved; the history above is
/// of the figures the earlier text gave, the last of them five lines up.
const RECORDED_SIZES: [usize; 5] = [206_273, 193_617, 177_507, 170_526, 168_187];

#[test]
fn every_seeded_input_round_trips_through_reference_unrar() {
    // Section 9.2's round trip, for every input shape the vectors name,
    // against the only decoder available until spec H2's lands.
    for (name, input) in [
        ("zeros", vec![0u8; 200_000]),
        ("ramp", (0..200_000).map(|i| (i % 251) as u8).collect()),
        (
            "twobyte",
            (0..200_000)
                .map(|i| if i % 2 == 0 { 0xaa } else { 0x55 })
                .collect(),
        ),
        ("sparse", {
            let mut v = vec![b' '; 200_000];
            for at in (0..v.len()).step_by(997) {
                v[at] = b'#';
            }
            v
        }),
    ] {
        admitted(name, &input, 5);
    }
}

/// Encode with this package and decode with spec H2's, which is the round
/// trip section 9.2 asks for.
fn round_trips(name: &str, input: &[u8], level: u8) {
    let packed = rar20::rar5_encode(input, level, DICTIONARY);
    for parallel in [false, true] {
        let out = rar5::decode_member(
            &packed,
            input.len() as u64,
            u64::from(DICTIONARY),
            0,
            parallel,
        )
        .unwrap_or_else(|e| panic!("{name} level {level} parallel {parallel}: {e}"));
        assert_eq!(
            out, input,
            "{name} level {level} parallel {parallel}: wrong bytes"
        );
    }
}

#[test]
fn every_shape_round_trips_through_rarkits_own_decoder() {
    // The same shapes the admission tests use, through spec H2's decoder.
    // Determinism at any thread count is an API promise, so both
    // settings of `parallel` must give the input back.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("one", b"A".to_vec()),
        ("runs", vec![b'A'; 70_000]),
        ("text", rarkit_testdata::chatter(0x7072, 400_000)),
        ("soup", rarkit_testdata::chatter(9, 2_300_000)),
        ("noise", noise(300_000, 7)),
        ("zeros", vec![0u8; 200_000]),
        ("ramp", (0..200_000).map(|i| (i % 251) as u8).collect()),
        ("multiblock", {
            let mut v = rarkit_testdata::chatter(0x7072, 900_000);
            v.extend_from_slice(&noise(200_000, 11));
            v
        }),
        ("bonus", {
            let mut v = Vec::new();
            let seed = rarkit_testdata::chatter(0x7072, 600);
            v.extend_from_slice(&seed);
            for gap in [0x80usize, 0x1000, 0x8000, 0x50000] {
                v.extend_from_slice(&noise(gap, gap as u32));
                v.extend_from_slice(&seed);
            }
            v
        }),
    ];
    for (name, input) in cases {
        for level in [1u8, 3, 5] {
            round_trips(name, &input, level);
        }
    }
}

// ---- spec H3 section 4: the solid encoder state -----------------------

/// A solid set's members: each the one before it with a line changed, so
/// the history is worth reaching into, which is what a solid set is for.
fn solid_members(count: usize, each: usize, seed: u32) -> Vec<Vec<u8>> {
    let base = rarkit_testdata::chatter((seed) as u64, each);
    (0..count)
        .map(|n| {
            let mut member = base.clone();
            let at = (n * 977) % member.len().saturating_sub(40).max(1);
            member[at..at + 8].copy_from_slice(b"CHANGED!");
            member.extend_from_slice(&noise(64, seed + n as u32));
            member
        })
        .collect()
}

#[test]
fn a_carried_index_keeps_its_size_bound_against_a_rebuilt_one() {
    // Spec H3 section 4, "What a carried index may cost in size": the
    // index a solid set carries from member to member, against one built
    // again for every member, does NOT always give the smaller archive.
    // What is owed is a bound. At level 5 (the tree) no set comes out
    // more than 0.7 percent larger carried than rebuilt, and over many
    // sets together the carried index is no larger in sum; at levels 1
    // to 4 (the chains) the two are the same size within 0.03 percent on
    // any one set. The two arms differ in the index alone.
    //
    // Eight sets of five members of 90,000 bytes. One thread; under
    // 64 MiB.
    let mut sums = [(0usize, 0usize); 5];
    for seed in 31..39u32 {
        let members = solid_members(5, 90_000, seed);
        let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
        for level in [1u8, 2, 3, 4, 5] {
            let carried: usize = rar20::rar5_encode_solid(&borrowed, level, DICTIONARY)
                .iter()
                .map(Vec::len)
                .sum();
            let rebuilt: usize = rar20::rar5_encode_solid_rebuilt(&borrowed, level, DICTIONARY)
                .iter()
                .map(Vec::len)
                .sum();
            let what = format!("set {seed} level {level}: {carried} carried, {rebuilt} rebuilt");
            if level == 5 {
                assert!(
                    carried * 1_000 <= rebuilt * 1_007,
                    "{what}: over 0.7 percent"
                );
            } else {
                assert!(
                    carried.abs_diff(rebuilt) * 10_000 <= rebuilt * 3,
                    "{what}: over 0.03 percent apart"
                );
            }
            let sum = &mut sums[usize::from(level) - 1];
            *sum = (sum.0 + carried, sum.1 + rebuilt);
        }
    }
    let (carried, rebuilt) = sums[4];
    assert!(
        carried <= rebuilt,
        "level 5, eight sets in sum: {carried} carried against {rebuilt} rebuilt"
    );
}

#[test]
fn a_solid_set_reaches_into_the_members_before_it() {
    // What a solid set is for, as a number: the same members are smaller
    // together than apart, at every level.
    let members = solid_members(6, 60_000, 77);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 3, 5] {
        let solid: usize = rar20::rar5_encode_solid(&borrowed, level, DICTIONARY)
            .iter()
            .map(Vec::len)
            .sum();
        let apart: usize = rar20::rar5_encode_each(&borrowed, level, DICTIONARY)
            .iter()
            .map(Vec::len)
            .sum();
        assert!(
            solid * 4 < apart,
            "level {level}: solid {solid} against {apart} apart, which is no gain"
        );
    }
}

#[test]
fn a_solid_set_round_trips_through_rarkits_own_decoder() {
    let members = solid_members(6, 60_000, 12);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 2, 3, 4, 5] {
        let packed = rar20::rar5_encode_solid(&borrowed, level, DICTIONARY);
        let chain: Vec<(&[u8], u64)> = packed
            .iter()
            .zip(&members)
            .map(|(p, m)| (p.as_slice(), m.len() as u64))
            .collect();
        for parallel in [false, true] {
            let out = rar5::decode_solid_chain(&chain, u64::from(DICTIONARY), 0, parallel)
                .expect("a solid chain decodes");
            assert!(
                out == members,
                "level {level}: the solid chain read back wrong"
            );
        }
    }
}

#[test]
fn a_solid_set_is_admitted_by_reference_unrar() {
    // Section 9.2's required assertion, over the shape spec G 3.9 names:
    // the first member clear of the solid bit, every one after it
    // carrying it, and one dictionary for the whole set.
    let Some(_) = unrar() else {
        eprintln!("reference unrar is not on PATH: the solid set is not admitted");
        return;
    };
    let members = solid_members(4, 40_000, 5);
    let level = 3;
    let packed = rar20::rar5_encode_solid(
        &members.iter().map(|m| m.as_slice()).collect::<Vec<_>>(),
        level,
        DICTIONARY,
    );
    let built: Vec<Member> = members
        .iter()
        .zip(&packed)
        .enumerate()
        .map(|(n, (unpacked, packed))| Member {
            name: ["A.BIN", "B.BIN", "C.BIN", "D.BIN"][n],
            unpacked,
            packed,
            dictionary_exponent: 0,
            method: 3,
            solid: n > 0,
        })
        .collect();
    let bytes = archive(&built);

    let dir = std::env::temp_dir().join(format!("rarkit-h3-solid-set-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    let path = dir.join("test.rar");
    std::fs::File::create(&path)
        .expect("the archive")
        .write_all(&bytes)
        .expect("written");
    let run = Command::new("unrar")
        .arg("x")
        .arg("-y")
        .arg(&path)
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    assert!(
        run.status.success(),
        "unrar refused the solid set: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    for (n, member) in members.iter().enumerate() {
        let got = std::fs::read(dir.join(["A.BIN", "B.BIN", "C.BIN", "D.BIN"][n]))
            .expect("unrar wrote the member");
        assert!(got == *member, "member {n} came out different");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_windowed_member_round_trips_at_every_window() {
    // Spec G 3.7.3: one member fed a window at a time is the same member.
    let input = rarkit_testdata::chatter(44, 900_000);
    for level in [1u8, 3, 5] {
        for window in [DICTIONARY as usize, 300_000, 1 << 20] {
            let packed = rar20::rar5_encode_windowed(&input, window, level, DICTIONARY);
            let out =
                rar5::decode_member(&packed, input.len() as u64, u64::from(DICTIONARY), 0, false)
                    .expect("a windowed member decodes");
            assert!(
                out == input,
                "level {level} window {window}: read back wrong"
            );
        }
    }
}

#[test]
fn a_solid_set_is_byte_identical_at_every_thread_count() {
    // API promise 6 over the carried state: the index a member continues
    // from must not depend on how many threads built it.
    let members = solid_members(4, 300_000, 9);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 3, 5] {
        let first = rar20::on_threads(1, || rar20::rar5_encode_solid(&borrowed, level, DICTIONARY));
        for threads in [2usize, 4, 8] {
            let again = rar20::on_threads(threads, || {
                rar20::rar5_encode_solid(&borrowed, level, DICTIONARY)
            });
            assert!(
                again == first,
                "level {level}: {threads} threads wrote a different solid set"
            );
        }
    }
}

#[test]
fn a_slid_history_writes_what_an_unslid_one_writes() {
    // The slide keeps the dictionary, which is everything a match may
    // still reach, and builds the index again over what it kept. So it
    // is a cost and never a choice: the bytes must not move. The shipped
    // slack is megabytes, so the test asks for a small one and pays for
    // several slides over a set a test can afford.
    let members = solid_members(8, 40_000, 63);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 2, 3, 4, 5] {
        let whole = rar20::rar5_encode_solid(&borrowed, level, DICTIONARY);
        let slid = rar20::rar5_encode_solid_slid(&borrowed, 50_000, level, DICTIONARY);
        assert!(slid == whole, "level {level}: a slide moved the bytes");
        let chain: Vec<(&[u8], u64)> = slid
            .iter()
            .zip(&members)
            .map(|(p, m)| (p.as_slice(), m.len() as u64))
            .collect();
        let out = rar5::decode_solid_chain(&chain, u64::from(DICTIONARY), 0, false)
            .expect("a slid solid chain decodes");
        assert!(
            out == members,
            "level {level}: the slid chain read back wrong"
        );
    }
}

#[test]
fn an_empty_chunk_inside_a_solid_set_is_a_member_of_no_bytes() {
    // `Engine::encode_chunk`'s empty arm, which emits the one last block
    // a member of no bytes still needs so its chain is walkable.
    //
    // It is NOT reachable from spec G's writer: `write/engine.rs` gates
    // the encoder on `size > 0`, so a member of no bytes in the middle
    // of a solid set is a STORED member, which is what spec G 3.9 names
    // in as many words, and the arm was
    // instrumented to confirm the writer never enters it. The
    // arm is reachable from this package's own entry, so it is tested
    // here, where it lives, rather than left to a writer test that
    // cannot drive it.
    let members = solid_members(3, 40_000, 88);
    let empty: Vec<u8> = Vec::new();
    let with_gap: Vec<&[u8]> = vec![&members[0], &empty, &members[1], &empty, &members[2]];
    for level in [1u8, 3, 5] {
        let packed = rar20::rar5_encode_solid(&with_gap, level, DICTIONARY);
        assert!(
            packed.iter().all(|member| !member.is_empty()),
            "level {level}: a member of no bytes still owes a last block"
        );
        let chain: Vec<(&[u8], u64)> = packed
            .iter()
            .zip(&with_gap)
            .map(|(p, m)| (p.as_slice(), m.len() as u64))
            .collect();
        let out = rar5::decode_solid_chain(&chain, u64::from(DICTIONARY), 0, false)
            .expect("a solid chain with empty members decodes");
        assert!(
            out.iter().map(Vec::as_slice).eq(with_gap.iter().copied()),
            "level {level}: an empty member broke the chain"
        );
    }
}
#[test]
fn a_batched_solid_set_is_byte_identical_to_one_member_at_a_time() {
    // Pipelining the parse across a solid set's member boundaries is a
    // WIDTH change and nothing else. The gap it closes
    // was measured: a 512 KiB solid member is two parse blocks and the
    // engine joined at every member, so the create legs' solid arm ran
    // 1.90x parallel where the same bytes in one member ran 10.63x, for
    // the same CPU to within 6%. Staging several members and parsing them
    // as one wave may not move a byte, and `drive.rs`'s `Segment` says
    // why it does not: each member is walked and parsed over a slice that
    // stops at its own end, so both finders answer what they answered
    // when it was the last thing in the buffer.
    //
    // Two shapes, because they exercise different halves of the cut: 30
    // members of one parse block each, so a wave holds many whole
    // members; and 9 members of two blocks each over a larger
    // dictionary, so a member's blocks are grouped and its LAST block is
    // a short one.
    for (count, each, dictionary) in [(30usize, 40_000usize, DICTIONARY), (9, 300_000, 1 << 20)] {
        let members = solid_members(count, each, 41);
        let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
        for level in [1u8, 2, 3, 4, 5] {
            let apiece = rar20::rar5_encode_solid(&borrowed, level, dictionary);
            let batched = rar20::rar5_encode_solid_batched(&borrowed, None, level, dictionary);
            assert!(
                batched == apiece,
                "level {level}, {count} members of {each}: a batch moved the bytes"
            );
        }
    }
}

#[test]
fn a_batched_solid_set_holds_at_every_thread_count_and_over_a_slide() {
    // Two things a batch must survive. The THREAD COUNT, because the
    // wave is wider now and a wider wave is more threads in flight at
    // once (API promise 6). And a SLIDE, which cuts a batch rather than
    // joining it: a slide drops bytes a staged parse has not read yet, so
    // it has to happen with nothing in flight, and `Engine::may_stage`
    // refuses to stage across one.
    let members = solid_members(24, 40_000, 7);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 3, 5] {
        let apiece =
            rar20::on_threads(1, || rar20::rar5_encode_solid(&borrowed, level, DICTIONARY));
        for threads in [1usize, 2, 4, 8] {
            let batched = rar20::on_threads(threads, || {
                rar20::rar5_encode_solid_batched(&borrowed, None, level, DICTIONARY)
            });
            assert!(
                batched == apiece,
                "level {level}: {threads} threads batched a different set"
            );
        }
        let slid = rar20::rar5_encode_solid_slid(&borrowed, 50_000, level, DICTIONARY);
        let slid_batched =
            rar20::rar5_encode_solid_batched(&borrowed, Some(50_000), level, DICTIONARY);
        assert!(
            slid_batched == slid,
            "level {level}: a batch that met a slide moved the bytes"
        );
    }
}

#[test]
fn a_batch_holding_a_member_of_no_bytes_still_owes_it_a_last_block() {
    // A member of no bytes asks nothing of a finder, so it is no block of
    // the wave; it still owes the one last block that makes its chain
    // walkable, and a batch has to emit it in its own place in the
    // order. Spec G's writer cannot reach this arm - it stores a member
    // of no bytes - but this package's own entry can, so it is tested
    // where it lives.
    let members = solid_members(6, 40_000, 15);
    let empty: Vec<u8> = Vec::new();
    let with_gap: Vec<&[u8]> = vec![
        &members[0],
        &empty,
        &members[1],
        &members[2],
        &empty,
        &members[3],
        &members[4],
        &members[5],
        &empty,
    ];
    for level in [1u8, 3, 5] {
        let apiece = rar20::rar5_encode_solid(&with_gap, level, DICTIONARY);
        let batched = rar20::rar5_encode_solid_batched(&with_gap, None, level, DICTIONARY);
        assert!(
            batched == apiece,
            "level {level}: a batch holding a member of no bytes moved the bytes"
        );
        assert!(
            batched.iter().all(|member| !member.is_empty()),
            "level {level}: a member of no bytes still owes a last block"
        );
        let chain: Vec<(&[u8], u64)> = batched
            .iter()
            .zip(&with_gap)
            .map(|(p, m)| (p.as_slice(), m.len() as u64))
            .collect();
        let out = rar5::decode_solid_chain(&chain, u64::from(DICTIONARY), 0, false)
            .expect("a batched solid chain decodes");
        let want: Vec<Vec<u8>> = with_gap.iter().map(|m| m.to_vec()).collect();
        assert!(
            out == want,
            "level {level}: the batched chain read back wrong"
        );
    }
}
