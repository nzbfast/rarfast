//! Spec H3 section 7.1: the RAR 2.9 encoder's output is extracted by
//! reference `unrar` 7.23, byte for byte.
//!
//! Section 8.4 records that there is no ratio to quote for this arm,
//! because `rar` 7.x refuses `-ma4`, so the one external check that
//! exists is exactly this one.

mod support {
    pub mod rar4build;
}

use rarkit::internals::rar20;
use std::io::Write;
use std::process::Command;
use support::rar4build::{archive, Member};

/// 1 MiB, which the header's flag bits name as `65,536 << 4`.
const DICTIONARY: u32 = 1 << 20;
const DICTIONARY_BITS: u8 = 4;

fn have_unrar() -> bool {
    Command::new("unrar")
        .arg("-iver")
        .output()
        .map(|found| found.status.success())
        .unwrap_or(false)
}

/// Encode `input`, wrap it, hand it to reference `unrar`, compare.
fn admitted(name: &str, input: &[u8], level: u8) {
    if !have_unrar() {
        eprintln!("reference unrar is not on PATH: {name} not admitted");
        return;
    }
    let packed = rar20::rar29_encode(input, level, DICTIONARY);
    let bytes = archive(&[Member {
        name: "MEMBER.BIN",
        unpacked: input,
        packed: &packed,
        version: 29,
        method: 0x35,
        dictionary_bits: DICTIONARY_BITS,
        solid: false,
    }]);

    let dir = std::env::temp_dir().join(format!(
        "rarkit-h3-rar4-{name}-{level}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::File::create(dir.join("test.rar"))
        .expect("the archive")
        .write_all(&bytes)
        .expect("written");

    let run = Command::new("unrar")
        .arg("x")
        .arg("-y")
        .arg("test.rar")
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    assert!(
        run.status.success(),
        "{name} level {level}: unrar refused the archive\n{}",
        String::from_utf8_lossy(&run.stdout)
    );
    let out = std::fs::read(dir.join("MEMBER.BIN")).expect("the extracted member");
    assert_eq!(out.len(), input.len(), "{name} level {level}: wrong length");
    assert_eq!(out, input, "{name} level {level}: wrong bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect()
}

fn proselike(len: usize) -> Vec<u8> {
    let phrases: [&[u8]; 6] = [
        b"a block header begins at a byte boundary, ",
        b"and the code lengths are additive. ",
        b"the keep bit carries the stored lengths into this read. ",
        b"symbol 256 is followed by a two field decision. ",
        b"a short distance match is exactly two bytes long. ",
        b"the low part goes through the low distance alphabet. ",
    ];
    let mut out = Vec::with_capacity(len + 64);
    let mut at = 0;
    while out.len() < len {
        out.extend_from_slice(phrases[at % phrases.len()]);
        at += 1 + (out.len() % 3);
    }
    out.truncate(len);
    out
}

#[test]
fn a_single_byte_is_admitted() {
    admitted("one", b"A", 3);
}

#[test]
fn one_repeated_byte_is_admitted() {
    admitted("runs", &vec![b'A'; 70_000], 3);
}

#[test]
fn text_is_admitted_at_every_level() {
    let input = proselike(400_000);
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
    let mut input = proselike(900_000);
    input.extend_from_slice(&noise(200_000, 11));
    admitted("multiblock", &input, 3);
}

#[test]
fn far_matches_across_the_bonus_bands_are_admitted() {
    // H1's TWO thresholds, at 0x2000 and 0x40000, rather than H2's three.
    let mut input = Vec::new();
    let seed = proselike(600);
    input.extend_from_slice(&seed);
    for gap in [0x80usize, 0x1000, 0x8000, 0x50000] {
        input.extend_from_slice(&noise(gap, gap as u32));
        input.extend_from_slice(&seed);
    }
    admitted("bonus", &input, 5);
}

#[test]
fn the_low_distance_alphabet_is_exercised() {
    // Every distance slot from 10 up sends its low four bits through the
    // low distance alphabet, which has no analogue in RAR 5.
    let mut input = Vec::new();
    let seed = proselike(200);
    for gap in [40usize, 60, 100, 200, 400, 900, 2000, 5000, 11000, 25000] {
        input.extend_from_slice(&seed);
        input.extend_from_slice(&noise(gap, gap as u32));
    }
    input.extend_from_slice(&seed);
    admitted("lowdist", &input, 5);
}

/// Encode with this package and decode with spec H1's, which is the round
/// trip section 9.2 asks for.
fn round_trips(name: &str, input: &[u8], level: u8) {
    use rarkit::internals::rar3_lz::{decode_stream, MemberIn};
    let packed = rar20::rar29_encode(input, level, DICTIONARY);
    let members = [MemberIn {
        packed: 0..packed.len(),
        unpacked: input.len() as u64,
    }];
    let (out, _) = decode_stream(&packed, &members, DICTIONARY, true)
        .unwrap_or_else(|e| panic!("{name} level {level}: {e}"));
    assert!(out[0].data == input, "{name} level {level}: wrong bytes");
}

#[test]
fn every_shape_round_trips_through_rarkits_own_decoder() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("one", b"A".to_vec()),
        ("runs", vec![b'A'; 70_000]),
        ("text", proselike(400_000)),
        ("soup", rarkit_testdata::chatter(9, 1_300_000)),
        ("noise", noise(300_000, 7)),
        ("ramp", (0..200_000).map(|i| (i % 251) as u8).collect()),
        ("multiblock", {
            let mut v = rarkit_testdata::chatter(2, 900_000);
            v.extend_from_slice(&noise(200_000, 11));
            v.extend_from_slice(&rarkit_testdata::chatter(3, 1_200_000));
            v
        }),
        ("aligned", {
            // Sixteen byte records that recur far back, so far matches
            // share their low distance bits and the run form is written.
            let record = noise(1 << 12, 5);
            let mut v = Vec::new();
            for round in 0..200u32 {
                v.extend_from_slice(&record[..(1 << 12) - 16 * (round as usize % 7)]);
                v.extend_from_slice(&round.to_le_bytes());
                v.extend_from_slice(&[0u8; 12]);
            }
            v
        }),
    ];
    for (name, input) in cases {
        for level in [1u8, 3, 5] {
            round_trips(name, &input, level);
            if name == "aligned" || name == "soup" {
                admitted(name, &input, level);
            }
        }
    }
}

#[test]
fn the_same_input_and_options_give_byte_identical_output() {
    // API promise 6 at 1, 2, 4 and 8 threads (section 9.2), over an input
    // of several parse blocks.
    let mut input = rarkit_testdata::chatter(4, 2_500_000);
    input.extend_from_slice(&noise(300_000, 3));
    input.extend_from_slice(&rarkit_testdata::chatter(6, 1_500_000));
    for level in [1u8, 3, 5] {
        let first = rar20::on_threads(1, || rar20::rar29_encode(&input, level, DICTIONARY));
        for threads in [2usize, 4, 8] {
            let again =
                rar20::on_threads(threads, || rar20::rar29_encode(&input, level, DICTIONARY));
            assert!(
                again == first,
                "level {level}: {threads} threads wrote different bytes from one"
            );
        }
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
        let each = rar20::rar29_encode_each(&[&first, &second, &third, &second], level, DICTIONARY);
        for (got, input) in each.iter().zip([&first, &second, &third, &second]) {
            assert!(
                *got == rar20::rar29_encode(input, level, DICTIONARY),
                "level {level}: a reused encoder wrote different bytes"
            );
        }
    }
}

#[test]
fn the_archive_size_for_a_fixed_corpus_is_recorded() {
    // Section 9.2 and 8.4: the size goes in a test as a NUMBER, so a
    // change that trades ratio for wall shows up in the diff. Raise or
    // lower these deliberately.
    let input = rarkit_testdata::chatter(5, 1 << 20);
    let sizes: Vec<usize> = [1u8, 2, 3, 4, 5]
        .iter()
        .map(|&level| rar20::rar29_encode(&input, level, DICTIONARY).len())
        .collect();
    assert_eq!(sizes, RECORDED_SIZES, "the recorded archive sizes moved");
    // What levels 4 and 5 wrote before the lazy tree parse, and their options
    // still write: the optimal parse over the tree.
    for (plan, size) in [("optimal:tree:8:0", 163025), ("optimal:tree:32:0", 143668)] {
        let old = rar20::rar29_encode_spelled(&input, plan, DICTIONARY).expect("a plan");
        assert_eq!(old.len(), size, "{plan}");
    }
}

/// What the megabyte of shared test text, `chatter(5, 1 << 20)`, packs to at levels 1 to 5 with a 1 MiB
/// dictionary.
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
/// +6.9% at level 2, +8.1% at level 3 and +10.9% at level 4, with levels 1
/// and 5 unmoved.
///
/// **Moved 30 Sep 2026** (level 3 is the lazy parse 64
/// chain links deep, `Plan::for_level`): level 3 writes 241,471 to 227,914
/// bytes (-5.61 percent), the other levels unmoved. On this corpus, word
/// shuffled text whose repeats sit far apart, the deeper chain walk finds
/// matches the optimal parse's 8 links did not reach. That change was
/// CONDITIONAL on its timed runs; `WriteOptions::level3_optimal` writes
/// the old figure.
///
/// **Moved 30 Sep 2026 by the BACKWARD EXTENSION** (`lz::BACK_LIMIT`) and
/// level 3's lazy parse at `drive::LEVEL3_LINKS` (32) links instead of 64,
/// the shipped default: level 3 writes
/// 227,914 to 234,369 (+2.83 percent), still above level 4; the other
/// levels are unmoved (levels 1 and 2 keep the extension off by default).
/// `WriteOptions::level3_deep` writes 223,267, and
/// `WriteOptions::low_levels_extend` 261,221 and 249,299 at levels 1 and 2.
///
/// **Moved 1 Oct 2026**: levels 4 and 5 take the lazy parse
/// over the tree (cut 12 and 16, one hint slot, the full reach) in place
/// of the optimal parse, for 1.1x to 2.3x less create wall: level 4 writes
/// 216,999 to 218,474 and level 5 190,745 to 208,014 here, both still under level 3. The old
/// figures are what `WriteOptions::level4_optimal` / `level5_optimal`
/// write (`optimal:tree:8:0` and `optimal:tree:32:0`), checked below.
///
/// **Moved 1 Oct 2026** (level 1 is the fast parse over
/// chains keyed on six bytes, `Plan::for_level`, which this method
/// shares): level 1 writes 269,956 to 258,104 bytes (-4.39 percent), still
/// above level 2; levels 2 to 5 are unmoved by it. `WriteOptions::level1_priced`
/// writes the old figure (`tests/level1_parse.rs`).
///
/// **Moved 1 Oct 2026 by the ladder's order** (SPEC-H3 8.1, "LEVEL 4 RUNS
/// THE CHAINS" and "Levels 4 and 5 take the BACKWARD EXTENSION", which
/// this method shares): level 4 is level 3's lazy parse over the chains
/// at 64 links with the backward extension, 218,474 to 223,267 here (word
/// shuffled text, where the chains give up bytes for their wall;
/// `WriteOptions::level4_tree` keeps the tree), and level 5's lazy tree
/// plan takes the extension, 208,014 to 206,181. Levels 1 to 3 are
/// unmoved, and the order holds.
///
/// **Moved 1 Oct 2026 by LEVEL 5 BY CLASS** (SPEC-H3 8.1, which this
/// method shares): this megabyte's head reads under the level's cut-off,
/// so level 5 writes it over the chains at 80 links, 206,181 to 220,150
/// (6.8 percent more, for the chains' wall; `WriteOptions::level5_tree`
/// keeps the tree). Levels 1 to 4 are unmoved, and the order holds: level
/// 5 is under level 4 by 1.4 percent.
///
/// **Taken again 11 Oct 2026, on new test text.** The megabyte is the
/// shared test data makers' now and every figure here was taken from
/// that day's build, whose engine had not moved; the history above is
/// of the figures the earlier text gave, the last of them five lines up.
const RECORDED_SIZES: [usize; 5] = [204_634, 193_771, 177_351, 169_821, 167_737];

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
            let carried: usize = rar20::rar29_encode_solid(&borrowed, level, DICTIONARY)
                .iter()
                .map(Vec::len)
                .sum();
            let rebuilt: usize = rar20::rar29_encode_solid_rebuilt(&borrowed, level, DICTIONARY)
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
fn a_solid_set_round_trips_through_rarkits_own_decoder() {
    use rarkit::internals::rar3_lz::{decode_stream, MemberIn};
    let members = solid_members(6, 60_000, 12);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 2, 3, 4, 5] {
        let packed = rar20::rar29_encode_solid(&borrowed, level, DICTIONARY);
        // Spec F concatenates a solid chain's packed spans, and H1's
        // driver reads them as one stream.
        let mut stream = Vec::new();
        let spans: Vec<MemberIn> = packed
            .iter()
            .zip(&members)
            .map(|(p, m)| {
                let at = stream.len();
                stream.extend_from_slice(p);
                MemberIn {
                    packed: at..stream.len(),
                    unpacked: m.len() as u64,
                }
            })
            .collect();
        let (out, _) = decode_stream(&stream, &spans, DICTIONARY, true)
            .unwrap_or_else(|e| panic!("level {level}: {e}"));
        for (n, member) in members.iter().enumerate() {
            assert!(
                out[n].data == *member,
                "level {level}: solid member {n} read back wrong"
            );
        }
    }
}

#[test]
fn a_solid_set_reaches_into_the_members_before_it() {
    let members = solid_members(6, 60_000, 77);
    let borrowed: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    for level in [1u8, 3, 5] {
        let solid: usize = rar20::rar29_encode_solid(&borrowed, level, DICTIONARY)
            .iter()
            .map(Vec::len)
            .sum();
        let apart: usize = rar20::rar29_encode_each(&borrowed, level, DICTIONARY)
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
fn a_solid_set_is_admitted_by_reference_unrar() {
    if !have_unrar() {
        eprintln!("reference unrar is not on PATH: the solid set is not admitted");
        return;
    }
    let names = ["A.BIN", "B.BIN", "C.BIN", "D.BIN"];
    let members = solid_members(4, 40_000, 5);
    let level = 3;
    let packed = rar20::rar29_encode_solid(
        &members.iter().map(|m| m.as_slice()).collect::<Vec<_>>(),
        level,
        DICTIONARY,
    );
    let built: Vec<Member> = members
        .iter()
        .zip(&packed)
        .enumerate()
        .map(|(n, (unpacked, packed))| Member {
            name: names[n],
            unpacked,
            packed,
            version: 29,
            method: 0x35,
            dictionary_bits: DICTIONARY_BITS,
            solid: n > 0,
        })
        .collect();
    let bytes = archive(&built);

    let dir = std::env::temp_dir().join(format!("rarkit-h3-rar4-solid-set-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::File::create(dir.join("test.rar"))
        .expect("the archive")
        .write_all(&bytes)
        .expect("written");
    let run = Command::new("unrar")
        .arg("x")
        .arg("-y")
        .arg("test.rar")
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    assert!(
        run.status.success(),
        "unrar refused the solid set\n{}",
        String::from_utf8_lossy(&run.stdout)
    );
    for (n, member) in members.iter().enumerate() {
        let got = std::fs::read(dir.join(names[n])).expect("unrar wrote the member");
        assert!(got == *member, "member {n} came out different");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_chunk_inside_a_solid_set_is_a_member_of_no_bytes() {
    // `rar5_encode.rs`'s twin says why this lives here and not in a
    // writer test: spec G's writer gates the encoder on `size > 0`, so
    // only this package's own entry reaches the empty arm.
    use rarkit::internals::rar3_lz::{decode_stream, MemberIn};
    let members = solid_members(3, 40_000, 88);
    let empty: Vec<u8> = Vec::new();
    let with_gap: Vec<&[u8]> = vec![&members[0], &empty, &members[1], &empty, &members[2]];
    for level in [1u8, 3, 5] {
        let packed = rar20::rar29_encode_solid(&with_gap, level, DICTIONARY);
        assert!(
            packed.iter().all(|member| !member.is_empty()),
            "level {level}: a member of no bytes still owes a last block"
        );
        let mut stream = Vec::new();
        let spans: Vec<MemberIn> = packed
            .iter()
            .zip(&with_gap)
            .map(|(p, m)| {
                let at = stream.len();
                stream.extend_from_slice(p);
                MemberIn {
                    packed: at..stream.len(),
                    unpacked: m.len() as u64,
                }
            })
            .collect();
        let (out, _) = decode_stream(&stream, &spans, DICTIONARY, true)
            .unwrap_or_else(|e| panic!("level {level}: {e}"));
        for (n, member) in with_gap.iter().enumerate() {
            assert!(
                out[n].data == **member,
                "level {level}: member {n} read back wrong past an empty one"
            );
        }
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
            let apiece = rar20::rar29_encode_solid(&borrowed, level, dictionary);
            let batched = rar20::rar29_encode_solid_batched(&borrowed, None, level, dictionary);
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
        let apiece = rar20::on_threads(1, || {
            rar20::rar29_encode_solid(&borrowed, level, DICTIONARY)
        });
        for threads in [1usize, 2, 4, 8] {
            let batched = rar20::on_threads(threads, || {
                rar20::rar29_encode_solid_batched(&borrowed, None, level, DICTIONARY)
            });
            assert!(
                batched == apiece,
                "level {level}: {threads} threads batched a different set"
            );
        }
        let slid = rar20::rar29_encode_solid_slid(&borrowed, 50_000, level, DICTIONARY);
        let slid_batched =
            rar20::rar29_encode_solid_batched(&borrowed, Some(50_000), level, DICTIONARY);
        assert!(
            slid_batched == slid,
            "level {level}: a batch that met a slide moved the bytes"
        );
    }
}
