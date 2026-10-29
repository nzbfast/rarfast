//! SPEC-H2 section 3.7: a member whose match distances reach the LAST
//! bytes of its dictionary, end to end.
//!
//! The in-crate screen for this is `v5_edge_a_distance_at_the_window_reads_
//! the_oldest_byte_not_a_scribble`, which drives the window itself. This
//! one is the same property one level up, and it is the level the defect
//! was found at: rarkit's own RAR 5 encoder writes the member, both
//! decoder arms read it, `rarkit-oracle` reads it, and reference `unrar`
//! extracts it.
//!
//! The defect it guards: on a ring that has lapped,
//! a match whose distance came within a stride of the DICTIONARY read a
//! byte that the short match in front of it had scribbled, and the decode
//! returned wrong bytes with no error. Spec H3's encoder held its own
//! reach 64 bytes short of the dictionary until it was fixed, which is why
//! no archive this project wrote could reach it either.

mod support {
    pub mod rar5build;
}

use rarkit::internals::{rar20, rar5};
use std::io::Write;
use std::process::Command;
use support::rar5build::{archive, Member};

/// The smallest dictionary RAR 5 declares, exponent zero: a member laps it
/// in a quarter of a megabyte instead of in tens.
const WINDOW: usize = 128 * 1024;

/// A cheap deterministic stream, so the base the repeats sit in holds no
/// match of its own for the parse to prefer over them.
fn noise(state: &mut u32) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    (*state >> 19) as u8
}

/// Append `length` bytes from `distance` back, the byte at a time way.
fn repeat(out: &mut Vec<u8>, distance: usize, length: usize) {
    for _ in 0..length {
        let byte = out[out.len() - distance];
        out.push(byte);
    }
}

/// An input that laps the dictionary and then crosses, for every `k` from
/// zero to 64, a short LEAD match followed within a stride by a match at
/// distance `dictionary - k`.
///
/// The lead is what matters and what no vector had: it is the operation
/// whose length a stride ladder can round up, and what it writes past its
/// own end is the window's oldest live byte. The gap walks the edge
/// distance out from under the lead one byte at a time.
fn edge_input() -> Vec<u8> {
    edge_input_at(WINDOW)
}

/// [`edge_input`] for a dictionary of `dictionary` bytes.
fn edge_input_at(dictionary: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9u32;
    let mut input: Vec<u8> = (0..dictionary + 4096).map(|_| noise(&mut state)).collect();
    for lead in [1usize, 2, 3, 5, 8, 15, 16, 17, 31, 33, 47, 49, 63, 64] {
        for gap in [0usize, 1, 3, 7, 14] {
            for k in 0..=64usize {
                repeat(&mut input, 1024, lead);
                for _ in 0..gap {
                    input.push(noise(&mut state));
                }
                repeat(&mut input, dictionary - k, 70);
            }
        }
    }
    input
}

/// Whether reference `unrar` is on PATH.
fn unrar() -> Option<String> {
    let found = Command::new("unrar").arg("-iver").output().ok()?;
    found
        .status
        .success()
        .then(|| String::from_utf8_lossy(&found.stdout).trim().to_string())
}

/// Every level, both decoder arms: what the encoder wrote comes back.
#[test]
fn the_window_edge_round_trips_through_both_arms_at_every_level() {
    let input = edge_input();
    for level in 0..=5u8 {
        let packed = rar20::rar5_encode(&input, level, WINDOW as u32);
        for parallel in [false, true] {
            let back = rar5::decode_member(&packed, input.len() as u64, WINDOW as u64, 0, parallel)
                .unwrap_or_else(|e| panic!("level {level} parallel {parallel}: {e}"));
            assert!(
                back == input,
                "level {level} parallel {parallel}: first difference at {:?} of {} bytes",
                back.iter().zip(&input).position(|(a, b)| a != b),
                input.len()
            );
        }
    }
}

/// A dictionary above the least a window reaches back whatever the header
/// declares (256 KiB, SPEC-H2 3.7): the coverage assertion's, where a
/// window one byte short of the dictionary is a window that is short.
const FAR_WINDOW: usize = 512 * 1024;

/// The coverage assertion, so this file cannot go quiet if the encoder's
/// parse changes: read through a window ONE BYTE short of the dictionary,
/// the same kind of member must come out with other bytes, which is only
/// true if the stream really does carry a distance of exactly the
/// dictionary. Such a match is no fault (SPEC-H2 3.7 as amended on 11 Oct 2026): it
/// gives a zero for each of its bytes, so the member decodes whole and
/// WRONG, where until then it was refused as `DistanceOutOfRange`.
///
/// It is made at 512 KiB and not at this file's 128 KiB because a window
/// reaches back 256 KiB whatever is declared: at 128 KiB a declared size
/// one byte short moves nothing.
#[test]
fn the_member_really_does_carry_a_distance_of_exactly_the_dictionary() {
    let input = edge_input_at(FAR_WINDOW);
    for level in 0..=5u8 {
        let packed = rar20::rar5_encode(&input, level, FAR_WINDOW as u32);
        let whole = rar5::decode_member(&packed, input.len() as u64, FAR_WINDOW as u64, 0, false)
            .unwrap_or_else(|e| panic!("level {level}: {e}"));
        assert!(whole == input, "level {level}: the member itself");
        let short =
            rar5::decode_member(&packed, input.len() as u64, FAR_WINDOW as u64 - 1, 0, false)
                .unwrap_or_else(|e| panic!("level {level}: a short window is no fault, {e}"));
        assert_eq!(short.len(), input.len(), "level {level}");
        let first = short
            .iter()
            .zip(&input)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| panic!("level {level}: no distance reached the dictionary"));
        assert_eq!(
            short[first], 0,
            "level {level}: a zero where the match could not reach"
        );
    }
}

#[cfg(feature = "oracle-compare")]
/// Section 6.1: the same member through `rarkit-oracle`.
#[test]
fn the_window_edge_member_matches_the_oracle() {
    let input = edge_input();
    for level in [1u8, 3, 5] {
        let packed = rar20::rar5_encode(&input, level, WINDOW as u32);
        let bytes = archive(&[Member {
            name: "EDGE.BIN",
            unpacked: &input,
            packed: &packed,
            dictionary_exponent: 0,
            method: 3,
            solid: false,
        }]);
        let theirs = rarkit_oracle::extract(&[&bytes], None)
            .unwrap_or_else(|e| panic!("level {level}: oracle: {e}"));
        let theirs: Vec<_> = theirs.into_iter().filter(|m| !m.is_directory).collect();
        assert_eq!(theirs.len(), 1, "level {level}: member count");
        assert!(theirs[0].data == input, "level {level}: the oracle's bytes");
    }
}

/// Spec H3 section 9.2's assertion, for this member: reference `unrar`
/// admits it and extracts it byte for byte. This is the arm that is not
/// this project's own code at either end.
#[test]
fn reference_unrar_extracts_the_window_edge_member() {
    let Some(version) = unrar() else {
        eprintln!("reference unrar is not on PATH: the window edge member is not admitted");
        return;
    };
    let input = edge_input();
    for level in [1u8, 3, 5] {
        let packed = rar20::rar5_encode(&input, level, WINDOW as u32);
        let bytes = archive(&[Member {
            name: "EDGE.BIN",
            unpacked: &input,
            packed: &packed,
            dictionary_exponent: 0,
            method: 3,
            solid: false,
        }]);
        let dir =
            std::env::temp_dir().join(format!("rarkit-h2-edge-{level}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a work directory");
        let path = dir.join("edge.rar");
        std::fs::File::create(&path)
            .expect("the archive")
            .write_all(&bytes)
            .expect("written");
        let run = Command::new("unrar")
            .arg("x")
            .arg("-y")
            .arg("-idq")
            .arg(&path)
            .current_dir(&dir)
            .output()
            .expect("unrar runs");
        assert!(
            run.status.success(),
            "level {level}: {version} refused the archive: {}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let got = std::fs::read(dir.join("EDGE.BIN")).expect("what unrar extracted");
        assert!(
            got == input,
            "level {level}: {version} extracted different bytes, first difference at {:?}",
            got.iter().zip(&input).position(|(a, b)| a != b)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
