//! SPEC-H2 sections 3.7 and 6.3: match distances at the EDGE of the window.
//!
//! The other RAR 5 targets decode 256 KiB into a 1 MiB window, so the ring
//! never laps and the slot ahead of the write point holds a byte the
//! stream never produced. That is why none of them found the defect this
//! target exists for: a short match followed within a stride by a match
//! whose distance is within a stride of the DICTIONARY, on a ring that has
//! already lapped, read a byte the short match had scribbled and returned
//! wrong bytes with no error.
//!
//! So the input is BUILT to hold those pairs rather than hoped for: the
//! dictionary is the smallest RAR 5 declares, the member laps it twice,
//! and the fuzz bytes choose the lead lengths, the gaps and how far inside
//! the window's edge each distance lands. The encoder writes it, both
//! decoder arms read it, and the bytes must come back.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::{rar20, rar5};

/// 128 KiB, the smallest dictionary RAR 5 declares, so a member laps it
/// for a quarter of a megabyte rather than for tens.
const WINDOW: u64 = 128 * 1024;


/// Append `length` bytes from `distance` back, the byte at a time way, so
/// the input holds a repeat the encoder can only express at that distance.
fn repeat(out: &mut Vec<u8>, distance: usize, length: usize) {
    for _ in 0..length {
        let byte = out[out.len() - distance];
        out.push(byte);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    // Levels 4 and 5 run the optimal parse over the carried tree, which is
    // far too slow to fuzz a quarter megabyte member with; the distances
    // this target is about are the finder's, and levels 0 to 3 reach them.
    let level = data[0] % 4;
    let window = WINDOW as usize;
    let mut noise = rarkit_testdata::Seeded::new(u64::from(u32::from_le_bytes([
        data[1], data[2], data[3], data[4],
    ])));

    // A base that laps the dictionary, so every slot ahead of the write
    // point holds a live byte.
    let mut input: Vec<u8> = (0..window + 4096).map(|_| noise.next_byte()).collect();

    // Then the pairs the target is for, one per three fuzz bytes: a short
    // LEAD match, a gap of literals, and a match at the window's edge.
    for step in data[5..].chunks(3) {
        if step.len() < 3 || input.len() > 3 * window {
            break;
        }
        let lead = usize::from(step[0] % 64) + 1;
        let gap = usize::from(step[1] % 24);
        // Zero puts the distance at exactly the dictionary, which section
        // 3.7 says is legal and which the ring serves from the slot the
        // write point is about to overwrite.
        let edge = usize::from(step[2] % 65);
        repeat(&mut input, 1024, lead);
        for _ in 0..gap {
            input.push(noise.next_byte());
        }
        repeat(&mut input, window - edge, 70);
    }

    let packed = rar20::rar5_encode(&input, level, window as u32);
    for parallel in [false, true] {
        let back = rar5::decode_member(&packed, input.len() as u64, WINDOW, 0, parallel)
            .expect("spec H2's decoder reads what this encoder wrote");
        assert!(
            back == input,
            "level {level} parallel {parallel}: the round trip changed the bytes at {:?}",
            back.iter().zip(&input).position(|(a, b)| a != b)
        );
    }
    // The window edge under the OVERLAP, with a wave of one block so the
    // chain crosses a wave boundary at every block: the ring's write
    // invariant is the apply stage's and the apply stage is serial, so a
    // decode running beside it must leave these distances where they were.
    // The debug build's `assert_no_reachable_spill` is what watches that,
    // on every copy, and it is why this target runs in a debug build.
    for (workers, wave, overlap) in [(2, Some(1), true), (8, Some(1), true), (2, Some(1), false)] {
        let back = rar5::decode_member_scheduled(
            &packed,
            input.len() as u64,
            WINDOW,
            0,
            workers,
            wave,
            overlap,
        )
        .expect("spec H2's decoder reads what this encoder wrote");
        assert!(
            back == input,
            "level {level}, {workers} workers, wave {wave:?}, overlap {overlap}: \
             the round trip changed the bytes at {:?}",
            back.iter().zip(&input).position(|(a, b)| a != b)
        );
    }
});
