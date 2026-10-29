//! SPEC-H2 section 5: the archives, each against the check table.

use super::*;

/// Section 5.2: every archive is a test - extract every member and compare
/// to the recorded SHA-256. The table is section 5.1's confirmation run.
#[cfg(feature = "repo-tests")]
#[test]
fn every_archive_reproduces_the_check_table() {
    let expected = check_table();
    let mut checked = 0;
    for stem in ARCHIVES {
        let data = archive(stem);
        let got = decode_archive(&data, false);
        let want: Vec<_> = expected.iter().filter(|row| row.0 == stem).collect();
        assert_eq!(got.len(), want.len(), "{stem}: member count");
        for ((name, bytes), row) in got.iter().zip(&want) {
            assert_eq!(name, &row.1, "{stem}: member order");
            assert_eq!(bytes.len() as u64, row.2, "{stem}/{name}: size");
            assert_eq!(hex(bytes), row.3, "{stem}/{name}: sha256");
            checked += 1;
        }
    }
    assert_eq!(checked, 18, "18 members in 16 archives (section 5.1)");
}

/// Section 4.2 and SPEC-API 8.1 as amended on 26 Sep 2026: the
/// window is the only data dependent allocation, and it is what the stream
/// can REACH, `min(declared dictionary, unpacked size)`. A stream whose
/// reach is its dictionary allocates exactly what the declared rule did.
#[test]
fn the_window_is_the_members_reach_and_is_allocated_once() {
    // The declared size, the fixed spill margin of `output.rs` which keeps
    // a stride copy off the window's oldest bytes, and the constant ring
    // FLOOR below which no ring is allocated; nothing that scales with the
    // archive beyond the dictionary itself. Both constants are of the kind
    // section 4.2's erratum describes, "a constant the implementation adds
    // on top", and neither is charged to `MemoryPolicy::max_window`.
    let lz = Rar5Lz::new(1 << 20, &policy()).unwrap();
    assert_eq!(lz.window_bytes(), (1 << 20) + SPILL);
    // A dictionary ABOVE the floor allocates exactly the declared size and
    // the margin, which is what says the floor costs the large windows
    // nothing at all.
    let lz = Rar5Lz::new(1 << 24, &policy()).unwrap();
    assert_eq!(lz.window_bytes(), (1 << 24) + SPILL);
    // A dictionary BELOW it gets the floor, and the floor is a CONSTANT:
    // the smallest dictionary RAR 5 can declare and the largest one under
    // the floor allocate the same ring, so nothing here scales with the
    // archive.
    // The floor counts the spill (27 Sep 2026): the ring is exactly it.
    let lz = Rar5Lz::new(128 << 10, &policy()).unwrap();
    assert_eq!(lz.window_bytes(), RING_FLOOR);
    let lz = Rar5Lz::new(512 << 10, &policy()).unwrap();
    assert_eq!(lz.window_bytes(), RING_FLOOR);
    let Err(err) = Rar5Lz::new(1 << 34, &policy()) else {
        panic!("a window past the policy must be refused");
    };
    assert!(matches!(
        err.kind(),
        ErrorKind::LimitExceeded {
            resource: crate::Resource::Window,
            ..
        }
    ));
    // The 26 Sep 2026 amendment: a dictionary ABOVE the ceiling with a small reach is
    // built, and its ring is the reach (here under the floor, so the floor,
    // which the ceiling caps). The floor counts the spill, as above.
    let tight = MemoryPolicy {
        max_window: 1 << 20,
        ..policy()
    };
    let lz = Rar5Lz::with_reach(1 << 30, 64 << 10, &tight).unwrap();
    assert_eq!(lz.window_bytes(), RING_FLOOR);
    let lz = Rar5Lz::with_reach(1 << 24, 3 << 20, &policy()).unwrap();
    assert_eq!(lz.window_bytes(), (3 << 20) + SPILL);
    // A reach above the ceiling is refused before any allocation, naming
    // Window, the REACH as needed and the policy's figure as limit.
    let Err(err) = Rar5Lz::with_reach(1 << 30, (1 << 20) + 1, &tight) else {
        panic!("a reach past the policy must be refused");
    };
    assert!(matches!(
        err.kind(),
        ErrorKind::LimitExceeded {
            resource: crate::Resource::Window,
            needed,
            limit,
        } if *needed == (1 << 20) + 1 && *limit == 1 << 20
    ));
}

/// The same amendment, end to end: a member declared with a dictionary far above the
/// policy's ceiling decodes to the same bytes when its reach fits.
#[cfg(feature = "repo-tests")]
#[test]
fn a_member_declaring_past_the_ceiling_decodes_within_its_reach() {
    let data = archive(ARCHIVES[0]);
    let mut checked = 0;
    for member in members(&data) {
        if member.directory || member.method == 0 || member.solid {
            continue;
        }
        let tight = MemoryPolicy {
            max_window: member.unpacked.max(1 << 20),
            ..policy()
        };
        let mut lz = Rar5Lz::with_reach(1 << 32, member.unpacked, &tight).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(&member.packed);
        lz.member(&mut source, member.unpacked, member.algorithm, &mut sink)
            .unwrap_or_else(|e| panic!("{}: {e}", member.name));
        let mut want: Vec<u8> = Vec::new();
        let mut full = Rar5Lz::new(member.window, &policy()).unwrap();
        full.member(
            &mut SliceSource::new(&member.packed),
            member.unpacked,
            member.algorithm,
            &mut want,
        )
        .unwrap();
        assert_eq!(sink, want, "{}", member.name);
        checked += 1;
    }
    assert!(checked > 0);
}

/// Section 4.2: four tables per set, each a 512 entry primary lookup.
#[test]
fn a_table_sets_lookup_size_is_a_constant() {
    use super::tables::LUT_ENTRIES;
    assert_eq!(LUT_ENTRIES, 512);
    assert_eq!(std::mem::size_of::<[u32; LUT_ENTRIES]>(), 2048);
}

/// Section 5.2's second half: a member's own bytes are what the archive
/// says, and a null sink sees the same count.
#[cfg(feature = "repo-tests")]
#[test]
fn a_null_sink_counts_what_a_buffer_collects() {
    for stem in ["h5_text_m3", "h5_solid", "h5_empty"] {
        let data = archive(stem);
        let collected: u64 = decode_archive(&data, false)
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum();
        let mut counted = 0u64;
        let mut decoder: Option<Rar5Lz> = None;
        for member in members(&data) {
            if member.directory || member.method == 0 {
                continue;
            }
            if !member.solid || decoder.is_none() {
                decoder = Some(Rar5Lz::new(member.window, &policy()).unwrap());
            }
            let mut sink = NullSink { bytes: 0 };
            let mut source = SliceSource::new(&member.packed);
            decoder
                .as_mut()
                .unwrap()
                .member(&mut source, member.unpacked, member.algorithm, &mut sink)
                .unwrap();
            counted += sink.bytes;
        }
        assert_eq!(counted, collected, "{stem}");
    }
}

/// Section 6.2: every single bit flip in the first 4 KiB of one member's
/// packed data either decodes or fails cleanly. Never a panic, never a hang,
/// never an allocation above the window.
#[cfg(feature = "repo-tests")]
#[test]
fn a_bit_flip_in_packed_data_never_panics() {
    let data = archive("h5_x86_m5");
    let member: Member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    let limit = member.packed.len().min(4096);
    for byte in 0..limit {
        for bit in 0..8 {
            let mut packed = member.packed.clone();
            packed[byte] ^= 1 << bit;
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            let _ = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
            assert!(sink.len() as u64 <= member.unpacked);
        }
    }
}

/// Section 6.2: a truncation at every 64th byte fails and never panics.
#[cfg(feature = "repo-tests")]
#[test]
fn a_truncation_never_panics() {
    let data = archive("h5_runs_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for cut in (0..member.packed.len()).step_by(64) {
        let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(&member.packed[..cut]);
        let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
        assert!(outcome.is_err(), "cut at {cut} should not complete");
    }
}

/// Section 6.2: a declared unpacked size multiplied by 16 runs out of
/// blocks and says so, rather than looping or growing.
#[cfg(feature = "repo-tests")]
#[test]
fn an_inflated_declared_size_ends_the_member() {
    let data = archive("h5_runs_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(&member.packed);
    let err = lz
        .member(
            &mut source,
            member.unpacked * 16,
            member.algorithm,
            &mut sink,
        )
        .unwrap_err();
    assert!(matches!(
        err.kind(),
        ErrorKind::Truncated | ErrorKind::Corrupt(Corruption::Rar5(Rar5Fault::IncompleteMember))
    ));
}

/// Section 3.6: the filtered and unfiltered pair of one input
/// reproduce the same bytes, which is what isolates spec C's transforms
/// from this package.
#[cfg(feature = "repo-tests")]
#[test]
fn the_filtered_and_unfiltered_pairs_agree() {
    for (with, without) in [
        ("h5_x86_m5", "h5_x86_nofilter"),
        ("h5_delta_m5", "h5_delta_off"),
    ] {
        let a = decode_archive(&archive(with), false);
        let b = decode_archive(&archive(without), false);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].1, b[0].1, "{with} against {without}");
    }
}

/// V5-SOLIDFILT: the filter base is MEMBER relative. The solid
/// archive puts a filtered member after an unfiltered one, and a stream
/// relative base would corrupt it.
#[cfg(feature = "repo-tests")]
#[test]
fn v5_solidfilt_a_filter_after_a_solid_member_is_member_relative() {
    let solid = decode_archive(&archive("h5_solid_mixed"), false);
    let alone = decode_archive(&archive("h5_x86_m5"), false);
    let x86 = solid
        .iter()
        .find(|(name, _)| name == "X86.BIN")
        .expect("X86.BIN in the solid chain");
    assert_eq!(x86.1, alone[0].1);
}
