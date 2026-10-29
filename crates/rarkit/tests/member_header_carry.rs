//! A member's header is copied once per extra FRAGMENT, never once per
//! member (spec F 3.5.4, 3.5.6).
//!
//! The walking thread used to copy one member's header three times on the
//! way through: out of the block, into the packed stream, and into the
//! landing. For an archive of many small members that is three copies of a
//! few hundred bytes for a member of about 160, and it cost a measured 6.1
//! nanoseconds a copy of a 330 nanosecond member on an M3 Mac
//! (the 20,000 stored member TEST legs). The
//! header the close needs is the LAST fragment's, which for a member with
//! one fragment is the first one, and that one the caller already holds.
//!
//! These tests pin both halves of that, in both directions:
//!
//! * a member with one fragment costs NO header copy, and
//! * a member that CONTINUES across volumes still reports the LAST
//!   fragment's name and verdict, which is what the copy is for.
//!
//! The non-vacuity assertions matter as much as the counts: a test that
//! reads zero copies because nothing extracted at all would pass without
//! them.

#![cfg(feature = "test-support")]

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

/// What `close` was told about each member, which is where a header that
/// went missing would show.
#[derive(Default)]
struct Seen {
    names: Vec<Vec<u8>>,
    verdicts: Vec<Option<bool>>,
    bytes: Vec<u64>,
}

impl Sink for Seen {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Verify)
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if member.is_directory {
            return Ok(());
        }
        self.names.push(member.name.to_vec());
        self.verdicts.push(outcome.checksum_ok);
        self.bytes.push(outcome.bytes);
        Ok(())
    }
}

fn fixture(name: &str) -> Arc<dyn RangeSource> {
    let path = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/archives"
    ))
    .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("vector {name}: {e}"));
    Arc::new(bytes) as Arc<dyn RangeSource>
}

fn run(names: &[&str]) -> (Seen, u64) {
    let volumes: Vec<Arc<dyn RangeSource>> = names.iter().map(|n| fixture(n)).collect();
    let mut sink = Seen::default();
    rarkit::probe::reset_header_clones();
    extract(volumes, &ReadOptions::default(), &mut sink, &mut ()).expect("the fixture extracts");
    (sink, rarkit::probe::header_clones())
}

#[test]
fn a_member_with_one_fragment_costs_no_header_copy() {
    let (seen, clones) = run(&["f01_stored.rar"]);
    assert!(
        !seen.names.is_empty(),
        "non-vacuity: the fixture must deliver at least one member, or a \
         count of zero copies means nothing"
    );
    assert!(
        seen.verdicts.iter().all(|v| *v == Some(true)),
        "every member verifies, so the header the verdict was read from was \
         the right one: {:?}",
        seen.verdicts
    );
    assert_eq!(
        clones, 0,
        "a member that is not split has its header BORROWED from the block \
         the walk already holds; {clones} copies says the per-member copy is \
         back"
    );
}

#[test]
fn a_member_split_over_four_volumes_copies_once_per_later_fragment() {
    let (seen, clones) = run(&[
        "f11_svol.part1.rar",
        "f11_svol.part2.rar",
        "f11_svol.part3.rar",
        "f11_svol.part4.rar",
    ]);
    // The member's name and verdict come from the LAST fragment's header,
    // which is the whole reason a later fragment is copied at all. Reading
    // the FIRST fragment's header here instead fails this assertion, and
    // fails `containers::a_stored_member_split_over_four_volumes_joins`
    // with it.
    assert_eq!(seen.names, vec![b"rand.bin".to_vec()]);
    assert_eq!(seen.verdicts, vec![Some(true)]);
    assert_eq!(seen.bytes, vec![12_000]);
    assert!(
        clones >= 3,
        "four volumes means three continuation headers, each copied once \
         because the walk has moved past the block that held the first; \
         read {clones}"
    );
}

/// **The many-small path's BYTE IDENTITY, and a corruption shown to
/// fail**, added 22 Sep 2026 with the lever that boxed the landing's
/// `Option<FileHdr>`.
///
/// That lever made the LAST fragment's header a pointer rather than a
/// whole 296 byte header carried by value in a slot that is `None` for
/// every member with one fragment, which took `Landed` from 424 bytes to
/// 136. The header is what `close` reads its checksum from (spec F
/// 3.5.6), so a dereference that went to the wrong place would be
/// invisible in a wall figure and visible only here.
///
/// Reference parity is NOT re-proved here and is not this file's to
/// prove: `tests/corpus_differential.rs` holds rarkit's output against
/// the reference tool's over the whole corpus and runs in `make ci`.
/// What these two pin is the shape those tests do not have many of - a
/// few hundred small members in one archive - and the negative that no
/// passing extraction can show on its own.
mod many_small {
    use std::sync::Arc;

    use rarkit::{
        extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource,
        ReadOptions, Result, Sink, WriteOptions, Writer,
    };

    const MEMBERS: usize = 400;

    /// A distinct body per member, so a member served another member's
    /// bytes fails the comparison rather than matching by accident.
    fn body(i: usize) -> Vec<u8> {
        format!("member {i} of {MEMBERS}\n").repeat(8).into_bytes()
    }

    fn many() -> Vec<u8> {
        let mut writer = Writer::new(WriteOptions::default()).expect("options");
        // Names and bodies outlive the writer: `MemberSpec` borrows both,
        // and the writer holds those borrows until `finish_into`.
        let names: Vec<Vec<u8>> = (0..MEMBERS)
            .map(|i| format!("m{i:05}.txt").into_bytes())
            .collect();
        let bodies: Vec<Vec<u8>> = (0..MEMBERS).map(body).collect();
        for i in 0..MEMBERS {
            let name = &names[i];
            let payload = &bodies[i];
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(payload),
                    mtime: None,
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish");
        out
    }

    /// Every member's bytes and verdict, as `close` reported them.
    #[derive(Default)]
    struct Kept {
        names: Vec<Vec<u8>>,
        bytes: Vec<Vec<u8>>,
        verdicts: Vec<Option<bool>>,
    }

    impl Sink for Kept {
        type Out = Vec<u8>;

        fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
            if member.is_directory {
                return Ok(Disposition::Skip);
            }
            Ok(Disposition::Write(Vec::new()))
        }

        fn close(
            &mut self,
            member: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> Result<()> {
            self.names.push(member.name.to_vec());
            self.bytes.push(out.unwrap_or_default());
            self.verdicts.push(outcome.checksum_ok);
            Ok(())
        }
    }

    fn read(archive: Vec<u8>) -> Kept {
        let volumes: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
        let mut sink = Kept::default();
        let _ = extract(volumes, &ReadOptions::default(), &mut sink, &mut ());
        sink
    }

    #[test]
    fn four_hundred_small_members_come_back_byte_for_byte() {
        let kept = read(many());
        assert_eq!(
            kept.names.len(),
            MEMBERS,
            "non-vacuity: every member must be reported, or the comparison \
             below is over nothing"
        );
        for i in 0..MEMBERS {
            assert_eq!(
                kept.names[i],
                format!("m{i:05}.txt").into_bytes(),
                "member {i} reported the wrong name, which is the header the \
                 close read"
            );
            assert_eq!(
                kept.bytes[i],
                body(i),
                "member {i} did not come back byte for byte"
            );
            assert_eq!(
                kept.verdicts[i],
                Some(true),
                "member {i} failed its checksum on an archive that is not damaged"
            );
        }
    }

    /// **The sink sees ONE `MemberInfo` a member, not two.**
    ///
    /// `info_of` builds 168 bytes of seventeen fields read out of the
    /// header, and it ran once for `open` and again for `close`
    /// although for a member with one fragment the two are field for
    /// field the same: same header, same data range, same name. The
    /// one-fragment path now hands the open's value back.
    ///
    /// A test cannot see which value it was given, so it checks the
    /// thing that would break if the wrong one were handed back: every
    /// field the close reports must equal what `open` was told. Making
    /// the one-fragment path fire for a SPLIT member fails the split
    /// tests in this file and in `containers`, which is the other half
    /// of the same invariant.
    #[test]
    fn open_and_close_agree_field_for_field_on_every_member() {
        /// The fields of a `MemberInfo` that a wrong close would get
        /// wrong: the name, the two sizes, the data range and the
        /// directory bit.
        type Snap = (Vec<u8>, u64, Option<u64>, std::ops::Range<u64>, bool);

        #[derive(Default)]
        struct Both {
            opened: Vec<Snap>,
            closed: Vec<Snap>,
        }

        fn snapshot(m: &MemberInfo<'_>) -> Snap {
            (
                m.name.to_vec(),
                m.packed_size,
                m.unpacked_size,
                m.data.clone(),
                m.is_directory,
            )
        }

        impl Sink for Both {
            type Out = std::io::Sink;

            fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>> {
                self.opened.push(snapshot(member));
                Ok(Disposition::Verify)
            }

            fn close(
                &mut self,
                member: &MemberInfo<'_>,
                _out: Option<Self::Out>,
                _outcome: &MemberOutcome,
            ) -> Result<()> {
                self.closed.push(snapshot(member));
                Ok(())
            }
        }

        let volumes: Vec<Arc<dyn RangeSource>> = vec![Arc::new(many())];
        let mut sink = Both::default();
        extract(volumes, &ReadOptions::default(), &mut sink, &mut ()).expect("extracts");
        assert_eq!(
            sink.opened.len(),
            MEMBERS,
            "non-vacuity: every member must be opened, or the comparison is over nothing"
        );
        assert_eq!(
            sink.closed.len(),
            MEMBERS,
            "every member that opened must close"
        );
        assert_eq!(
            sink.opened, sink.closed,
            "the close must describe the same member the open did, field for field"
        );
    }

    /// The NEGATIVE the test above cannot show: that the checksum is
    /// read from a header at all. A member whose stored bytes are
    /// changed by one bit must come back FAILED and must not take its
    /// neighbours with it.
    #[test]
    fn one_flipped_bit_fails_that_member_and_no_other() {
        let clean = many();
        // The members are STORED, so a member's body appears in the
        // archive verbatim. Finding it by content rather than by a
        // computed offset keeps this test honest if the writer's
        // layout ever moves.
        let victim = MEMBERS / 2;
        let needle = body(victim);
        let at = clean
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .expect("a stored member's bytes are in the archive verbatim");

        let mut damaged = clean.clone();
        damaged[at + 3] ^= 0x01;
        assert_ne!(clean, damaged, "the corruption must change a byte");

        let kept = read(damaged);
        assert_eq!(
            kept.verdicts.len(),
            MEMBERS,
            "non-vacuity: a damaged member must not stop the walk; spec F \
             section 8 reports it and moves on"
        );
        assert_eq!(
            kept.verdicts[victim],
            Some(false),
            "member {victim} was damaged and must FAIL its checksum"
        );
        for (i, verdict) in kept.verdicts.iter().enumerate() {
            if i != victim {
                assert_eq!(
                    *verdict,
                    Some(true),
                    "member {i} was not damaged and must still pass"
                );
            }
        }
    }
}
