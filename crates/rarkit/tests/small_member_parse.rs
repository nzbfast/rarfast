//! The small-member parse (SPEC-H3 8.1, SPEC-G 3.8.1) through the public
//! `Writer`: at levels 4 and 5 a non-solid member of at most one parse
//! block (262,144 bytes, on its declared size) takes the lone lazy parse
//! by default (`WriteOptions::small_member_lazy`, `true`
//! by default), and the option switched off gives it level 3's optimal
//! chain parse, the earlier default, instead.
//!
//! Which parse a member took is pinned at the encoder
//! (`encode::tests::levels_4_and_5_parse_a_lone_member_lazily_and_the_option_off_optimally`
//! and `a_lone_block_from_the_samples_floor_up_is_sampled_and_noise_takes_the_floor`:
//! byte-identity with the spelled plans on both sides of the bound, the
//! RAR 2.9 method included). What is pinned here is what reaches the
//! writer: the bound on both sides for byte-slice and reader payloads
//! alike, the option reaching exactly the members the specification says
//! and no other, solid sets and levels 1 to 3 untouched by it, and every
//! archive read back (the spec's acceptance tests 1 to 6; test 7, the
//! command line, is `rarkit-cli`'s).
use rarkit::{
    extract, Disposition, Entropy, MemberInfo, MemberSpec, Payload, RangeSource, ReadOptions,
    Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};
use std::sync::Arc;

const BOUND: usize = 262_144;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Bytes with nothing in them to find.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| (xorshift(&mut state) >> 24) as u8)
        .collect()
}

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Bytes,
    Reader,
}

/// One archive of `members`, at `level`, solid or not, with the option on
/// or off.
fn write(members: &[Vec<u8>], level: u8, solid: bool, lazy: bool, shape: Shape) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid,
        small_member_lazy: lazy,
        entropy: Entropy::Seeded([3; 32]),
        workers: Some(4),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.bin").into_bytes())
        .collect();
    let mut readers: Vec<&[u8]> = members.iter().map(|m| &m[..]).collect();
    for ((bytes, name), reader) in members.iter().zip(&names).zip(readers.iter_mut()) {
        let payload = match shape {
            Shape::Bytes => Payload::Bytes(bytes),
            Shape::Reader => Payload::Reader {
                reader,
                size: bytes.len() as u64,
                crc32: None,
            },
        };
        writer
            .add(MemberSpec {
                name,
                payload,
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("write");
    out
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(archive: &[u8], members: &[Vec<u8>]) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ()).expect("read back");
    assert!(sink.0 == members, "the archive reads back as its members");
}

#[test]
fn levels_4_and_5_take_the_bound_on_both_sides_for_both_payload_kinds() {
    // Acceptance tests 1 and 4: the member of 262,144 bytes is the one
    // the option reaches, the one of 262,145 is not, and a slice and a
    // reader are written alike.
    for level in [4u8, 5] {
        for len in [BOUND, BOUND + 1] {
            let members = vec![rarkit_testdata::chatter(7, len)];
            let off = write(&members, level, false, false, Shape::Bytes);
            assert!(off == write(&members, level, false, false, Shape::Reader));
            let on = write(&members, level, false, true, Shape::Bytes);
            assert!(on == write(&members, level, false, true, Shape::Reader));
            if len == BOUND {
                assert!(
                    off != on,
                    "level {level}: the option reaches a member of {len}"
                );
            } else {
                assert!(
                    off == on,
                    "level {level}: the option passes a member of {len} by"
                );
            }
            reads_back(&off, &members);
            reads_back(&on, &members);
        }
    }
}

#[test]
fn the_bound_is_the_declared_size_and_noise_takes_the_floor_either_way() {
    // Acceptance tests 2 and 5: a member of 262,144 bytes is small
    // whether it compresses or not; an incompressible one of 32 KiB or
    // more is sampled and takes the floor effort with the option on or
    // off, so the option moves none of its bytes.
    for level in [4u8, 5] {
        for len in [32 << 10, 100_000, BOUND] {
            let members = vec![noise(len, 9)];
            let off = write(&members, level, false, false, Shape::Bytes);
            let on = write(&members, level, false, true, Shape::Bytes);
            assert!(
                off == on,
                "level {level}: {len} bytes of noise take the floor"
            );
            reads_back(&off, &members);
        }
    }
}

#[test]
fn a_solid_set_and_levels_1_to_3_are_untouched_by_the_option() {
    // Acceptance tests 3 and 6: no member of a solid set, its first
    // included, is small at any size; and levels 1 to 3 write the same
    // bytes with the option on and off (at level 3 it is a no-op).
    let members = vec![
        rarkit_testdata::chatter(1, BOUND),
        rarkit_testdata::chatter(2, BOUND + 1),
        rarkit_testdata::chatter(3, 40_000),
    ];
    for level in [4u8, 5] {
        let off = write(&members, level, true, false, Shape::Bytes);
        assert!(off == write(&members, level, true, true, Shape::Bytes));
        reads_back(&off, &members);
    }
    for level in [1u8, 2, 3] {
        for solid in [false, true] {
            let off = write(&members, level, solid, false, Shape::Bytes);
            assert!(
                off == write(&members, level, solid, true, Shape::Bytes),
                "level {level} solid {solid}"
            );
        }
    }
}

#[test]
fn the_default_is_the_lazy_parse() {
    // The option is ON by default, so a caller who leaves it
    // alone writes the lazy side's bytes at levels 4 and 5.
    assert!(WriteOptions::default().small_member_lazy);
    let members = vec![rarkit_testdata::chatter(11, BOUND)];
    for level in [4u8, 5] {
        let mut writer = Writer::new(WriteOptions {
            format: WriteFormat::Rar5,
            method: WriteMethod::Compressed {
                level,
                dictionary: None,
            },
            entropy: Entropy::Seeded([3; 32]),
            workers: Some(4),
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"m0.bin",
                payload: Payload::Bytes(&members[0]),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut default = Vec::new();
        writer.finish_into(&mut default).expect("write");
        assert!(
            default == write(&members, level, false, true, Shape::Bytes),
            "level {level}: the default is the option on"
        );
        assert!(default != write(&members, level, false, false, Shape::Bytes));
    }
}
