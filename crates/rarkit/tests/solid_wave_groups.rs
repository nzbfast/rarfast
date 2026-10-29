//! A solid batch's hint waves end where walk groups do (spec H3 section
//! 8.3's structural requirement that a batch is a width and never a byte;
//! the solid work).
//!
//! Five members of three parse blocks and then one of four, all in one
//! batch at a 2 MiB dictionary: the tree's hints hold sixteen blocks, so
//! the member of four blocks, one walk group, starts at the sixteenth. A
//! wave that ended after a fixed count of blocks walked that group as two,
//! with other comparison limits, and the batched archive was not the one a
//! member at a time writes.
use rarkit::{Entropy, MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

fn write(members: &[(Vec<u8>, Vec<u8>)], depth: usize) -> Vec<u8> {
    rarkit::internals::writers::with_batch_depth(depth, || {
        let mut writer = Writer::new(WriteOptions {
            format: WriteFormat::Rar5,
            method: WriteMethod::Compressed {
                level: 4,
                dictionary: Some(2 << 20),
            },
            solid: true,
            order: rarkit::MemberOrder::AsAdded,
            entropy: Entropy::Seeded([5; 32]),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        })
        .expect("options");
        for (name, data) in members {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(data),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish");
        out
    })
}

#[test]
fn a_member_that_straddles_a_hint_wave_keeps_its_member_at_a_time_bytes() {
    let mut members: Vec<(Vec<u8>, Vec<u8>)> = (0..5)
        .map(|i| {
            (
                format!("three{i}.txt").into_bytes(),
                rarkit_testdata::chatter(100 + i as u64, 700_000 + i * 1_000),
            )
        })
        .collect();
    members.push((
        b"four.txt".to_vec(),
        rarkit_testdata::chatter(200, 1_000_000),
    ));
    members.extend((0..6).map(|i| {
        (
            format!("tail{i}.txt").into_bytes(),
            rarkit_testdata::chatter(300 + i as u64, 3_000 + i * 500),
        )
    }));
    let control = write(&members, 1);
    let batched = write(&members, 32);
    assert!(batched == control, "a batch moved a byte");
}
