//! The worker team's KEPT BUFFERS stay bounded at the default memory
//! policy (`Run::keep_spare`), as they are under a caller's ceiling.
//!
//! **The finding.** A member the team does not take is packed by the
//! writing thread into its own buffer, and that buffer came back to the
//! team's kept buffers when the next team member was written
//! (`Run::take_prepared`). At the default policy they were bounded by
//! count alone, so every large member's packed capacity stayed for the
//! rest of the run: on the 4 GiB binary set (9,516 real members, the
//! largest 237 MB) the stated peak climbed to 645 to 844 MB and the
//! process to 565 to 684 MiB, over the 512 MiB ceiling.
//!
//! **What is checked.** A set of small members with THREE large members of
//! noise among them states a peak close to the same set with ONE: the
//! first two large members' buffers are not kept while the third is
//! written. Both archives are the member-at-a-time walk's.

use rarkit::internals::writers;
use rarkit::{
    Entropy, MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, WriteReport, Writer,
};

struct Entry {
    name: Vec<u8>,
    bytes: Vec<u8>,
}

const LARGE: usize = 12 << 20;

/// Three hundred small members of text, and `large` members of noise
/// spread among them.
fn set(large: usize) -> Vec<Entry> {
    let mut sizes = rarkit_testdata::Seeded::new(77);
    let mut entries: Vec<Entry> = (0..300u64)
        .map(|i| Entry {
            name: format!("small{i:03}.txt").into_bytes(),
            bytes: rarkit_testdata::chatter(i, sizes.between(1, 16_000)),
        })
        .collect();
    for n in 0..large {
        entries.insert(
            60 + n * 90,
            Entry {
                name: format!("large{n}.bin").into_bytes(),
                bytes: rarkit_testdata::scramble(n as u64 + 1, LARGE),
            },
        );
    }
    entries
}

fn options(workers: usize) -> WriteOptions {
    WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: None,
        },
        entropy: Entropy::Seeded([7; 32]),
        workers: Some(workers),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

/// Writes `entries` as one archive, every member a READER (the command
/// line's shape).
fn write(entries: &[Entry], options: WriteOptions) -> (Vec<u8>, WriteReport) {
    let mut readers: Vec<std::io::Cursor<&[u8]>> = entries
        .iter()
        .map(|entry| std::io::Cursor::new(entry.bytes.as_slice()))
        .collect();
    let mut writer = Writer::new(options).expect("options");
    for (entry, reader) in entries.iter().zip(readers.iter_mut()) {
        writer
            .add(MemberSpec {
                name: &entry.name,
                payload: Payload::Reader {
                    reader,
                    size: entry.bytes.len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    let report = writer.finish_into(&mut out).expect("write");
    (out, report)
}

#[test]
fn the_team_keeps_no_large_members_packed_buffers_at_the_default_policy() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .expect("a pool");
    let one = set(1);
    let three = set(3);
    let (one_alone, _) = write(&one, options(1));
    let (three_alone, _) = write(&three, options(1));
    let (one_wide, one_report, three_wide, three_report, prepared) = pool.install(|| {
        writers::reset_team_prepared();
        let (one_wide, one_report) = write(&one, options(4));
        let (three_wide, three_report) = write(&three, options(4));
        (
            one_wide,
            one_report,
            three_wide,
            three_report,
            writers::team_prepared(),
        )
    });
    assert!(prepared > 0, "the team ran");
    assert!(
        one_wide == one_alone,
        "the team moved a byte (one large member)"
    );
    assert!(three_wide == three_alone, "the team moved a byte (three)");
    // Each large member's packed output is its size and more; kept, the
    // first two would add at least that much each to the third's peak,
    // twice LARGE. Since 30 Sep 2026 the crews' resident bytes are stated
    // at every sample (`Run::team_resident`), so a large member the lead
    // writes while the crews hold theirs states both, which is about 6.9
    // MB here and is no kept buffer: the bound is one
    // LARGE, which two kept buffers still pass by twelve MiB.
    let grown = three_report
        .peak_working_memory
        .saturating_sub(one_report.peak_working_memory);
    assert!(
        grown < LARGE as u64,
        "three large members stated {} against one's {}: {grown} more, so the team kept \
         the earlier ones' packed buffers",
        three_report.peak_working_memory,
        one_report.peak_working_memory
    );
}
