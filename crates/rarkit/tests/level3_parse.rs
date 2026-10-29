//! Level 3's parse through the public `Writer`: level 3 is the lazy parse over
//! its hash chains (32 links deep with the backward extension),
//! `WriteOptions::level3_deep` keeps the earlier 64 links, and
//! `WriteOptions::level3_optimal` restores the optimal parse 8 links deep
//! and overrides the other. Each option reaches level 3 only, both archive
//! formats, solid or not, and every archive it writes reads back.
//!
//! Which parse a member took is pinned at the encoder
//! (`encode::tests::level_3_is_the_lazy_parse_32_links_deep_and_the_options_are_64_links_and_the_optimal_parse`);
//! what is pinned here is what reaches the writer.
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberSpec, Payload, RangeSource,
    Rar4Version, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};
use std::sync::Arc;

fn write(
    members: &[Vec<u8>],
    format: WriteFormat,
    level: u8,
    solid: bool,
    optimal: bool,
    deep: bool,
) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid,
        // The RAR 4 family writes no filter record (SPEC-J).
        filters: match format {
            WriteFormat::Rar5 => FilterPolicy::Detect,
            WriteFormat::Rar4(_) => FilterPolicy::Off,
        },
        level3_optimal: optimal,
        level3_deep: deep,
        entropy: Entropy::Seeded([5; 32]),
        workers: Some(4),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.txt").into_bytes())
        .collect();
    for (bytes, name) in members.iter().zip(&names) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(bytes),
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
fn the_option_reaches_level_3_only_and_every_archive_reads_back() {
    assert!(!WriteOptions::default().level3_optimal);
    assert!(!WriteOptions::default().level3_deep);
    // One member past a parse block, so it is never lone, and a small one.
    let members = vec![
        rarkit_testdata::chatter(1, 600_000),
        rarkit_testdata::chatter(2, 20_000),
    ];
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V30)] {
        for solid in [false, true] {
            let lazy = write(&members, format, 3, solid, false, false);
            let optimal = write(&members, format, 3, solid, true, false);
            let deep = write(&members, format, 3, solid, false, true);
            assert!(
                lazy != optimal,
                "{format:?} solid {solid}: the option reaches level 3"
            );
            assert!(
                lazy != deep && deep != optimal,
                "{format:?} solid {solid}: level3_deep reaches level 3"
            );
            assert!(
                write(&members, format, 3, solid, true, true) == optimal,
                "{format:?} solid {solid}: level3_optimal overrides level3_deep"
            );
            reads_back(&lazy, &members);
            reads_back(&optimal, &members);
            reads_back(&deep, &members);
            for level in [1u8, 2, 4, 5] {
                let plain = write(&members, format, level, solid, false, false);
                assert!(
                    plain == write(&members, format, level, solid, true, false)
                        && plain == write(&members, format, level, solid, false, true),
                    "{format:?} solid {solid}: the options pass level {level} by"
                );
            }
        }
    }
}
