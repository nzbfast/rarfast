//! The STREAMED walk (`Run::write_member_streamed`) stages a member's
//! windows the way the held walk does (`tests/one_member_windows.rs`), and
//! that is only a width: the same set is the same archive at any depth.
//!
//! The streamed walk used to hand the encoder one window per chunk, so a
//! member it streamed parsed a window's blocks per wave while the same
//! member held whole parsed a batch of windows per wave; that was part of
//! the streamed walk's wall against the held one. It now stages where the
//! caller set no ceiling, which is where the held walk does, and keeps a
//! window a flush under one.
//!
//! A SOLID volume set is what streams with no ceiling (spec G 3.5 case a),
//! so it is the set these rows write; depth 1 is the control arm, the walk
//! before this change. What the pending chunk holds is a batch's packed
//! bytes, which the engine's batch cap bounds, so the walk's working memory
//! still does not follow the member.

use std::sync::Arc;

use rarkit::internals::writers::{
    forget_widest_flush, reset_streamed_members, streamed_members, widest_flush, with_window_depth,
};
use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource, ReadOptions,
    Result, Sink, VolumeOut, WriteFormat, WriteMethod, WriteOptions, WriteReport, Writer,
};

const DEPTHS: [usize; 3] = [1, 2, usize::MAX];

#[derive(Default)]
struct Volumes(Vec<Vec<u8>>);

impl VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> Result<()> {
        self.0.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.0.push(Vec::new());
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        if let (Some(bytes), Some(last)) = (out, self.0.last_mut()) {
            *last = bytes;
        }
        Ok(())
    }
}

fn write(
    format: WriteFormat,
    level: u8,
    dictionary: u64,
    members: &[Vec<u8>],
) -> (Vec<Vec<u8>>, WriteReport) {
    let mut writer = Writer::new(WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(dictionary),
        },
        solid: true,
        volume_file_size: Some(700_000),
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|i| format!("m{i}.bin").into_bytes())
        .collect();
    for (name, data) in names.iter().zip(members) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Volumes::default();
    let report = writer.finish_volumes(&mut out).expect("finish");
    (out.0, report)
}

fn read_back(volumes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back: {e}"));
    sink.0
}

/// Every depth writes the same set, the set reads back, the long members
/// streamed, and staging did widen a flush where it could.
#[test]
fn a_streamed_member_is_the_same_archive_at_any_window_depth() {
    let rar4 = WriteFormat::Rar4(rarkit::Rar4Version::V29);
    for (label, format, level, dictionary) in [
        ("rar5 m1 128k", WriteFormat::Rar5, 1, 128 << 10),
        ("rar5 m3 256k", WriteFormat::Rar5, 3, 256 << 10),
        ("rar5 m5 256k", WriteFormat::Rar5, 5, 256 << 10),
        ("rar4 m3 256k", rar4, 3, 256 << 10),
    ] {
        let members = vec![
            rarkit_testdata::medley(1, 9_000),
            rarkit_testdata::medley(2, (3 << 20) + 4_321),
            rarkit_testdata::medley(3, (2 << 20) + 17),
        ];
        let mut first: Option<Vec<Vec<u8>>> = None;
        for depth in DEPTHS {
            reset_streamed_members();
            forget_widest_flush();
            let (volumes, _) =
                with_window_depth(depth, || write(format, level, dictionary, &members));
            assert!(
                streamed_members() >= 2,
                "{label} depth {depth}: the long members did not stream"
            );
            if depth > 1 {
                assert!(
                    widest_flush() > 1,
                    "{label} depth {depth}: no flush was wider than a window"
                );
            }
            match &first {
                None => {
                    assert_eq!(read_back(&volumes), members, "{label}: read back");
                    first = Some(volumes);
                }
                Some(control) => assert!(
                    control == &volumes,
                    "{label}: depth {depth} wrote a different set from depth 1"
                ),
            }
        }
    }
}
