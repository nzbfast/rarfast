//! The SEGMENT TEAM in a VOLUME SET (`write::engine`'s `Segments` under
//! `Run::stream_fragments`): a member longer than one stretch, streamed a
//! fragment at a time across volumes that can patch, is the SAME volumes
//! at every team width, one included, which is the walk the writer had
//! before the team (API promise 2.6). The team hands the writer packed
//! bytes a round at a time and the writer cuts them at each volume's end
//! as it cut the one engine's, so a width can move no fragment.
//!
//! Both archive formats, levels 1 and 3, a volume size that puts several
//! volume ends inside one stretch and inside one round, and the same
//! with a PASSWORD, data only and headers too, under a seeded entropy.
//! Every set reads back. The held-member limit is lowered
//! (`with_stream_above`) so that a member of a few MiB streams as a
//! member of hundreds does at the shipped limit (spec G 3.5 case b).
use std::io::{Cursor, Read};
use std::sync::Arc;

use rarkit::internals::writers::{
    reset_segment_rounds, reset_streamed_members, segment_rounds, streamed_members,
    with_segment_width, with_stream_above,
};
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, RangeSource, Rar4Version, ReadOptions, Result, Sink, VolumeOut, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

/// The dictionary of every row: 256 KiB, so a member of a few MiB is many
/// stretches.
const SMALL: u64 = 256 << 10;

/// Volumes that can patch, kept in memory.
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

fn reads_back(what: &str, volumes: &[Vec<u8>], data: &[u8], password: Option<&str>) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default().with_password(password.map(Password::new));
    let mut sink = Collect::default();
    extract(sources, &options, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: reading back: {e}"));
    assert_eq!(sink.0.len(), 1, "{what}: members read back");
    assert!(sink.0[0] == data, "{what}: the member read back differs");
}

fn options(format: WriteFormat, level: u8, volume: u64) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(SMALL),
        },
        volume_size: Some(volume),
        // The RAR 4 family refuses a filter request (SPEC-J).
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            FilterPolicy::Off
        } else {
            FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        workers: Some(4),
        // Seeded, so an encrypted set is the same bytes on every run and
        // at every width.
        entropy: Entropy::Seeded([7; 32]),
        ..WriteOptions::default()
    }
}

/// One member through a READER, the command line's payload, into volumes
/// that can patch, with the team held to `width` engines. Answers the
/// volumes, the segment team's rounds with the most engines of one, and
/// how many members the streamed walk took.
fn write(
    options: WriteOptions,
    width: usize,
    data: &[u8],
) -> (Vec<Vec<u8>>, (usize, usize), usize) {
    with_stream_above(1 << 20, || {
        with_segment_width(width, || {
            reset_segment_rounds();
            reset_streamed_members();
            let mut reader = Cursor::new(data);
            let mut writer = Writer::new(options).expect("options");
            writer
                .add(MemberSpec {
                    name: b"big.bin",
                    payload: Payload::Reader {
                        reader: &mut reader as &mut (dyn Read + Send),
                        size: data.len() as u64,
                        crc32: None,
                    },
                    mtime: None,
                    attributes: 0o644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
            let mut out = Volumes::default();
            writer.finish_volumes(&mut out).expect("finish_volumes");
            (out.0, segment_rounds(), streamed_members())
        })
    })
}

/// The width of the pool both tests here run on. A team is never wider
/// than the pool it is called from, so a test that left the pool to the
/// machine and asked for a team of four asserted a machine of four
/// threads and more.
const POOL: usize = 8;

/// A test's body on a pool of [`POOL`] threads, whatever the machine. The
/// hooks a body sets and the team it reads back are the calling thread's,
/// so the whole body runs on one thread of that pool.
fn pooled(body: fn()) {
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(body)
}

const FORMATS: [(&str, WriteFormat); 2] = [
    ("rar5", WriteFormat::Rar5),
    ("rar4v29", WriteFormat::Rar4(Rar4Version::V29)),
];

/// The one engine's volumes and the team's, compared volume by volume.
fn same_at_every_width(
    what: &str,
    options: impl Fn() -> WriteOptions,
    data: &[u8],
    password: Option<&str>,
) {
    let (one, rounds, took) = write(options(), 1, data);
    assert_eq!(took, 1, "{what}: the member was held");
    assert_eq!(rounds, (0, 0), "{what}: one engine ran a team");
    assert!(one.len() >= 3, "{what}: {} volumes", one.len());
    reads_back(what, &one, data, password);
    for width in [2usize, 4] {
        let (volumes, (rounds, most), took) = write(options(), width, data);
        assert_eq!(took, 1, "{what}: width {width} held the member");
        assert!(
            rounds > 0 && most == width,
            "{what}: width {width}, {rounds} rounds of {most}"
        );
        assert_eq!(
            volumes.len(),
            one.len(),
            "{what}: width {width} moved a volume's end"
        );
        for (index, (team, engine)) in volumes.iter().zip(&one).enumerate() {
            assert!(
                team == engine,
                "{what}: width {width} moved a byte of volume {index}"
            );
        }
    }
}

#[test]
fn a_member_split_over_volumes_is_the_same_set_at_any_team_width() {
    pooled(a_member_split_over_volumes_is_the_same_set_at_any_team_width_on_the_pool);
}

fn a_member_split_over_volumes_is_the_same_set_at_any_team_width_on_the_pool() {
    let data = rarkit_testdata::medley(41, (9 << 20) + 12_345);
    for (family, format) in FORMATS {
        for level in [1u8, 3] {
            // Volumes of 700,001 bytes: several ends inside one stretch,
            // none on a window's edge. And of 1,500,000: an end every
            // few rounds.
            for volume in [700_001u64, 1_500_000] {
                let what = format!("{family} -m{level} -v{volume}");
                same_at_every_width(&what, || options(format, level, volume), &data, None);
            }
        }
    }
}

#[test]
fn an_encrypted_member_split_over_volumes_is_the_same_set_at_any_team_width() {
    pooled(an_encrypted_member_split_over_volumes_is_the_same_set_at_any_team_width_on_the_pool);
}

fn an_encrypted_member_split_over_volumes_is_the_same_set_at_any_team_width_on_the_pool() {
    let data = rarkit_testdata::medley(43, (7 << 20) + 777);
    for (family, format) in FORMATS {
        for headers in [false, true] {
            let how = if headers { "-hp" } else { "-p" };
            let what = format!("{family} -m1 -v900001 {how}");
            let sealed = || WriteOptions {
                password: Some(Password::new("segment volumes")),
                encrypt_headers: headers,
                ..options(format, 1, 900_001)
            };
            same_at_every_width(&what, sealed, &data, Some("segment volumes"));
        }
    }
}
