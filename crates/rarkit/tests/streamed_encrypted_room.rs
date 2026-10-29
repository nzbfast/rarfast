//! The STREAMED walk under a password and a FILE budget keeps every
//! volume inside its cap, and ends.
//!
//! Two faults of the bug sweep of 4 Oct 2026 sat in the walk's cipher
//! branch (`Run::stream_fragments`):
//!
//! - L-33: a member's LAST fragment was placed whenever its plain bytes
//!   fitted the room, and the cipher then padded it to a whole block of
//!   16, up to 15 bytes past the room and so past the cap. The held walk
//!   fits the PADDED length (`Run::fit_header`);
//! - M-25, the streamed form: a volume whose room beside the fragment's
//!   header is under one block took a fragment of no bytes, and where a
//!   fresh volume has no more room than that the walk never ended.
//!
//! Width and memory: each write runs on a pool of [`POOL`] threads with
//! one worker asked for, under the default memory policy, with the
//! streaming threshold lowered by the test hook so that a member of a few
//! hundred kilobytes takes the walk a large one takes.

use std::io::{Cursor, Read};
use std::sync::Arc;

use rarkit::internals::writers::{reset_streamed_members, streamed_members, with_stream_above};
use rarkit::{
    extract, Disposition, Entropy, Error, FilterPolicy, HostOs, MemberInfo, MemberOutcome,
    MemberSpec, Password, Payload, RangeSource, ReadOptions, Result, Sink, VolumeOut, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &str = "padded past the room";

/// The pool every write here runs on, whatever the machine.
const POOL: usize = 2;

fn pooled<T: Send>(body: impl FnOnce() -> T + Send) -> T {
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(body)
}

/// Volumes that can be patched, so a long member streams, and that give
/// out after `most`: the stand-in for a disk filling up.
struct Volumes {
    most: usize,
    kept: Vec<Vec<u8>>,
}

impl VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        if self.kept.len() >= self.most {
            return Err(Error::from(std::io::Error::other(
                "the run opened more volumes than it could need",
            )));
        }
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> Result<()> {
        self.kept.push(volume);
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
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn read_back(volumes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    let options = ReadOptions::default().with_password(Some(Password::new(PASSWORD)));
    extract(sources, &options, &mut sink, &mut ()).unwrap_or_else(|e| panic!("reading back: {e}"));
    sink.0
}

/// One member through a reader, RAR 5, a FILE budget of `cap`, streamed.
/// Answers the run's outcome, the volumes it closed and whether the
/// member took the streamed walk.
fn write(data: &[u8], cap: u64, most: usize) -> (Result<()>, Vec<Vec<u8>>, bool) {
    pooled(|| {
        with_stream_above(1 << 16, || {
            reset_streamed_members();
            let mut reader = Cursor::new(data);
            let mut out = Volumes {
                most,
                kept: Vec::new(),
            };
            let outcome = (|| {
                let mut writer = Writer::new(WriteOptions {
                    format: WriteFormat::Rar5,
                    method: WriteMethod::Compressed {
                        level: 1,
                        dictionary: Some(128 << 10),
                    },
                    password: Some(Password::new(PASSWORD)),
                    entropy: Entropy::Seeded([9u8; 32]),
                    volume_file_size: Some(cap),
                    filters: FilterPolicy::Off,
                    host_os: HostOs::Unix,
                    workers: Some(1),
                    ..WriteOptions::default()
                })?;
                writer.add(MemberSpec {
                    name: b"member.txt",
                    payload: Payload::Reader {
                        reader: &mut reader as &mut (dyn Read + Send),
                        size: data.len() as u64,
                        crc32: None,
                    },
                    mtime: None,
                    attributes: 0o644,
                    host_os: HostOs::Unix,
                    is_directory: false,
                })?;
                writer.finish_volumes(&mut out).map(|_| ())
            })();
            (outcome, out.kept, streamed_members() > 0)
        })
    })
}

/// L-33: caps swept a byte at a time across the sixteen that end at the
/// length the member takes whole. Somewhere in them the member's plain
/// packed bytes fit the room and its padded block does not.
#[test]
fn a_streamed_last_fragment_is_padded_inside_its_volumes_cap() {
    let mut over = Vec::new();
    for seed in 1..=3u64 {
        let data = rarkit_testdata::chatter(seed, 300_000 + seed as usize * 1_111);
        let (outcome, whole, streamed) = write(&data, 1 << 30, 4);
        outcome.expect("the uncapped write");
        assert!(streamed, "seed {seed}: the member did not stream");
        assert_eq!(whole.len(), 1, "seed {seed}: not one volume");
        let full = whole[0].len() as u64;
        for cap in full - 16..=full {
            let what = format!("seed {seed} cap={cap} (whole at {full})");
            let (outcome, volumes, streamed) = write(&data, cap, 8);
            outcome.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(streamed, "{what}: the member did not stream");
            for (i, volume) in volumes.iter().enumerate() {
                if volume.len() as u64 > cap {
                    over.push(format!("{what}: volume {i} is {} bytes", volume.len()));
                }
            }
            assert_eq!(read_back(&volumes), vec![data.clone()], "{what}");
        }
    }
    assert!(
        over.is_empty(),
        "{} volumes past their cap, the first: {}",
        over.len(),
        over[0]
    );
}

/// M-25, the streamed form: caps near the floor, where a fresh volume
/// may hold the fragment's header and under one cipher block beside it.
/// The member packs to a few hundred bytes, so a run that ends needs a
/// few dozen volumes at most; each cap is honoured or refused.
#[test]
fn a_streamed_member_under_a_file_cap_near_the_floor_ends() {
    let data = vec![b'z'; 300_000];
    let mut written = 0;
    for cap in 70u64..220 {
        let what = format!("cap={cap}");
        let (outcome, volumes, _) = write(&data, cap, 400);
        match outcome {
            Err(e) => assert!(
                volumes.len() < 400,
                "{what}: the run opened volumes until its output gave out: {e}"
            ),
            Ok(()) => {
                for (i, volume) in volumes.iter().enumerate() {
                    assert!(
                        volume.len() as u64 <= cap,
                        "{what}: volume {i} is {} bytes",
                        volume.len()
                    );
                }
                assert_eq!(read_back(&volumes), vec![data.clone()], "{what}");
                written += 1;
            }
        }
    }
    assert!(written > 0, "no cap in the sweep wrote a set");
}
