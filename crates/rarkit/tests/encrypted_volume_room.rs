//! An encrypted volume set whose budget leaves less than a cipher block
//! of room: the run ends, and no volume is longer than its cap.
//!
//! A fragment that is not a member's last holds whole cipher blocks of 16
//! bytes, so a volume with fewer than 16 bytes of room takes none of it.
//! Two faults sat there (bug sweep of 4 Oct 2026, M-25 and M-24):
//!
//! - a PAYLOAD budget (`WriteOptions::volume_size`) under 16 with a
//!   password never holds a block, and a member longer than the budget
//!   opened volumes for ever, each with a fragment of no bytes;
//! - a FILE budget (`WriteOptions::volume_file_size`) whose open volume
//!   had a header's room and under 16 bytes beside it opened a fresh
//!   volume and then filled it without paying for the fragment's header,
//!   so that volume ran past its cap (spec G 3.10.1: never).
//!
//! Width and memory: every member here is STORED and the memory policy is
//! the default one, so no thread pool and no ceiling enters; the tests
//! read the same on a runner of 2, 3 or 4 threads.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, Entropy, Error, FilterPolicy, HostOs, MemberInfo, MemberOutcome,
    MemberSpec, Password, Payload, RangeSource, Rar4Version, ReadOptions, Result, Sink, VolumeOut,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &str = "a block or nothing";

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// Volumes kept in memory, and a refusal once there are more than a run
/// that ends could need: the stand-in for a disk filling up.
struct Bounded {
    most: usize,
    kept: Vec<Vec<u8>>,
}

impl VolumeOut for Bounded {
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

fn spec<'a>(name: &'a [u8], data: &'a [u8]) -> MemberSpec<'a> {
    MemberSpec {
        name,
        payload: Payload::Bytes(data),
        mtime: None,
        attributes: 0o644,
        host_os: HostOs::Unix,
        is_directory: false,
    }
}

/// M-25: a payload budget under one cipher block, with a password, is
/// refused where the options are read, and never loops.
#[test]
fn a_payload_budget_under_a_cipher_block_with_a_password_ends() {
    let data = bytes(100, 7);
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        for size in [1u64, 8, 15] {
            let what = format!("{format:?} volume_size={size}");
            let made = Writer::new(WriteOptions {
                format,
                method: WriteMethod::Stored,
                password: Some(Password::new(PASSWORD)),
                entropy: Entropy::Seeded([3u8; 32]),
                volume_size: Some(size),
                filters: FilterPolicy::Off,
                host_os: HostOs::Unix,
                ..WriteOptions::default()
            });
            let Ok(mut writer) = made else {
                // Refused before anything is written: the answer.
                continue;
            };
            writer.add(spec(b"member.bin", &data)).expect("add");
            // 100 bytes at one byte a volume is 100 volumes; a run that
            // passes 400 is not going to end.
            let mut out = Bounded {
                most: 400,
                kept: Vec::new(),
            };
            match writer.finish_volumes(&mut out) {
                Ok(_) => assert_eq!(read_back(&out.kept), vec![data.clone()], "{what}"),
                Err(e) => assert!(
                    out.kept.len() < 400,
                    "{what}: the run opened volumes until its output gave out: {e}"
                ),
            }
        }
    }
}

/// The least payload budget a password leaves room for is one block, and
/// it still writes a set that reads back.
#[test]
fn a_payload_budget_of_one_cipher_block_with_a_password_writes_a_set() {
    let data = bytes(100, 9);
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        let mut writer = Writer::new(WriteOptions {
            format,
            method: WriteMethod::Stored,
            password: Some(Password::new(PASSWORD)),
            entropy: Entropy::Seeded([3u8; 32]),
            volume_size: Some(16),
            filters: FilterPolicy::Off,
            host_os: HostOs::Unix,
            ..WriteOptions::default()
        })
        .expect("options");
        writer.add(spec(b"member.bin", &data)).expect("add");
        let mut out = Bounded {
            most: 400,
            kept: Vec::new(),
        };
        writer.finish_volumes(&mut out).expect("finish_volumes");
        assert!(out.kept.len() > 1, "{format:?}: not a set");
        assert_eq!(read_back(&out.kept), vec![data.clone()], "{format:?}");
    }
}

/// M-24: under a FILE budget every volume of an encrypted set is at most
/// its cap, whatever room a member boundary leaves. The caps are swept a
/// byte at a time so that some boundary leaves a header's room and
/// between 1 and 15 bytes beside it.
#[test]
fn every_volume_of_an_encrypted_set_is_at_most_its_file_cap() {
    let members: Vec<(Vec<u8>, Vec<u8>)> = (0..12usize)
        .map(|i| {
            (
                format!("m{i}.bin").into_bytes(),
                bytes(150 + i * 37, i as u64 + 1),
            )
        })
        .collect();
    let want: Vec<Vec<u8>> = members.iter().map(|m| m.1.clone()).collect();
    let mut over = Vec::new();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        for encrypt_headers in [false, true] {
            for cap in 600u64..664 {
                let what = format!("{format:?} headers={encrypt_headers} cap={cap}");
                let mut writer = Writer::new(WriteOptions {
                    format,
                    method: WriteMethod::Stored,
                    password: Some(Password::new(PASSWORD)),
                    encrypt_headers,
                    entropy: Entropy::Seeded([5u8; 32]),
                    volume_file_size: Some(cap),
                    filters: FilterPolicy::Off,
                    host_os: HostOs::Unix,
                    ..WriteOptions::default()
                })
                .expect("options");
                for (name, data) in &members {
                    writer.add(spec(name, data)).expect("add");
                }
                let mut out = Bounded {
                    most: 4000,
                    kept: Vec::new(),
                };
                writer
                    .finish_volumes(&mut out)
                    .unwrap_or_else(|e| panic!("{what}: {e}"));
                for (i, volume) in out.kept.iter().enumerate() {
                    if volume.len() as u64 > cap {
                        over.push(format!("{what}: volume {i} is {} bytes", volume.len()));
                    }
                }
                assert_eq!(read_back(&out.kept), want, "{what}: read back");
            }
        }
    }
    assert!(
        over.is_empty(),
        "{} volumes past their cap, the first: {}",
        over.len(),
        over[0]
    );
}

/// M-24 and M-25 at the small end: a FILE budget near the floor, where a
/// fresh volume may not hold a header and one cipher block, either
/// writes a set inside its cap or is refused. It never runs on.
#[test]
fn a_file_cap_near_the_floor_with_a_password_is_honoured_or_refused() {
    let members: Vec<(Vec<u8>, Vec<u8>)> = (0..3usize)
        .map(|i| {
            (
                format!("m{i}.bin").into_bytes(),
                bytes(200 + i * 37, i as u64 + 1),
            )
        })
        .collect();
    let want: Vec<Vec<u8>> = members.iter().map(|m| m.1.clone()).collect();
    let mut written = 0;
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        for encrypt_headers in [false, true] {
            for cap in (60u64..260).step_by(3) {
                let what = format!("{format:?} headers={encrypt_headers} cap={cap}");
                let Ok(mut writer) = Writer::new(WriteOptions {
                    format,
                    method: WriteMethod::Stored,
                    password: Some(Password::new(PASSWORD)),
                    encrypt_headers,
                    entropy: Entropy::Seeded([5u8; 32]),
                    volume_file_size: Some(cap),
                    filters: FilterPolicy::Off,
                    host_os: HostOs::Unix,
                    ..WriteOptions::default()
                }) else {
                    continue;
                };
                for (name, data) in &members {
                    writer.add(spec(name, data)).expect("add");
                }
                // 711 bytes at one block a volume is 45 volumes.
                let mut out = Bounded {
                    most: 200,
                    kept: Vec::new(),
                };
                match writer.finish_volumes(&mut out) {
                    Err(e) => assert!(
                        out.kept.len() < 200,
                        "{what}: the run opened volumes until its output gave out: {e}"
                    ),
                    Ok(_) => {
                        for (i, volume) in out.kept.iter().enumerate() {
                            assert!(
                                volume.len() as u64 <= cap,
                                "{what}: volume {i} is {} bytes",
                                volume.len()
                            );
                        }
                        assert_eq!(read_back(&out.kept), want, "{what}: read back");
                        written += 1;
                    }
                }
            }
        }
    }
    assert!(written > 0, "no cap in the sweep wrote a set");
}
