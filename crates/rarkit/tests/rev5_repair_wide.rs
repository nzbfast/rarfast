//! `rev5::repair` over a set large enough for its walk across the pool:
//! the bytes it writes, and how often it reads a source.
//!
//! A repair reads every surviving volume once to check it against the
//! table and once to rebuild from it, and no more (SPEC-CLI 13.3 R12
//! does not fix the count; this is the count the code is held to). The set here is six stored volumes of 1,200,000 bytes and three
//! recovery volumes, with two volumes absent and one present and wrong,
//! so three are rebuilt and the stripe is long enough for the wide walk
//! on a pool of two threads or more. On a pool of one thread the same
//! assertions hold of the stripe walk.
//!
//! Width and memory: any width; about 60 MB, the set held twice and the
//! rebuilt volumes once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rarkit::{MemberSpec, Payload, RangeSource, RevCount, WriteOptions, Writer};

/// Deterministic bytes an encoder cannot shrink much.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    // A congruential walk of 64 bits from a start the seed picks; each
    // byte is taken from the walk's upper half, where it does not repeat
    // within any length used here.
    let mut walk = seed.wrapping_add(1).wrapping_mul(0x0123_4567_89AB_CDEF);
    let mut bytes = Vec::with_capacity(n);
    while bytes.len() < n {
        walk = walk.wrapping_mul(6_700_417).wrapping_add(104_729);
        bytes.push((walk >> 37) as u8);
    }
    bytes
}

/// Writes one stored member as a file-capped set with `.rev` volumes.
fn set_with_rev(data: &[u8], cap: u64, count: RevCount) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let options = WriteOptions {
        volume_file_size: Some(cap),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"payload.bin",
            payload: Payload::Bytes(data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let mut rev: Vec<Vec<u8>> = Vec::new();
    writer
        .finish_volumes_with_recovery(
            &mut volumes,
            &mut rev,
            count,
            &rarkit::rev5::RevOptions {
                memory: rarkit::MemoryPolicy::default(),
            },
        )
        .expect("finish with recovery");
    (volumes, rev)
}

/// A source that counts the bytes read from it.
struct Counted {
    bytes: Vec<u8>,
    read: AtomicU64,
}

impl RangeSource for Counted {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let got = self.bytes.read_at(offset, buf)?;
        self.read.fetch_add(got as u64, Ordering::Relaxed);
        Ok(got)
    }
    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

fn counted(bytes: &[u8]) -> Arc<Counted> {
    Arc::new(Counted {
        bytes: bytes.to_vec(),
        read: AtomicU64::new(0),
    })
}

/// A writer whose bytes can be read after the repair has let it go.
struct Kept(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Kept {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn three_volumes_are_rebuilt_byte_for_byte_and_no_source_is_read_a_third_time() {
    let data = noise(6_800_000, 41);
    let (volumes, rev) = set_with_rev(&data, 1_200_000, RevCount::Exactly(3));
    assert_eq!(volumes.len(), 6, "the set's shape");
    let (absent, wrong) = ([1usize, 5], 3usize);

    let infos: Vec<rarkit::rev5::RevInfo> = rev
        .iter()
        .map(|r| rarkit::rev5::inspect(r as &dyn RangeSource).expect("inspect"))
        .collect();
    let rev_sources: Vec<Arc<Counted>> = rev.iter().map(|r| counted(r)).collect();
    let data_sources: Vec<Option<Arc<Counted>>> = volumes
        .iter()
        .enumerate()
        .map(|(index, volume)| {
            if absent.contains(&index) {
                None
            } else if index == wrong {
                let mut spoiled = volume.clone();
                spoiled[600_000] ^= 0x40;
                Some(counted(&spoiled))
            } else {
                Some(counted(volume))
            }
        })
        .collect();

    let rebuilt: Vec<Arc<Mutex<Vec<u8>>>> = (0..volumes.len())
        .map(|_| Arc::new(Mutex::new(Vec::new())))
        .collect();
    let report = rarkit::rev5::repair(
        &rarkit::rev5::RepairSet {
            data: data_sources
                .iter()
                .map(|slot| slot.clone().map(|s| s as Arc<dyn RangeSource>))
                .collect(),
            recovery: infos
                .iter()
                .zip(&rev_sources)
                .map(|(info, source)| (info, Arc::clone(source) as Arc<dyn RangeSource>))
                .collect(),
        },
        &rarkit::MemoryPolicy::default(),
        &mut |index| {
            Ok(Box::new(Kept(Arc::clone(&rebuilt[index as usize])))
                as Box<dyn std::io::Write + Send>)
        },
        &mut (),
    )
    .expect("repair");

    assert_eq!(report.rebuilt, vec![1, 3, 5]);
    assert!(report.failed.is_empty());
    for index in [1usize, 3, 5] {
        assert!(
            *rebuilt[index].lock().unwrap() == volumes[index],
            "volume {index} is not the set's own"
        );
    }
    // Once to check, once to rebuild. The volume that was wrong is read
    // to check it and never again.
    for (index, slot) in data_sources.iter().enumerate() {
        let Some(source) = slot else { continue };
        let read = source.read.load(Ordering::Relaxed);
        let size = source.bytes.len() as u64;
        let owed = if index == wrong { size } else { 2 * size };
        assert!(read <= owed, "volume {index}: {read} bytes read of {size}");
    }
    for (index, source) in rev_sources.iter().enumerate() {
        let read = source.read.load(Ordering::Relaxed);
        let size = source.bytes.len() as u64;
        assert!(
            read <= 2 * size,
            "recovery volume {index}: {read} bytes read of {size}"
        );
    }
}
