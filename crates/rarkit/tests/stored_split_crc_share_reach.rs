//! That the stored split CRC share FIRES, on each path a clear stored
//! member is read through: the serial `copy` (test, and extract below the
//! seam) and the seam's lent path (`read/extract/lent.rs::decode_lent`,
//! extract through the seam). `stored_split_crc_share.rs` proves the
//! verdicts are right whichever path runs; this proves the share is taken
//! at all, by the bytes each path appended rather than hashed again.
//!
//! One test in its own binary: the counts are process-wide, because the
//! lent path runs on the seam's source thread.

#![cfg(feature = "test-support")]

use std::sync::Arc;

use rarkit::{
    probe, ChecksumKind, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Payload,
    RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// Five fragments at a 64 KiB cap, the last short.
const MEMBER: usize = 300_000;
const VOLUME_CAP: u64 = 64 << 10;

struct Null;

impl std::io::Write for Null {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Keep {
    verify: bool,
    verdicts: Vec<Option<bool>>,
}

impl Sink for Keep {
    type Out = Null;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Null>> {
        Ok(if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Null)
        })
    }
    fn close(
        &mut self,
        _m: &MemberInfo<'_>,
        _o: Option<Null>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.verdicts.push(outcome.checksum_ok);
        Ok(())
    }
}

fn run(set: &[Vec<u8>], verify: bool, hint: Option<bool>) -> Vec<Option<bool>> {
    let sources: Vec<Arc<dyn RangeSource>> = set
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Keep {
        verify,
        verdicts: Vec::new(),
    };
    let options = ReadOptions::default()
        .with_workers(Some(2))
        .with_sink_is_file(hint);
    rarkit::extract(sources, &options, &mut sink, &mut ()).expect("extracts");
    sink.verdicts
}

#[test]
fn the_share_fires_on_the_copy_path_and_on_the_lent_path() {
    let payload: Vec<u8> = (0..MEMBER as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Crc32,
        volume_file_size: Some(VOLUME_CAP),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"m.bin",
            payload: Payload::Bytes(&payload),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut set: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut set).expect("finish_volumes");
    assert!(
        set.len() > 3,
        "the vector is not split over several volumes"
    );
    // Every fragment but the last is shared, so at least the first
    // volume's worth of the member is.
    let floor = (MEMBER as u64) / 2;

    for (arm, verify, hint, seam_floor) in [
        ("test", true, None, Some(u64::MAX)),
        ("extract, serial", false, None, Some(u64::MAX)),
        ("extract, through the seam", false, Some(true), Some(0)),
    ] {
        probe::set_seam_floor(seam_floor);
        probe::reset_crc_shared();
        let verdicts = run(&set, verify, hint);
        let (copy, lent) = probe::crc_shared();
        probe::set_seam_floor(None);
        assert_eq!(verdicts, vec![Some(true)], "{arm}");
        println!("{arm}: shared {copy} bytes on copy, {lent} on the lent path");
        if hint.is_some() {
            assert!(lent >= floor, "{arm}: the lent path shared {lent} bytes");
            assert_eq!(
                copy, 0,
                "{arm}: the member went through copy, not the lent path"
            );
        } else {
            assert!(copy >= floor, "{arm}: the copy path shared {copy} bytes");
            assert_eq!(lent, 0, "{arm}");
        }
        assert!(
            copy + lent < MEMBER as u64,
            "{arm}: the last fragment is never shared"
        );
    }
}
