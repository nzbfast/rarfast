//! Spec H3 6.6's bounded copy of a FILTERED member: past the piece length
//! (256 MiB as shipped) the encoder takes the member as a carried run of
//! pieces instead of copying it whole. A test cannot afford a 256 MiB
//! member, so this binary alone sets the bench knob
//! `RARKIT_FILTER_PIECE_MIB` to 4 before the first write (the knob is read
//! once a process, which is why this is its own test binary) and writes a
//! 12 MiB filtered member through three pieces. A span's transform must be
//! measured from its MEMBER offset across every piece boundary, and
//! reference `unrar` 7.23 and rarkit's own reader must both give the
//! member back byte for byte.

use std::process::Command;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, Payload,
    RangeSource, ReadOptions, Sink, WriteMethod, WriteOptions, Writer,
};

/// 16-bit stereo PCM of slow tones and a noisy low byte (a delta pays),
/// then bytes laid out like x86 code with near calls to a few targets
/// (an address transform pays), so the pieces carry both kinds of
/// record: 7 MiB of the one and 5 MiB of the other.
fn member() -> Vec<u8> {
    const SOUND: usize = 7 << 20;
    const WHOLE: usize = 12 << 20;
    let mut hiss = rarkit_testdata::Seeded::new(0x7063_6d00);
    let mut out = Vec::with_capacity(WHOLE);
    // Two triangle waves, one a channel, of periods 1,800 and 2,600
    // frames; the low byte of every sample is noise.
    let triangle = |frame: usize, period: usize| -> i16 {
        let phase = frame % period;
        let rise = if phase < period / 2 {
            phase
        } else {
            period - phase
        };
        (rise * 40_000 / period) as i16 - 10_000
    };
    let mut frame = 0;
    while out.len() < SOUND {
        for period in [1_800, 2_600] {
            let sample = (triangle(frame, period) & !0xff) | i16::from(hiss.next_byte());
            out.extend_from_slice(&sample.to_le_bytes());
        }
        frame += 1;
    }
    out.truncate(SOUND);
    out.extend_from_slice(&rarkit_testdata::machine_like(0x7063_6d01, WHOLE - SOUND));
    out
}

fn write(data: &[u8], filters: FilterPolicy) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        filters,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"long.bin",
            payload: Payload::Bytes(data),
            mtime: None,
            attributes: 0o644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

#[derive(Default)]
struct Collect(Vec<u8>, bool);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.1 = outcome.checksum_ok == Some(true);
        self.0.extend(out.unwrap_or_default());
        Ok(())
    }
}

struct NoProgress;

impl rarkit::Progress for NoProgress {}

#[test]
fn a_filtered_member_longer_than_one_piece_round_trips() {
    // SAFETY of intent: the only test in this binary, run before any
    // write reads the knob.
    std::env::set_var("RARKIT_FILTER_PIECE_MIB", "4");
    let data = member();
    let detect = write(&data, FilterPolicy::Detect);
    let off = write(&data, FilterPolicy::Off);
    assert!(
        detect.len() * 100 < off.len() * 97,
        "the pieces filtered nothing: {} against {}",
        detect.len(),
        off.len()
    );

    let mut sink = Collect::default();
    extract(
        vec![Arc::new(detect.clone()) as Arc<dyn RangeSource>],
        &ReadOptions::default(),
        &mut sink,
        &mut NoProgress,
    )
    .expect("rarkit reads it back");
    assert!(sink.1, "the checksum failed");
    assert!(sink.0 == data, "rarkit gave back different bytes");

    let has_unrar = Command::new("unrar")
        .arg("-iver")
        .output()
        .is_ok_and(|out| out.status.success());
    if !has_unrar {
        eprintln!("reference unrar is not on PATH: the pieces are not admitted");
        return;
    }
    let dir = std::env::temp_dir().join(format!("rarkit-filter-pieces-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::write(dir.join("t.rar"), &detect).expect("the archive");
    let run = Command::new("unrar")
        .args(["x", "-y", "-idq", "t.rar"])
        .current_dir(&dir)
        .output()
        .expect("unrar runs");
    assert!(
        run.status.success(),
        "unrar refused the pieces: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let got = std::fs::read(dir.join("long.bin")).expect("the extracted member");
    assert!(got == data, "unrar gave back different bytes");
    let _ = std::fs::remove_dir_all(&dir);
}
