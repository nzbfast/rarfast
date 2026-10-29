//! A DECODED member continuing a solid chain is never the seam's (spec F
//! 3.7.7, `read::seam::engages`), whatever the caller says its writer is.
//!
//! Under `sink_is_file` `Some(false)` (`p` to a stream) the seam's size
//! floor used to take every written solid member of 16 MiB and up, which
//! then decoded serially without the chain's look-ahead:
//! measured 30 Sep 2026. The non-solid twin is the
//! control that the seam still engages here at all.
//!
//! ONE test in this binary: the seam's counter is process-wide.

#![cfg(feature = "parallel")]

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource, ReadOptions,
    Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// Compressed members of these sizes, solid when asked.
fn written(solid: bool, sizes: &[usize]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let options = WriteOptions {
        solid,
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let data: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(k, &len)| rarkit_testdata::chatter((k as u32 + 1) as u64, len))
        .collect();
    let names: Vec<String> = (0..data.len()).map(|k| format!("m{k}.txt")).collect();
    let mut writer = Writer::new(options).expect("options");
    for (name, bytes) in names.iter().zip(&data) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    (out, data)
}

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
        assert_eq!(outcome.checksum_ok, Some(true), "every checksum");
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

/// Extract under `hint` at four workers; the members and the most seam
/// units alive at once.
fn run(archive: &[u8], hint: Option<bool>) -> (Vec<Vec<u8>>, usize) {
    let mut options = ReadOptions::default();
    options.workers = Some(4);
    options.sink_is_file = hint;
    let mut sink = Collect(Vec::new());
    rarkit::probe::reset_peak_seam();
    extract(
        vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>],
        &options,
        &mut sink,
        &mut (),
    )
    .expect("extract");
    (sink.0, rarkit::probe::peak_seam())
}

/// Above the seam's 16 MiB floor for a decoded member.
const BIG: usize = (17 << 20) + 123;

#[test]
fn a_member_continuing_a_solid_chain_is_never_the_seams() {
    // The control: one member above the floor, alone, is the seam's.
    let (plain, data) = written(false, &[BIG]);
    let (got, seams) = run(&plain, Some(false));
    assert_eq!(got, data, "one member: the bytes");
    assert_eq!(seams, 1, "one member above the floor is the seam's");

    // A small first member, so the one member of the chain that does not
    // continue it is under the floor too, then two above it.
    let (solid, data) = written(true, &[4_000, BIG, BIG + 4_444]);
    for hint in [None, Some(false)] {
        let (got, seams) = run(&solid, hint);
        assert_eq!(got, data, "solid, hint {hint:?}: the bytes");
        assert_eq!(
            seams, 0,
            "solid, hint {hint:?}: no member continuing the chain was the seam's"
        );
    }
}
