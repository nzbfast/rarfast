//! A member CONTINUING a solid chain keeps its packed scratch for the next
//! (`read::extract::decode`'s tail), under a policy that gives scratch back
//! (`MemoryPolicy::keeps_residency`); every other member still gives it back
//! at its end.
//!
//! Before this, the walk shrank its packed buffer to 128 KiB after every
//! member of a chain and the next member grew it straight back to the tape
//! path's 4 MiB request into fresh pages: 2.67 GB of zeroing and 655,000
//! page faults a run on a 2 GiB `-s` text set, and no lower peak, since the
//! next member grows it again (measured 30 Sep 2026).
//! What the give-back protects (the sum of high-water buffers
//! across every decoding thread) is the pool's and the look-ahead's
//! workers', and none of them continues a chain, so the non-solid twin here
//! must still give back once per member.
//!
//! ONE test in this binary: the counter is process-wide, because a worker
//! gives back on its own thread.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy, Payload,
    RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// `members` compressed members of about 600 KB, solid when asked.
fn written(members: usize, solid: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    let options = WriteOptions {
        solid,
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let data: Vec<Vec<u8>> = (0..members)
        .map(|k| rarkit_testdata::chatter((77 + k as u32) as u64, 600_000 + k * 4_099))
        .collect();
    let names: Vec<String> = (0..data.len()).map(|k| format!("m{k:02}.txt")).collect();
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

struct Collect {
    got: Vec<Vec<u8>>,
    ok: Vec<Option<bool>>,
}

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
        self.ok.push(outcome.checksum_ok);
        self.got.push(out.unwrap_or_default());
        Ok(())
    }
}

/// Extract `archive` under a NAMED budget (which gives scratch back) with
/// the seam's cost class `hint`; the members and the give-backs counted.
fn run(archive: &[u8], hint: Option<bool>) -> (Collect, u64) {
    let mut options = ReadOptions::default();
    options.memory = MemoryPolicy::from_limit(256 << 20);
    options.sink_is_file = hint;
    assert!(
        options.memory.keeps_residency(),
        "a named budget gives back"
    );
    let mut sink = Collect {
        got: Vec::new(),
        ok: Vec::new(),
    };
    rarkit::probe::reset_scratch_give_backs();
    extract(
        vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>],
        &options,
        &mut sink,
        &mut (),
    )
    .expect("extract");
    (sink, rarkit::probe::scratch_give_backs())
}

#[test]
fn a_solid_chain_keeps_its_scratch_and_every_other_member_gives_it_back() {
    const MEMBERS: usize = 10;

    let (solid, data) = written(MEMBERS, true);
    for hint in [None, Some(false), Some(true)] {
        let (sink, give_backs) = run(&solid, hint);
        assert_eq!(sink.got, data, "solid, hint {hint:?}: the bytes");
        assert!(
            sink.ok.iter().all(|&ok| ok == Some(true)),
            "solid, hint {hint:?}: every checksum"
        );
        // The chain's first member does not continue it and gives back;
        // the nine that continue keep the scratch for the next.
        assert_eq!(
            give_backs, 1,
            "solid, hint {hint:?}: one give-back, at the chain's start"
        );
    }

    // The non-solid twin: no member continues anything, so every member
    // decoded gives back, on whichever thread decoded it (the counter is
    // not vacuous, and the pool's workers are as they were).
    let (plain, data) = written(MEMBERS, false);
    let (sink, give_backs) = run(&plain, None);
    assert_eq!(sink.got, data, "non-solid: the bytes");
    assert_eq!(
        give_backs, MEMBERS as u64,
        "non-solid: a give-back per member"
    );
}
