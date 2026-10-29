//! A member the look-ahead gave a slot and the walk then refused (a wrong
//! password) gives its slot's first buffer back.
//!
//! ONE test in this file, because it reads `rarkit::memory::current`,
//! which is the whole process's: a second test running beside it in the
//! same binary would move the figure.
//!
//! It runs `extract` at a stated width of 2 under the default memory
//! policy, over one 4 MiB archive built in memory, and the look-ahead
//! holds at most a few 512 KiB buffers. The offload floor is lowered to
//! zero for the calling thread, so the members go ahead.

#![cfg(feature = "parallel")]

use std::sync::Arc;

use rarkit::{
    extract, Disposition, Entropy, HostOs, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};

const MEMBERS: usize = 8;
/// Each member's bytes, which is also the first buffer its slot takes.
const EACH: usize = 512 << 10;

/// Bytes that do not compress, the same on every run.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 11) as u8
        })
        .collect()
}

/// One RAR 5 archive, not solid, of `MEMBERS` compressed members of `EACH`
/// bytes, encrypted under `password`.
fn archive(password: &[u8]) -> Vec<u8> {
    let bodies: Vec<Vec<u8>> = (0..MEMBERS).map(|i| noise(EACH, i as u32 + 1)).collect();
    let names: Vec<String> = (0..MEMBERS).map(|i| format!("m{i}.bin")).collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(1 << 20),
        },
        password: Some(Password::new(password)),
        entropy: Entropy::Seeded([7; 32]),
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("the writer takes these options");
    for (name, body) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0o100644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("the writer takes the member");
    }
    let mut out = std::io::Cursor::new(Vec::new());
    writer
        .finish_seek(&mut out)
        .expect("the archive is written");
    out.into_inner()
}

/// Writes every member, and reads what the engine holds at each `close`.
#[derive(Default)]
struct Held {
    at_close: Vec<u64>,
    refused: usize,
}

impl Sink for Held {
    type Out = std::io::Sink;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.at_close.push(rarkit::memory::current());
        self.refused += usize::from(outcome.password_refused);
        Ok(())
    }
}

/// The engine holds no more at the last refused member's close than at the
/// first one's.
///
/// Each member here is given a slot, and with it a first buffer of its own
/// 512 KiB from the look-ahead's spares, before the walk finds its
/// password wrong and closes it with no writer. Before this was pinned
/// that buffer was dropped still counted as taken, so every refused member
/// left 512 KiB on the engine's memory count for the rest of the
/// operation: 3.5 MiB by the eighth close here.
#[test]
fn a_refused_slot_member_gives_its_first_buffer_back() {
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::set_seq_ahead(Some(true));
    let bytes = archive(b"the right one");
    let opts = ReadOptions::default()
        .with_workers(Some(2))
        .with_password(Some(Password::new(b"the wrong one")));

    let mut sink = Held::default();
    let _ = extract(
        vec![Arc::new(bytes) as Arc<dyn RangeSource>],
        &opts,
        &mut sink,
        &mut (),
    );
    assert_eq!(sink.at_close.len(), MEMBERS, "every member is closed");
    assert_eq!(sink.refused, MEMBERS, "every member's password is refused");
    let first = sink.at_close[0];
    let last = sink.at_close[MEMBERS - 1];
    assert!(
        last < first + EACH as u64,
        "the engine's memory count rose from {first} at the first refused \
         member's close to {last} at the last one's: {:?}",
        sink.at_close
    );
}
