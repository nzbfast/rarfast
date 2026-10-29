//! A member the WALK decodes while a worker writes it (`extract_parallel`
//! over a solid archive, the member over the offload floor): what the
//! caller sees at its close is what the sequential walk shows it.
//!
//! Every test here runs `extract_parallel` at a stated worker count of 2
//! (three threads with the walk, inside the narrowest hosted runner) under
//! the default memory policy, over archives of a few hundred kilobytes
//! built in memory. The offload floor is lowered to zero for the calling
//! thread, because every member here is far below the production floor.

#![cfg(feature = "parallel")]

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, Entropy, ErrorKind, HostOs, MemberInfo, MemberOutcome,
    MemberSpec, ParallelSink, Password, Payload, RangeSource, ReadOptions, Result, Sink,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// The worker count every test here asks for.
const WORKERS: usize = 2;

/// One solid RAR 5 archive of `members` compressed members of `each` bytes,
/// its member data encrypted when a password is given.
fn solid(members: usize, each: usize, password: Option<&[u8]>) -> Vec<u8> {
    let bodies: Vec<Vec<u8>> = (0..members)
        .map(|i| rarkit_testdata::chatter((i as u32 + 1) as u64, each))
        .collect();
    let names: Vec<String> = (0..members).map(|i| format!("m{i}.txt")).collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(1 << 20),
        },
        password: password.map(Password::new),
        solid: true,
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

fn sources(bytes: Vec<u8>) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes) as Arc<dyn RangeSource>]
}

/// A caller's writer that knows how many of its kind are alive, and that
/// refuses every write when told to.
struct Out {
    live: Arc<AtomicUsize>,
    refuses: bool,
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.refuses {
            return Err(std::io::Error::other("this test's writer is full"));
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What one `close` was told: the member, its verdict, whether its writer
/// came back.
type Closed = (Vec<u8>, Option<bool>, bool);

/// The sink for both drivers.
#[derive(Default)]
struct Watch {
    /// The member, by the order of its `open`, whose writer refuses.
    refuses: Option<usize>,
    opened: AtomicUsize,
    live: Arc<AtomicUsize>,
    /// How many EARLIER writers were still alive at each `open`.
    live_at_open: Mutex<Vec<usize>>,
    closed: Mutex<Vec<Closed>>,
}

impl ParallelSink for Watch {
    type Out = Out;

    fn open(&self, _member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        let live = self.live.fetch_add(1, Ordering::SeqCst);
        self.live_at_open
            .lock()
            .expect("the sink's lock")
            .push(live);
        let index = self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(Disposition::Write(Out {
            live: Arc::clone(&self.live),
            refuses: self.refuses == Some(index),
        }))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed.lock().expect("the sink's lock").push((
            member.name.to_vec(),
            outcome.checksum_ok,
            out.is_some(),
        ));
        Ok(())
    }
}

impl Sink for Watch {
    type Out = Out;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        ParallelSink::open(self, member)
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        ParallelSink::close(self, member, out, outcome)
    }
}

impl Watch {
    fn closed(&self) -> Vec<Closed> {
        self.closed.lock().expect("the sink's lock").clone()
    }

    fn live_at_open(&self) -> Vec<usize> {
        self.live_at_open.lock().expect("the sink's lock").clone()
    }
}

/// A caller's write error that only the WORKER's answer carries ends the
/// run without closing the member, as the sequential walk ends it.
///
/// The member is 40,000 bytes, below the 64 KiB chunk the walk hands its
/// worker, so the one chunk leaves the walk at the member's close and the
/// refusal cannot reach the walk through a later `write`: it arrives in
/// the worker's answer and nowhere else. The sequential walk raises the
/// caller's error out of the write and never closes that member; before
/// this was pinned the pool closed it with the walk's own verdict (the
/// checksum good, the bytes whole) and raised the error afterwards.
#[test]
fn a_write_error_in_the_worker_s_answer_closes_nothing() {
    rarkit::probe::set_offload_floor(Some(0));
    let bytes = solid(3, 40_000, None);
    let opts = ReadOptions::default();

    let mut serial = Watch {
        refuses: Some(1),
        ..Watch::default()
    };
    let want = extract(sources(bytes.clone()), &opts, &mut serial, &mut ())
        .expect_err("the writer refused");
    assert!(matches!(want.kind(), ErrorKind::Caller), "{want}");
    assert_eq!(
        serial.closed(),
        vec![(b"m0.txt".to_vec(), Some(true), true)],
        "the sequential walk closes the member before the refused one and no other"
    );

    let wide = Watch {
        refuses: Some(1),
        ..Watch::default()
    };
    let have =
        extract_parallel(sources(bytes), &opts, &wide, WORKERS).expect_err("the writer refused");
    assert!(matches!(have.kind(), ErrorKind::Caller), "{have}");
    assert!(
        have.into_caller_error().is_ok(),
        "the caller's value is recoverable"
    );
    assert_eq!(
        wide.closed(),
        serial.closed(),
        "the pool closed a member the sequential walk does not close"
    );
}

/// A member refused after its `open` (a wrong password) gives its worker
/// back: the caller's writer for it is gone by the next member's `open`.
///
/// The walk closes such a member with no writer, and the writer itself is
/// with the worker the pool piped the member to. Before this was pinned
/// nobody took that worker's answer: the worker never came free again, and
/// the answer kept the caller's writer alive to the end of the operation,
/// one for every worker in the pool.
#[test]
fn a_member_refused_after_its_open_gives_its_worker_back() {
    rarkit::probe::set_offload_floor(Some(0));
    const MEMBERS: usize = 6;
    let bytes = solid(MEMBERS, 40_000, Some(b"the right one"));
    let opts = ReadOptions::default().with_password(Some(Password::new(b"the wrong one")));

    let mut serial = Watch::default();
    let want = extract(sources(bytes.clone()), &opts, &mut serial, &mut ());
    assert_eq!(serial.closed().len(), MEMBERS, "every member is closed");
    assert_eq!(
        serial.live_at_open(),
        vec![0; MEMBERS],
        "the sequential walk holds no refused member's writer"
    );

    let wide = Watch::default();
    let have = extract_parallel(sources(bytes), &opts, &wide, WORKERS);
    assert_eq!(
        have.as_ref().map_err(|e| format!("{:?}", e.kind())).ok(),
        want.as_ref().map_err(|e| format!("{:?}", e.kind())).ok(),
        "the two drivers end differently"
    );
    assert_eq!(
        have.err().map(|e| format!("{:?}", e.kind())),
        want.err().map(|e| format!("{:?}", e.kind())),
        "the two drivers end in different errors"
    );
    assert_eq!(wide.closed(), serial.closed());
    assert_eq!(
        wide.live_at_open(),
        vec![0; MEMBERS],
        "a refused member's writer was still alive when a later member opened"
    );
}
