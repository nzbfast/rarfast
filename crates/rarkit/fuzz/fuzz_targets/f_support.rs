//! Shared scaffolding for spec F's four fuzz targets (its section 6.3):
//! a source that answers short reads of a length the fuzzer chooses, a
//! sink that can refuse a member, and a `Progress` that asserts `released`
//! is monotone on every run.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, Progress, RangeSource, Result, Sink};

/// The vectors of spec F section 5, compiled in so a target needs no file
/// at run time.
pub const VECTORS: &[(&str, &[u8])] = &[
    (
        "f01",
        include_bytes!("../../../../specs/vectors-F/archives/f01_stored.rar"),
    ),
    (
        "f02",
        include_bytes!("../../../../specs/vectors-F/archives/f02_dirs.rar"),
    ),
    (
        "f03",
        include_bytes!("../../../../specs/vectors-F/archives/f03_m3.rar"),
    ),
    (
        "f04",
        include_bytes!("../../../../specs/vectors-F/archives/f04_solid.rar"),
    ),
    (
        "f05",
        include_bytes!("../../../../specs/vectors-F/archives/f05_blake.rar"),
    ),
    (
        "f06",
        include_bytes!("../../../../specs/vectors-F/archives/f06_comment.rar"),
    ),
    (
        "f07",
        include_bytes!("../../../../specs/vectors-F/archives/f07_pw.rar"),
    ),
    (
        "f09",
        include_bytes!("../../../../specs/vectors-F/archives/f09_rr.rar"),
    ),
    (
        "f10",
        include_bytes!("../../../../specs/vectors-F/archives/f10_qo.rar"),
    ),
    (
        "d140",
        include_bytes!("../../../../specs/vectors-F/archives/D140_M5.RAR"),
    ),
    (
        "d155",
        include_bytes!("../../../../specs/vectors-F/archives/D155_M5.RAR"),
    ),
    (
        "d250",
        include_bytes!("../../../../specs/vectors-F/archives/D250_M5.RAR"),
    ),
    (
        "r420",
        include_bytes!("../../../../specs/vectors-F/archives/r420_m5.rar"),
    ),
];

/// The header-encrypted vectors, for target 4.
pub const ENCRYPTED: &[&[u8]] = &[
    include_bytes!("../../../../specs/vectors-F/archives/f08_hp.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/r420_hp.rar"),
];

/// The stored four-volume set of `f11_svol`, in order.
pub const SVOL: &[&[u8]] = &[
    include_bytes!("../../../../specs/vectors-F/archives/f11_svol.part1.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/f11_svol.part2.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/f11_svol.part3.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/f11_svol.part4.rar"),
];

/// The compressed four-volume set of `f12_cvol`, in order. Its members
/// carry the SAME name as `f11`'s, which is what makes a spliced set
/// detectable.
pub const CVOL: &[&[u8]] = &[
    include_bytes!("../../../../specs/vectors-F/archives/f12_cvol.part1.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/f12_cvol.part2.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/f12_cvol.part3.rar"),
    include_bytes!("../../../../specs/vectors-F/archives/f12_cvol.part4.rar"),
];

/// A source that answers short reads of a length the fuzzer chooses, and
/// counts the bytes it has handed out so a target can bound a run.
pub struct Choppy {
    pub data: Vec<u8>,
    pub chunk: usize,
    pub served: AtomicU64,
}

impl Choppy {
    pub fn new(data: Vec<u8>, chunk: u8) -> Arc<Choppy> {
        Arc::new(Choppy {
            data,
            chunk: usize::from(chunk).max(1),
            served: AtomicU64::new(0),
        })
    }
}

impl RangeSource for Choppy {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        let Some(rest) = self.data.get(start..) else {
            return Ok(0);
        };
        let n = rest.len().min(buf.len()).min(self.chunk);
        buf[..n].copy_from_slice(&rest[..n]);
        self.served.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn available(&self) -> u64 {
        self.data.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

/// A sink that discards, and that refuses a member when the fuzzer's bit
/// for it is set.
pub struct Fickle {
    pub refuse: u64,
    pub opened: u32,
    pub closed: Vec<(Vec<u8>, Option<bool>, u64)>,
}

impl Fickle {
    pub fn new(refuse: u64) -> Fickle {
        Fickle {
            refuse,
            opened: 0,
            closed: Vec::new(),
        }
    }
}

impl Sink for Fickle {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        let bit = self.opened.min(63);
        self.opened += 1;
        if self.refuse >> bit & 1 != 0 {
            return Err(rarkit::Error::caller(std::io::Error::other("refused")));
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed.push((
            member.name.to_vec(),
            outcome.checksum_ok,
            out.map(|v| v.len() as u64).unwrap_or(0),
        ));
        Ok(())
    }
}

/// Asserts `released` is monotone per volume on every run, which is the
/// drop-behind promise callers rely on (spec F 3.7.3).
#[derive(Default)]
pub struct Monotone {
    pub last: Vec<u64>,
}

impl Progress for Monotone {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        let v = volume as usize;
        while self.last.len() <= v {
            self.last.push(0);
        }
        assert!(
            offset >= self.last[v],
            "released went backwards on volume {volume}: {offset} after {}",
            self.last[v]
        );
        self.last[v] = offset;
        Ok(())
    }
}

/// Pick one of `items` with a byte of fuzzer entropy.
pub fn pick<T: Copy>(items: &[T], byte: u8) -> T {
    items[usize::from(byte) % items.len()]
}
