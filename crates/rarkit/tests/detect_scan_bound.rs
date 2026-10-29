//! `detect` reads no further than its scan bound: at most `sfx_scan` bytes
//! plus one signature (API 4.1, API 5.1 "reads at most `sfx_scan` + 8
//! bytes", spec F 3.1.2 "It reads no further than `sfx_scan` plus the
//! signature's length").
//!
//! A source that records every `read_at` stands in front of a file far
//! longer than any bound tried, so a read past the bound is counted rather
//! than cut short by the end of the file.

use std::sync::atomic::{AtomicU64, Ordering};

use rarkit::{detect, Format, RangeSource};

const SIG_RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SIG_RAR4: &[u8] = b"Rar!\x1a\x07\x00";

/// A source that records how many bytes it handed out and the furthest
/// offset any read reached.
struct Counted {
    data: Vec<u8>,
    bytes: AtomicU64,
    reach: AtomicU64,
}

impl Counted {
    fn new(data: Vec<u8>) -> Self {
        Counted {
            data,
            bytes: AtomicU64::new(0),
            reach: AtomicU64::new(0),
        }
    }
}

impl RangeSource for Counted {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.read_at(offset, buf)?;
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.reach.fetch_max(offset + n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn available(&self) -> u64 {
        self.data.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

/// Scan bounds either side of the 4 KiB read and its eight byte overlap.
const BOUNDS: [u64; 12] = [0, 1, 7, 8, 100, 4087, 4088, 4095, 4096, 4097, 8191, 10_000];

/// No signature anywhere: the whole bound is searched and nothing more is
/// read.
#[test]
fn a_source_without_a_signature_is_read_no_further_than_the_bound() {
    for bound in BOUNDS {
        let src = Counted::new(vec![0x5a; 64 * 1024]);
        assert_eq!(detect(&src, bound).unwrap(), None, "bound {bound}");
        let bytes = src.bytes.load(Ordering::Relaxed);
        let reach = src.reach.load(Ordering::Relaxed);
        assert!(
            bytes <= bound + 8 && reach <= bound + 8,
            "bound {bound}: read {bytes} bytes, reaching offset {reach}; \
             the promise is at most {}",
            bound + 8
        );
    }
}

/// A signature that starts exactly at the bound is found, one byte later is
/// not, and neither reads past the bound plus the signature.
#[test]
fn a_signature_at_the_edge_is_found_within_the_bound() {
    for bound in BOUNDS {
        for (sig, format) in [(SIG_RAR5, Format::Rar5), (SIG_RAR4, Format::Rar4Family)] {
            for (start, expect) in [(bound, true), (bound + 1, false)] {
                let mut data = vec![0x5a; 64 * 1024];
                let at = start as usize;
                data[at..at + sig.len()].copy_from_slice(sig);
                let src = Counted::new(data);
                let found = detect(&src, bound).unwrap();
                if expect {
                    let found = found.unwrap_or_else(|| panic!("bound {bound}: not found"));
                    assert_eq!((found.format, found.start), (format, start));
                } else {
                    assert_eq!(found, None, "bound {bound}, start {start}");
                }
                let bytes = src.bytes.load(Ordering::Relaxed);
                let reach = src.reach.load(Ordering::Relaxed);
                assert!(
                    bytes <= bound + 8 && reach <= bound + 8,
                    "bound {bound}, signature at {start}: read {bytes} bytes, \
                     reaching offset {reach}; the promise is at most {}",
                    bound + 8
                );
            }
        }
    }
}
