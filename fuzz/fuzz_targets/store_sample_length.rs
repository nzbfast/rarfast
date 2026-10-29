//! Spec G 3.8.3: the store rule's sample, COUNTED, is the sample packed.
//!
//! Since 1 Oct 2026 the rule reads a sample's packed length off a count of
//! its parse's symbols (`encode::floor_count`, `encode::rar5::SampleLength`)
//! and packs nothing. That is sound only if the counted length is the
//! packed one on EVERY input, since a length one byte off at the 99.5
//! percent bar moves a member between stored and compressed. The scoring
//! there is a second copy of the lazy parse's, so this target holds the
//! two together on arbitrary bytes, as the crate's own test does on a
//! fixed set.
//!
//! The input is taken three ways, each as samples of at most 64 KiB:
//!
//! - as it is;
//! - repeated to 64 KiB, which is a period of the input's length;
//! - EXPANDED: read as literal runs and copies (a length, a distance back
//!   into what is already written), so that a few hundred bytes of input
//!   make 64 KiB with matches at chosen distances and lengths, which is
//!   what reaches the repeated-distance arms, the lookahead and the price
//!   model's settle.
//!
//! Each is counted and packed by judges built for it, and then all three
//! by ONE kept judge in two orders, so that the counter's head table,
//! which is never emptied, has met another sample first.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::writers::store_probe_whole;

const SAMPLE: usize = 64 << 10;

/// `data` read as literal runs and copies, up to one sample.
fn expand(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SAMPLE);
    let mut at = 0;
    while at < data.len() && out.len() < SAMPLE {
        let op = data[at];
        at += 1;
        if op < 0x60 || out.is_empty() {
            // A literal run of 1 to 16 bytes.
            let run = usize::from(op & 15) + 1;
            let end = (at + run).min(data.len());
            out.extend_from_slice(&data[at..end]);
            if end == at {
                out.push(op);
            }
            at = end;
        } else {
            // A copy: 2 to 257 bytes, or to the sample's end where the op
            // says so, from a distance of one or two bytes of input.
            let length = if op == 0xff {
                SAMPLE
            } else {
                usize::from(op - 0x60) * usize::from(1 + (op & 1)) + 2
            };
            let near = usize::from(*data.get(at).unwrap_or(&0));
            let far = usize::from(*data.get(at + 1).unwrap_or(&0));
            at += if op & 2 == 0 { 1 } else { 2 };
            let back = if op & 2 == 0 { near } else { near | far << 8 };
            let distance = back % out.len() + 1;
            for _ in 0..length.min(SAMPLE - out.len()) {
                out.push(out[out.len() - distance]);
            }
        }
    }
    out.truncate(SAMPLE);
    out
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let raw = data[..data.len().min(SAMPLE)].to_vec();
    let cycled: Vec<u8> = data.iter().copied().cycle().take(SAMPLE).collect();
    let expanded = expand(data);
    let samples: Vec<&[u8]> = [&raw, &cycled, &expanded]
        .into_iter()
        .filter(|sample| !sample.is_empty())
        .map(Vec::as_slice)
        .collect();
    let mut lengths = Vec::new();
    for sample in &samples {
        let packed = store_probe_whole(&[sample], true, true);
        let counted = store_probe_whole(&[sample], true, false);
        assert_eq!(counted, packed, "a sample of {} bytes", sample.len());
        lengths.push(packed);
    }
    // One kept judge, the samples in two orders.
    let sum: u64 = lengths.iter().sum();
    assert_eq!(store_probe_whole(&samples, false, false), sum);
    let backward: Vec<&[u8]> = samples.iter().rev().copied().collect();
    assert_eq!(store_probe_whole(&backward, false, false), sum);
});
