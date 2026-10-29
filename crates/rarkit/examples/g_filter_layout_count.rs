//! The FILTER LAYOUT of RAR 5 archives, counted rather than timed (the
//! filter layout work, 28 Sep 2026).
//!
//! For each LZ member of each archive: its declared window and size, its
//! blocks and table groups, the filter records it carries (count by kind,
//! span lengths, how the starts sit against 0x40000, the bytes covered),
//! and what the serial drain copied for it. Every figure is a property of
//! the stream and reads the same on every box. The archives may come from
//! any writer; they are read by rarkit's own parser.
//!
//!     cargo run --release --example g_filter_layout_count -- a.rar b.rar
//!     cargo run --release --example g_filter_layout_count -- -v a.rar

fn main() {
    let mut verbose = false;
    let mut paths = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "-v" {
            verbose = true;
        } else {
            paths.push(arg);
        }
    }
    const KINDS: [&str; 4] = ["delta", "e8", "e8e9", "arm"];
    for path in paths {
        let archive = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let layouts = rarkit::internals::rar5::filter_layout(&archive)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        for (index, m) in layouts.iter().enumerate() {
            let mut by_kind = [0u64; 4];
            let mut lengths: Vec<u32> = Vec::with_capacity(m.spans.len());
            let mut covered = 0u64;
            let mut aligned = 0u64;
            for &(start, length, slot) in &m.spans {
                by_kind[usize::from(slot.min(3))] += 1;
                lengths.push(length);
                covered += u64::from(length);
                if start % 0x40000 == 0 {
                    aligned += 1;
                }
            }
            lengths.sort_unstable();
            let pick = |q: usize| {
                if lengths.is_empty() {
                    0
                } else {
                    lengths[(lengths.len() - 1) * q / 100]
                }
            };
            let d = &m.drain;
            println!(
                "{path} #{index}: window {} unpacked {} blocks {} groups {} | records {} \
                 (delta {} e8 {} e8e9 {} arm {}) length min {} p50 {} max {} | starts on 0x40000 {} \
                 | covered {} ({:.3}) | drains {} fast {} held {} direct {} r->scr {} r->hold {} \
                 h->sink {} h->scr {} memmove {}",
                m.window,
                m.unpacked,
                m.blocks,
                m.groups,
                m.spans.len(),
                by_kind[0],
                by_kind[1],
                by_kind[2],
                by_kind[3],
                pick(0),
                pick(50),
                pick(100),
                aligned,
                covered,
                covered as f64 / m.unpacked.max(1) as f64,
                d.drains,
                d.spans_fast,
                d.spans_held,
                d.ring_direct,
                d.ring_to_scratch,
                d.ring_to_hold,
                d.hold_to_sink,
                d.hold_to_scratch,
                d.hold_memmove,
            );
            if verbose {
                for &(start, length, slot) in &m.spans {
                    println!(
                        "  {start:#010x} +{length:#08x} {}",
                        KINDS[usize::from(slot.min(3))]
                    );
                }
            }
        }
    }
}
