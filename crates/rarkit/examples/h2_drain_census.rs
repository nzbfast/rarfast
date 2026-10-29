//! What `Window::drain` COPIES on each cached H2 corpus, counted rather
//! than timed.
//!
//! The filtered code leg fails the 0.97x gate where its unfiltered twin
//! does not, and the difference is the drain's hold-and-scratch path
//! (measured 21 Sep 2026). A wall cannot say how many passes over
//! the member that path costs; a count can, and a count is a property of
//! the stream, so it reads the same on every box.
//!
//! It reads the archives the gate bench caches under
//! `target/bench-h2`; run that bench once first.

fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("run `cargo bench -p rarkit --bench two_arm` once to cache the corpora")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rar"))
        .collect();
    names.sort();
    println!(
        "{:<26} {:>11} {:>7} {:>6} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8}",
        "corpus",
        "bytes",
        "drains",
        "fast",
        "held",
        "direct",
        "r->scr",
        "r->hold",
        "h->scr",
        "memmove",
        "copies/B"
    );
    for name in names {
        let archive = std::fs::read(dir.join(&name)).unwrap();
        let c = match rarkit::internals::rar5::drain_census(&archive) {
            Ok(c) => c,
            Err(err) => {
                println!("{name:<26} skipped: {err}");
                continue;
            }
        };
        let moved = c.ring_direct
            + c.ring_to_scratch
            + c.ring_to_hold
            + c.hold_to_sink
            + c.hold_to_scratch
            + c.hold_memmove;
        println!(
            "{:<26} {:>11} {:>7} {:>6} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8.3}",
            name.trim_end_matches(".rar"),
            c.bytes,
            c.drains,
            c.spans_fast,
            c.spans_held,
            c.ring_direct,
            c.ring_to_scratch,
            c.ring_to_hold,
            c.hold_to_scratch,
            c.hold_memmove,
            moved as f64 / c.bytes.max(1) as f64,
        );
        if c.kinds.iter().any(|n| *n > 0) {
            println!(
                "{:<26} filters: delta {} ({} B), x86 call {} ({} B), \
                 x86 call+jump {} ({} B), arm {} ({} B)",
                "",
                c.kinds[0],
                c.kind_bytes[0],
                c.kinds[1],
                c.kind_bytes[1],
                c.kinds[2],
                c.kind_bytes[2],
                c.kinds[3],
                c.kind_bytes[3],
            );
        }
    }
}
