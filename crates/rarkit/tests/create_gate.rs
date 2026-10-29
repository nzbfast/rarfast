//! Spec G section 7.1's create legs, CHECKED.
//!
//! the gate bench times the same legs; this file is what says the
//! two arms of each one wrote the same archive, so that the ratio the
//! bench prints is a ratio over equal work. The archives themselves are
//! not compared - two correct writers of one format compress the same
//! bytes differently - so what is compared is every member's name and
//! every member's bytes, read back out of BOTH arms' archives by BOTH
//! engines (`support/creategate.rs::check_agreement`).
//!
//! The legs run here at a fraction of their bench size. Their bench size
//! is chosen for a rig that runs eleven rounds of each; this file runs on
//! every `make ci`, and what it is proving is that the shapes agree, not
//! how fast they are.
// The exporter cut the cases of this file that need a crate this tree
// does not have; imports and helpers only they used are left in place.
#![allow(unused_imports, dead_code, unused_macros)]

#[path = "support/creategate.rs"]
mod creategate;

use creategate::{
    code_corpus, corpus, CodeCorpusError, Corpus, Shape, CODE_CORPUS_FIRE_SLICE,
    CODE_CORPUS_WINDOW, SHAPES,
};

/// The size every leg is checked at, and the most members it is cut into.
const CHECK_BYTES: usize = 1 << 20;
const CHECK_MEMBERS: usize = 64;

fn checked(shape: &Shape) -> Shape {
    shape.scaled(CHECK_BYTES, CHECK_MEMBERS)
}

/// On the executable corpus, level 1 writes the SAME archive as `Off`,
/// and levels 3 and 5 write a DIFFERENT, smaller one: the
/// filter really fires on the window the legs time. Without the second
/// half the `code` legs could quietly be timing an unfiltered create.
///
/// Checked on `CODE_CORPUS_FIRE_SLICE`, a MiB of the timed window, where
/// the file is on this box; said and passed where it is not.
#[test]
fn the_code_window_fires_a_filter_above_level_1_and_none_at_it() {
    for shape in SHAPES
        .iter()
        .filter(|s| s.corpus == Corpus::Code)
        .map(checked)
    {
        let data = match code_corpus(CODE_CORPUS_WINDOW) {
            Ok(bytes) => bytes[CODE_CORPUS_FIRE_SLICE].to_vec(),
            Err(CodeCorpusError::Absent(why)) => {
                println!("{}: not checked: {why}", shape.name);
                continue;
            }
            Err(CodeCorpusError::Wrong(why)) => panic!("{}: {why}", shape.name),
        };
        let detect = creategate::rarkit_archive(&shape, &data).expect("detect");
        let off = creategate::rarkit_archive(&shape.filters_off(), &data).expect("off");
        if shape.level == 1 {
            assert_eq!(detect, off, "{}: level 1 moved a byte", shape.name);
        } else {
            let (d, o) = (detect.concat().len(), off.concat().len());
            assert!(
                d < o,
                "{}: detect wrote {d} bytes against off's {o}; no filter paid",
                shape.name
            );
        }
    }
}
