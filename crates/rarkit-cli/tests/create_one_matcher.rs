//! A create reads a mask by the read commands' matcher, and the answers
//! are rar 7.23's.
//!
//! Until 9 Oct 2026 a create screened what it walked with a matcher of
//! its own, written beside the one the read commands use. The two agreed
//! on every row of `create-selection/rar723-exclude-include.txt` and
//! differed elsewhere, and where they differed the reference sides with
//! the read commands' rule. The table here is those rows, measured on 9
//! Oct 2026 (an Apple silicon Mac), with the older create's answer:
//!
//! - **a dot that ends a mask** matches the end of a name: `-xs/a.txt.`
//!   leaves `s/a.txt` out and `-n*.` takes `s/dx`, the one file with no
//!   dot in its name. The older matcher took nothing with either. A name
//!   typed as an argument is still that name alone unless `-r` searches
//!   for it: `rar a arc s/a.txt.` finds nothing and exits 10, `rar a -r
//!   arc a.txt.` stores every `a.txt`;
//! - **a wildcard directory mask that ends in a separator** takes what
//!   lies below the directories it names: `-ns/*.txt/` stores
//!   `s/dd.txt/k.bin`, which the older matcher left out;
//! - **nothing but `/` or `./`** takes every file and no directory;
//! - **under `-ep`** an exclude mask that is a bare name takes that name
//!   at any depth, an include mask does not (`-ep -nb.txt` stores
//!   nothing, exit 10, where rarfast stored `b.txt`), and a name with a
//!   separator after it takes nothing;
//! - **a mask that begins `../`** is compared with a path that begins so.
//!
//! Three rows measured the same day are NOT in the table, because the
//! shared matcher does not give them: rar a -r -ns/d*/ s, the same with
//! a.txt added, and rar a -r -ns/?/e/ s. The reference stores every FILE
//! below the directories the mask names and none of the directories
//! below them (`s/d/e`, `s/d/e/e`); rarfast stores those two entries as
//! well. It is the corner the read commands' matcher names as unmatched
//! in its own header, and the older create matcher stored no file at all
//! on these rows.
//!
//! Each run is `-mt2` over nine files of at most 3,000 bytes: a pool two
//! threads wide and a few KiB of memory.

#![cfg(unix)]

#[path = "support/selection_rows.rs"]
mod selection_rows;

#[test]
fn the_rows_where_the_two_matchers_differed_are_the_references() {
    selection_rows::agree_with_the_reference(
        "one-matcher",
        include_str!("create-selection/rar723-one-matcher.txt"),
    );
}
