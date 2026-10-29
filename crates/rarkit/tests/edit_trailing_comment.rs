//! An edit that does not touch the comment leaves the archive comment as
//! it was: a RAR 5 `CMT` block AFTER the members is not the archive
//! comment (spec F 3.2.9 S3), and a rewrite must not move it to where the
//! comment lives and make it one.
//!
//! Threads: one. Memory: one small vector archive.
use rarkit::{Archive, RangeSource, ReadOptions};
use std::sync::Arc;

/// The reader's evidence vector with one `CMT` block after the members.
fn trailing_cmt() -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-F/evidence-06oct/rar5-container/service-cmt-last/x.rar",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn open(bytes: Vec<u8>) -> Archive {
    let src: Arc<dyn RangeSource> = Arc::new(bytes);
    Archive::open(src, &ReadOptions::default()).expect("the archive opens")
}

/// Locking the archive keeps it with no comment, and keeps its service
/// blocks, the trailing `CMT` among them.
#[test]
fn an_unrelated_edit_does_not_make_a_trailing_cmt_block_the_comment() {
    let src = open(trailing_cmt());
    assert_eq!(src.comment(), None, "the vector has no archive comment");
    let services = src.services().len();
    let members: Vec<Vec<u8>> = src.members().map(|m| m.name.to_vec()).collect();

    let mut out = Vec::new();
    rarkit::edit::lock(&src, &mut out).expect("lock");
    let locked = open(out);

    assert_eq!(
        locked.comment(),
        None,
        "locking promoted the trailing CMT block to the archive comment"
    );
    assert_eq!(
        locked.services().len(),
        services,
        "a service block was lost"
    );
    let after: Vec<Vec<u8>> = locked.members().map(|m| m.name.to_vec()).collect();
    assert_eq!(after, members);
}
