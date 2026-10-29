//! The names spec G 3.4.4 forbids a writer to store, refused by `add`
//! and by `rename` alike (item B5 of the 0.9.0 hold).
//!
//! 3.4.4: rarkit writes a name only as UTF-8, `/` separated, with no
//! empty, `.` or `..` component, no leading `/`, no drive letter and no
//! NUL; any other name is refused, never rewritten. Section 2 gives the
//! kind, `Corrupt(Corruption::MemberName)`.
//!
//! Tested here: the UTF-8 part, and every name that could escape a
//! destination (on 471661fda RAR 5 still took one rooted at a
//! backslash). The empty and `.` components stay taken: reference `rar`
//! stores and renames to such names, the CLI tests pin that, and 3.4.4
//! and SPEC-CLI disagree on them; the disagreement is open.
//!
//! Width and memory: every member here is STORED and a few bytes long,
//! under the default memory policy; nothing follows the machine.

use std::sync::Arc;

use rarkit::{
    edit, Archive, Corruption, ErrorKind, HostOs, MemberSpec, Payload, RangeSource, Rar4Version,
    ReadOptions, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const FORMATS: [WriteFormat; 2] = [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)];

fn writer<'a>(format: WriteFormat) -> Writer<'a> {
    Writer::new(WriteOptions {
        format,
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options")
}

fn spec(name: &[u8]) -> MemberSpec<'_> {
    MemberSpec {
        name,
        payload: Payload::Bytes(b"payload"),
        mtime: None,
        attributes: 0,
        host_os: HostOs::Unix,
        is_directory: false,
    }
}

fn open(archive: &[u8]) -> Archive {
    let src: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    Archive::open(src, &ReadOptions::default()).expect("open")
}

fn one(format: WriteFormat, name: &[u8]) -> Vec<u8> {
    let mut w = writer(format);
    w.add(spec(name)).expect("add");
    let mut out = Vec::new();
    w.finish_into(&mut out).expect("finish");
    out
}

fn is_member_name(e: &rarkit::Error) -> bool {
    matches!(e.kind(), ErrorKind::Corrupt(Corruption::MemberName))
}

/// A name that is not UTF-8 is outside the one form 3.4.4 allows, in
/// both families: a stray byte, a Latin-1 byte and an encoded surrogate.
#[test]
fn a_name_outside_the_one_written_form_is_refused_by_add_and_rename() {
    let refused: [&[u8]; 3] = [b"a\xffb", b"caf\xe9", b"d\xed\xa0\x80/f"];
    let mut wrong = Vec::new();
    for format in FORMATS {
        for name in refused {
            let what = format!("{format:?} {:?}", String::from_utf8_lossy(name));
            match writer(format).add(spec(name)) {
                Err(e) if is_member_name(&e) => {}
                Err(e) => wrong.push(format!("{what}: add refused as {e}")),
                Ok(()) => wrong.push(format!("{what}: add took it")),
            }
            let source = one(format, b"a");
            let mut out = Vec::new();
            match edit::rename(&open(&source), b"a", name, &mut out) {
                Err(e) if is_member_name(&e) => {}
                Err(e) => wrong.push(format!("{what}: rename refused as {e}")),
                Ok(_) => wrong.push(format!("{what}: rename took it")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Every name 3.4.4 forbids that could walk out of a destination stays
/// refused, in both families, through add and rename: a `..` component
/// behind either separator, a name rooted at `/` or at a backslash, and
/// a drive followed by a separator.
#[test]
fn a_name_that_could_escape_a_destination_is_refused_by_add_and_rename() {
    let refused: [&[u8]; 14] = [
        b"..",
        b"../x",
        b"a/..",
        b"a/../b",
        b"..\\x",
        b"a\\..\\b",
        b"/",
        b"/x",
        b"\\x",
        b"\\\\server\\share\\x",
        b"C:/x",
        b"C:\\x",
        b"c:/",
        b"z:\\",
    ];
    let mut wrong = Vec::new();
    for format in FORMATS {
        for name in refused {
            let what = format!("{format:?} {:?}", String::from_utf8_lossy(name));
            match writer(format).add(spec(name)) {
                Err(e) if is_member_name(&e) => {}
                Err(e) => wrong.push(format!("{what}: add refused as {e}")),
                Ok(()) => wrong.push(format!("{what}: add took it")),
            }
            let source = one(format, b"a");
            let mut out = Vec::new();
            match edit::rename(&open(&source), b"a", name, &mut out) {
                Err(e) if is_member_name(&e) => {}
                Err(e) => wrong.push(format!("{what}: rename refused as {e}")),
                Ok(_) => wrong.push(format!("{what}: rename took it")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Names in the allowed form beside those are still taken: a dot inside
/// a component, a component made of dots other than `.` and `..`, and
/// UTF-8 outside ASCII.
#[test]
fn names_in_the_written_form_are_still_taken() {
    let taken: [&[u8]; 6] = [b".a", b"a.", b"a/.b/c", b"...", b"a/.../b", b"caf\xc3\xa9"];
    for format in FORMATS {
        for name in taken {
            let what = format!("{format:?} {:?}", String::from_utf8_lossy(name));
            writer(format)
                .add(spec(name))
                .unwrap_or_else(|e| panic!("{what}: add refused it: {e}"));
            let source = one(format, b"a");
            let mut out = Vec::new();
            edit::rename(&open(&source), b"a", name, &mut out)
                .unwrap_or_else(|e| panic!("{what}: rename refused it: {e}"));
        }
    }
}
