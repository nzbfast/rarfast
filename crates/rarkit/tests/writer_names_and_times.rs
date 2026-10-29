//! What the Writer admits of a member's name and time, and what it
//! writes for them (bug sweep of 4 Oct 2026, L-32, L-34 and L-35).
//!
//! Width and memory: every member here is STORED and a few bytes long,
//! under the default memory policy; nothing follows the machine.

use std::sync::Arc;

use rarkit::{
    edit, Archive, HostOs, MemberSpec, Payload, RangeSource, Rar4Version, ReadOptions, Timestamp,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

const RAR4: WriteFormat = WriteFormat::Rar4(Rar4Version::V40);

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

fn spec<'a>(name: &'a [u8], mtime: Option<Timestamp>, host_os: HostOs) -> MemberSpec<'a> {
    MemberSpec {
        name,
        payload: Payload::Bytes(b"payload"),
        mtime,
        attributes: 0,
        host_os,
        is_directory: false,
    }
}

fn open(archive: &[u8]) -> Archive {
    let src: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    Archive::open(src, &ReadOptions::default()).expect("open")
}

fn one(format: WriteFormat, name: &[u8]) -> Vec<u8> {
    let mut w = writer(format);
    w.add(spec(name, None, HostOs::Unix)).expect("add");
    let mut out = Vec::new();
    w.finish_into(&mut out).expect("finish");
    out
}

/// L-32: a name that opens with a drive, or carries a parent step behind
/// either separator, is refused by `add` and by `rename` (spec G 3.4.4).
///
/// A drive is a letter, a colon and a separator. A colon with no
/// separator after it is an ordinary byte of a Unix name, and reference
/// `rar` 7.x on a Unix host archives files named `a:b` and `C:evil.dll`
/// as they are (measured 4 Oct 2026), so those are taken.
#[test]
fn a_name_with_a_drive_letter_or_a_backslash_parent_step_is_refused() {
    let refused: [&[u8]; 5] = [
        b"C:/evil.dll",
        b"z:/",
        b"a\\..\\..\\x",
        b"..\\x",
        b"a/b\\..",
    ];
    for format in [WriteFormat::Rar5, RAR4] {
        for name in refused {
            let what = format!("{format:?} {:?}", String::from_utf8_lossy(name));
            assert!(
                writer(format).add(spec(name, None, HostOs::Unix)).is_err(),
                "{what}: add took it"
            );
            let source = one(format, b"a");
            let mut out = Vec::new();
            assert!(
                edit::rename(&open(&source), b"a", name, &mut out).is_err(),
                "{what}: rename took it"
            );
        }
    }
    // Names that only look like those are still taken.
    let taken: [&[u8]; 8] = [
        b"a:b",
        b"C:evil.dll",
        b"Z:",
        b"dir/c:/x",
        b"dir/c:x",
        b"1:/x",
        b"a..b/c",
        b"..a/b..",
    ];
    for name in taken {
        writer(WriteFormat::Rar5)
            .add(spec(name, None, HostOs::Unix))
            .unwrap_or_else(|e| panic!("{:?}: {e}", String::from_utf8_lossy(name)));
    }
    // A backslash that steps nowhere stays a legal RAR 5 name.
    writer(WriteFormat::Rar5)
        .add(spec(b"a\\b", None, HostOs::Unix))
        .expect("a RAR 5 name holding a backslash");
    // And a drive behind a backslash is one, where the family takes a
    // backslash at all.
    assert!(writer(WriteFormat::Rar5)
        .add(spec(b"C:\\x", None, HostOs::Unix))
        .is_err());
}

/// A RAR 4 name of `len` bytes, in components of 200.
fn long_name(len: usize) -> Vec<u8> {
    let mut name = Vec::with_capacity(len);
    while name.len() < len {
        if !name.is_empty() && name.len() % 200 == 0 {
            name.push(b'/');
        } else {
            name.push(b'n');
        }
    }
    name
}

/// L-34: a RAR 4 header's length field is 16 bits. A name that would
/// carry the header past 65,535 bytes is refused; it used to be written
/// with the length truncated, and the archive did not open.
#[test]
fn a_rar4_name_that_would_overflow_the_header_length_is_refused() {
    for len in [65_400usize, 65_480, 65_500, 65_520, 65_535] {
        let name = long_name(len);
        let mut w = writer(RAR4);
        match w.add(spec(&name, None, HostOs::Unix)) {
            Err(_) => {}
            Ok(_) => {
                let mut out = Vec::new();
                w.finish_into(&mut out)
                    .unwrap_or_else(|e| panic!("a name of {len}: {e}"));
                let src: Arc<dyn RangeSource> = Arc::new(out);
                let archive = Archive::open(src, &ReadOptions::default()).unwrap_or_else(|e| {
                    panic!("a name of {len} was written and does not open: {e}")
                });
                let names: Vec<Vec<u8>> = archive.members().map(|m| m.name.to_vec()).collect();
                assert_eq!(names, vec![name.clone()], "a name of {len}");
            }
        }
        // The same name through a rename.
        let source = one(RAR4, b"a");
        let mut out = Vec::new();
        if edit::rename(&open(&source), b"a", &name, &mut out).is_ok() {
            let src: Arc<dyn RangeSource> = Arc::new(out);
            let archive = Archive::open(src, &ReadOptions::default()).unwrap_or_else(|e| {
                panic!("a rename to a name of {len} was written and does not open: {e}")
            });
            let names: Vec<Vec<u8>> = archive.members().map(|m| m.name.to_vec()).collect();
            assert_eq!(names, vec![name.clone()], "a rename to a name of {len}");
        }
    }
    // The longest name that still fits is taken, and is far above any
    // real path.
    writer(RAR4)
        .add(spec(&long_name(65_400), None, HostOs::Unix))
        .expect("a name of 65,400 bytes");
}

/// L-35, RAR 5: a time outside the 32 bit Unix field is written exactly,
/// in the time record's 64 bit form, on either host. It used to be
/// clamped to 1970 or 2106 with nothing to say so.
#[test]
fn a_rar5_time_outside_the_unix_field_is_written_exactly() {
    let times = [
        // 1965
        Timestamp {
            unix_seconds: -86_400 * 365 * 5,
            nanos: 0,
        },
        // 1965, with a fraction
        Timestamp {
            unix_seconds: -86_400 * 365 * 5,
            nanos: 500_000_000,
        },
        // 2200
        Timestamp {
            unix_seconds: 86_400 * 365 * 230,
            nanos: 0,
        },
        // In range, as a control.
        Timestamp {
            unix_seconds: 1_700_000_000,
            nanos: 0,
        },
    ];
    for host in [HostOs::Unix, HostOs::Windows] {
        for time in times {
            let what = format!("{host:?} {}", time.unix_seconds);
            let mut w = Writer::new(WriteOptions {
                format: WriteFormat::Rar5,
                method: WriteMethod::Stored,
                filters: rarkit::FilterPolicy::Off,
                host_os: host,
                ..WriteOptions::default()
            })
            .expect("options");
            w.add(spec(b"old.txt", Some(time), host)).expect("add");
            let mut out = Vec::new();
            w.finish_into(&mut out).expect("finish");
            let archive = open(&out);
            let read = archive.members().next().expect("the member").mtime;
            assert_eq!(read, Some(time), "{what}: the time read back");
        }
    }
}
