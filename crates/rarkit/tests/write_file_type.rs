//! An archive the writer returns `Ok` for reads back through this
//! crate's own reader, WHATEVER FILE TYPE THE MEMBER'S ATTRIBUTES SAY.
//!
//! `MemberSpec` carries no link target, so the writer cannot write a
//! symbolic link; but in the RAR 4 family a Unix mode whose file type
//! bits say "symbolic link", on a member that is not a directory, IS a
//! symbolic link to every reader (spec F 3.3.12: host Unix, the link type
//! in the mode, the target in the content), ours included, which then
//! refuses to extract it as a file. So `Writer::add` refuses that member
//! by name before a byte is written. RAR 5 marks a link with a record of
//! its own, so there the same mode word stays a mode word on a plain
//! member (`rarkit-cli`'s `unix_modes` test extracts one). Every other
//! file type a mode can carry is written as the plain member or
//! directory it was given as, in both families, and reads back.
//!
//! Threads: the default pool. Memory: a few KiB a cell.
use rarkit::{
    extract, Disposition, ErrorKind, FilterPolicy, HostOs, MemberInfo, MemberSpec, Payload,
    RangeSource, Rar4Version, ReadOptions, Result, Sink, Unsupported, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};
use std::sync::Arc;

/// The link type in a Unix mode's file type bits.
const SYMLINK: u32 = 0o120000;

#[derive(Default)]
struct Collect {
    files: Vec<(Vec<u8>, bool, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        self.files.push((
            member.name.to_vec(),
            member.is_directory,
            out.unwrap_or_default(),
        ));
        Ok(())
    }
}

fn options(format: WriteFormat, level: u8) -> WriteOptions {
    WriteOptions {
        format,
        method: if level == 0 {
            WriteMethod::Stored
        } else {
            WriteMethod::Compressed {
                level,
                dictionary: None,
            }
        },
        // The RAR 4 family writes no filter record (SPEC-J).
        filters: FilterPolicy::Off,
        ..WriteOptions::default()
    }
}

fn spec<'a>(
    data: &'a [u8],
    attributes: u32,
    host_os: HostOs,
    is_directory: bool,
) -> MemberSpec<'a> {
    MemberSpec {
        name: if is_directory { b"d" } else { b"f.bin" },
        payload: Payload::Bytes(data),
        mtime: None,
        attributes,
        host_os,
        is_directory,
    }
}

const FORMATS: [WriteFormat; 3] = [
    WriteFormat::Rar5,
    WriteFormat::Rar4(Rar4Version::V29),
    WriteFormat::Rar4(Rar4Version::V40),
];
const HOSTS: [HostOs; 5] = [
    HostOs::MsDos,
    HostOs::Os2,
    HostOs::Windows,
    HostOs::Unix,
    HostOs::MacOs,
];

/// A plain member of the RAR 4 family whose Unix mode says symbolic
/// link is refused by name at `add`, and the writer is as it was.
#[test]
fn a_rar4_member_whose_unix_mode_says_symbolic_link_is_refused_at_add() {
    for format in FORMATS {
        if format == WriteFormat::Rar5 {
            continue;
        }
        for permissions in [0o777u32, 0o644, 0] {
            let mut writer = Writer::new(options(format, 0)).expect("options");
            let refused = writer
                .add(spec(b"target", SYMLINK | permissions, HostOs::Unix, false))
                .expect_err("a symbolic link with no target was taken");
            assert!(
                matches!(
                    refused.kind(),
                    ErrorKind::Unsupported(Unsupported::WriteFeature(what))
                        if what.contains("symbolic link")
                ),
                "{format:?}: refused as {refused}"
            );
            // The writer is as it was: a member it can write still goes
            // in, and the archive holds that member alone.
            writer
                .add(spec(b"plain", 0o100644, HostOs::Unix, false))
                .expect("a plain member after the refusal");
            let mut archive = Vec::new();
            writer.finish_into(&mut archive).expect("write");
            let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
            let mut sink = Collect::default();
            extract(sources, &ReadOptions::default(), &mut sink, &mut ()).expect("read back");
            assert_eq!(
                sink.files,
                vec![(b"f.bin".to_vec(), false, b"plain".to_vec())]
            );
        }
    }
}

/// THE RULE: for every file type a mode can carry, under every host, in
/// every format, stored and packed, a member the writer takes reads back
/// as what it was given as. The only cells it refuses are the RAR 4
/// family's plain member under a Unix host whose mode says symbolic link.
#[test]
fn every_member_the_writer_takes_reads_back_whatever_its_mode_says() {
    for format in FORMATS {
        for host_os in HOSTS {
            for kind in 0u32..16 {
                for is_directory in [false, true] {
                    for level in [0u8, 3] {
                        let attributes = (kind << 12) | 0o644;
                        let what = format!(
                            "{format:?} {host_os:?} mode {attributes:#o} directory {is_directory} \
                             level {level}"
                        );
                        let mut writer = Writer::new(options(format, level)).expect("options");
                        let added = writer.add(spec(b"content", attributes, host_os, is_directory));
                        let link = format != WriteFormat::Rar5
                            && !is_directory
                            && host_os == HostOs::Unix
                            && kind << 12 == SYMLINK;
                        assert_eq!(added.is_err(), link, "{what}: {:?}", added.err());
                        if link {
                            continue;
                        }
                        let mut archive = Vec::new();
                        writer.finish_into(&mut archive).expect("write");
                        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive)];
                        let mut sink = Collect::default();
                        extract(sources, &ReadOptions::default(), &mut sink, &mut ())
                            .unwrap_or_else(|e| {
                                panic!("{what}: written Ok and not read back: {e}")
                            });
                        let wanted = if is_directory {
                            (b"d".to_vec(), true, Vec::new())
                        } else {
                            (b"f.bin".to_vec(), false, b"content".to_vec())
                        };
                        assert_eq!(sink.files, vec![wanted], "{what}");
                    }
                }
            }
        }
    }
}
