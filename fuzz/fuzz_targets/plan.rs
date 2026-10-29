//! A member list and a set of options decoded from fuzz bytes, shared by
//! the writer targets of SPEC-G section 6.4.

use std::sync::Arc;

use rarkit::{
    ChecksumKind, Disposition, MemberInfo, MemberOutcome, MemberSortKey, MemberSpec, Payload,
    RangeSource, Rar4Version, ReadOptions, Sink, Timestamp, WriteFormat, WriteOptions, Writer,
};

/// One member the fuzzer asked for.
pub struct Member {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub mtime: Option<Timestamp>,
    pub attributes: u32,
    pub is_directory: bool,
}

/// A whole run: the options and the members.
pub struct Plan {
    pub format: WriteFormat,
    pub checksum: ChecksumKind,
    pub volume_size: Option<u64>,
    /// The budget counted as the whole volume FILE instead, which is
    /// mutually exclusive with `volume_size`.
    pub volume_file_size: Option<u64>,
    pub comment: Option<Vec<u8>>,
    pub lock: bool,
    /// Write a single archive through `finish_seek` rather than
    /// `finish_into`: the same archive by the one-pass route, which
    /// patches a placeholder where it lies instead of holding the bytes
    /// after it. Nothing else about the plan changes, so the two routes
    /// are compared against each other on every input that takes one.
    pub seekable: bool,
    /// One encoder run across every member (spec G 3.9).
    pub solid: bool,
    /// 0 stored, 1 to 5 the compression levels of the same number.
    pub level: u8,
    /// Name a SMALL dictionary rather than taking the default of 2 MiB.
    ///
    /// It is here for what it does to the WINDOW, which is the
    /// dictionary clamped up to one parse block: a small dictionary puts
    /// the window at 256 KiB, and a member larger than one window is
    /// what takes the writer's streamed walk (spec G 3.5 and 3.7.3).
    /// With the default dictionary that member would have to be over
    /// 2 MiB, which no fuzz input is going to invent.
    pub small_dictionary: bool,
    pub members: Vec<Member>,
}

/// Where the writer sorts `member` in a solid archive of packed members.
fn written_key(member: &Member) -> MemberSortKey<'_> {
    let size = if member.is_directory {
        0
    } else {
        member.data.len() as u64
    };
    MemberSortKey::of(&member.name, size, member.is_directory)
}

/// Bytes off the front of the fuzz input.
struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(head)
    }
}

impl Plan {
    /// Decodes a plan, or nothing when the input is too short to hold one.
    pub fn decode(data: &[u8]) -> Option<Plan> {
        let mut bytes = Bytes(data);
        let shape = bytes.byte()?;
        // A second byte, because the first has no bit left: every one of
        // its eight already chooses something.
        let more = bytes.byte()?;
        let format = match shape & 0x03 {
            0 => WriteFormat::Rar5,
            1 => WriteFormat::Rar4(Rar4Version::V29),
            2 => WriteFormat::Rar4(Rar4Version::V30),
            _ => WriteFormat::Rar4(Rar4Version::V40),
        };
        let checksum = if shape & 0x04 != 0 && matches!(format, WriteFormat::Rar5) {
            ChecksumKind::Blake2sp
        } else {
            ChecksumKind::Crc32
        };
        let volume_size = if shape & 0x08 != 0 {
            Some(u64::from(bytes.byte()?) * 16 + 1)
        } else {
            None
        };
        let comment = if shape & 0x10 != 0 {
            let len = usize::from(bytes.byte()?);
            Some(bytes.take(len)?.to_vec())
        } else {
            None
        };
        let lock = shape & 0x20 != 0;
        let seekable = shape & 0x80 != 0;
        let solid = more & 0x01 != 0;
        // The same budget read as the whole FILE rather than the payload.
        // The two are mutually exclusive and `Writer::new` refuses both,
        // so the bit MOVES the budget rather than adding one.
        let (volume_size, volume_file_size) = if more & 0x02 != 0 {
            (None, volume_size)
        } else {
            (volume_size, None)
        };
        // A compressed level for two shapes in eight, so the target
        // spends most of its time on the framing and some of it on the
        // encoder seam of spec G 1.2.
        let level = if shape & 0x40 != 0 {
            (shape >> 5) % 6
        } else {
            0
        };

        let small_dictionary = more & 0x04 != 0;
        // A member large enough to be STREAMED, out of a small input:
        // the first member's own bytes, repeated until they are over one
        // window. Repetition compresses away to nothing, which is the
        // point - the walk under test is the writer's and not the
        // encoder's, and a 400 KiB member that costs 400 KiB of corpus
        // would be a target nobody runs.
        let bulk = more & 0x08 != 0;

        let count = usize::from(bytes.byte()?) % 8;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let flags = bytes.byte()?;
            let name_len = usize::from(bytes.byte()?) % 40 + 1;
            let name = bytes.take(name_len)?.to_vec();
            let data_len = usize::from(bytes.byte()?) * 17;
            let data = bytes.take(data_len.min(bytes.0.len()))?.to_vec();
            let mtime = (flags & 0x01 != 0).then(|| Timestamp {
                unix_seconds: i64::from(u32::from_le_bytes(
                    bytes.take(4).unwrap_or(&[0, 0, 0, 0]).try_into().unwrap(),
                )),
                nanos: if flags & 0x02 != 0 { 123_456_789 } else { 0 },
            });
            members.push(Member {
                name,
                data,
                mtime,
                attributes: u32::from(flags) << 8,
                is_directory: flags & 0x04 != 0,
            });
        }
        if bulk {
            if let Some(first) = members
                .iter_mut()
                .find(|m| !m.is_directory && !m.data.is_empty())
            {
                let times = (400 * 1024) / first.data.len() + 1;
                first.data = first.data.repeat(times);
            }
        }
        Some(Plan {
            format,
            checksum,
            small_dictionary,
            volume_size,
            volume_file_size,
            comment,
            lock,
            seekable,
            solid,
            level,
            members,
        })
    }

    /// The options this plan asks for.
    pub fn options(&self) -> WriteOptions {
        WriteOptions {
            format: self.format,
            method: if self.level == 0 {
                rarkit::WriteMethod::Stored
            } else {
                rarkit::WriteMethod::Compressed {
                    level: self.level,
                    dictionary: self.small_dictionary.then_some(128 << 10),
                }
            },
            // SPEC-J: the RAR 4 family refuses a filter request
            // rather than resolving it to `Off`.
            filters: rarkit::FilterPolicy::Off,
            solid: self.solid,
            checksum: self.checksum,
            volume_size: self.volume_size,
            volume_file_size: self.volume_file_size,
            comment: self.comment.clone(),
            lock: self.lock,
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        }
    }

    /// Writes the plan and reads it back. Either the writer refuses, or
    /// what comes back is the member list that went in, in the order the
    /// writer gives it (spec G 3.9.1, "What a read-back test must
    /// therefore hold").
    pub fn run(&self) {
        let Some((volumes, mut wanted)) = self.archive() else {
            return;
        };
        self.in_written_order(&mut wanted);
        if volumes.is_empty() {
            return;
        }

        let sources: Vec<Arc<dyn RangeSource>> = volumes
            .into_iter()
            .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
            .collect();
        // A compressed archive goes through the SAME round trip as a
        // stored one. It could not when this target was written - no LZ
        // decoder was wired to the extract path - so it asserted only
        // that the archive opened and listed. Spec H3's encoders and
        // spec F's wiring are both in now, and what this target checks
        // for every level is that the bytes come back.
        let mut sink = Collect::default();
        let mut progress = Quiet;
        let read = rarkit::extract(sources, &ReadOptions::default(), &mut sink, &mut progress);
        assert!(
            read.is_ok(),
            "an archive this writer returned Ok for did not read back: {:?}",
            read.err().map(|e| e.to_string())
        );
        assert_eq!(
            sink.members.len(),
            wanted.len(),
            "member count after a round trip"
        );
        for (want, got) in wanted.iter().zip(&sink.members) {
            assert_eq!(want.name, got.0, "a member's name changed");
            if !want.is_directory {
                assert_eq!(want.data, got.1, "a member's bytes changed");
            }
        }
    }

    /// Put `members`, given in the order they were added, in the order
    /// the archive holds them. A solid archive of packed members is
    /// written in the order of [`MemberSortKey`], files before directory
    /// entries, which is the genuine writer's order for one (spec G 3.9.1,
    /// RULE 94); the plan never asks for `MemberOrder::AsAdded`. Every
    /// other plan, not solid or stored, is written in the order added. The
    /// sort is stable, as the writer's is, and a directory's size is 0
    /// whatever bytes the plan gave it.
    pub fn in_written_order(&self, members: &mut [&Member]) {
        if self.solid && self.level != 0 {
            members.sort_by(|left, right| written_key(left).cmp(&written_key(right)));
        }
    }

    /// Writes the plan and answers its volumes and the members that went
    /// in, in the order they were added, or nothing at all when the writer
    /// refused the plan.
    ///
    /// It is separate from [`Plan::run`] so that a target can write the
    /// SAME plan twice and compare the bytes - which is how the
    /// pipelining depth is driven in `write_volumes`.
    pub fn archive(&self) -> Option<(Vec<Vec<u8>>, Vec<&Member>)> {
        let Ok(mut writer) = Writer::new(self.options()) else {
            return None;
        };
        let mut wanted = Vec::new();
        for member in &self.members {
            let added = writer.add(MemberSpec {
                name: &member.name,
                payload: Payload::Bytes(&member.data),
                mtime: member.mtime,
                attributes: member.attributes,
                host_os: rarkit::HostOs::Unix,
                is_directory: member.is_directory,
            });
            if added.is_err() {
                return None;
            }
            wanted.push(member);
        }

        let volumes = if self.volume_size.is_some() || self.volume_file_size.is_some() {
            let mut out: Vec<Vec<u8>> = Vec::new();
            if writer.finish_volumes(&mut out).is_err() {
                return None;
            }
            // The promise the FILE budget makes, which nothing else in
            // this target would notice being broken: no volume is ever
            // longer than the cap.
            if let Some(cap) = self.volume_file_size {
                for (index, volume) in out.iter().enumerate() {
                    assert!(
                        volume.len() as u64 <= cap,
                        "volume {index} is {} bytes against a {cap} byte file cap",
                        volume.len()
                    );
                }
            }
            out
        } else if self.seekable {
            let mut seek = std::io::Cursor::new(Vec::new());
            let Ok(report) = writer.finish_seek(&mut seek) else {
                return None;
            };
            assert_eq!(
                report.held_volume_bytes, 0,
                "finish_seek held bytes it can patch in place"
            );
            vec![seek.into_inner()]
        } else {
            let mut out = Vec::new();
            if writer.finish_into(&mut out).is_err() {
                return None;
            }
            vec![out]
        };
        Some((volumes, wanted))
    }
}

#[derive(Default)]
pub struct Collect {
    pub members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.split_before {
            return Ok(Disposition::Write(Vec::new()));
        }
        self.members.push((member.name.to_vec(), Vec::new()));
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if member.is_directory {
            return Ok(());
        }
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1.extend_from_slice(&bytes);
        }
        Ok(())
    }
}

pub struct Quiet;

impl rarkit::Progress for Quiet {}
