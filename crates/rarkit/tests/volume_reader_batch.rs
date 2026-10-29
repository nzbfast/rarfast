//! A VOLUME SET whose members arrive as READERS is encoded in batches,
//! and that is a width and never a byte (spec G 3.9, 3.10 and 3.13;
//! 1 Oct 2026).
//!
//! **What changed.** The command line hands the writer every member as a
//! `Payload::Reader`. Until this change a reader in a volume set was left
//! to the member-at-a-time walk, in a solid run and in a non-solid set
//! alike, for two reasons: a batch whose tail lands past a volume
//! boundary is discarded and encoded again, and a reader is pulled once;
//! and a caller that reported volume boundaries against the member it
//! last pulled would see one land on the wrong member. So 5,000 small
//! members in volumes were 5,000 waves of a block or two, at three to six
//! times the wall of the same set in one archive. Now a solid batch keeps
//! the bytes it pulled until the batch after is staged and stages a
//! discarded tail again from them, the worker team takes a non-solid
//! set's readers, and `Progress::member_started` says which member the
//! writer has taken up.
//!
//! **What is held to here.** `tests/volume_reader_pins.rs` holds every
//! row to the digest the member-at-a-time writer gave. This file says the
//! same thing from inside: readers give the set that bytes in memory give
//! (which a volume set batched before this change), at every pipelining
//! depth and at one thread; every member reads back; reference `unrar`
//! takes every set with nothing on stderr; the rows really were batched,
//! and a discarded tail really was staged again; `member_started` follows
//! the writer and not the pulls; a reader that fails ends the write at
//! its member; and what the kept bytes cost is stated.

#[path = "support/volumereaders.rs"]
mod volumereaders;

use std::io::Read;
use std::process::Command;
use std::sync::{Arc, Mutex};

use rarkit::internals::writers;
use rarkit::{
    extract, Disposition, ErrorKind, MemberInfo, Password, Progress, RangeSource, ReadOptions,
    Result, Sink, VolumeNaming,
};
use volumereaders::{
    members, options_of, rows, set_digest, sets, write, write_from, Hand, Member, Row, DICTIONARY,
    PASSWORD, SMALL_CAP,
};

/// Collects each member's name and bytes, in archive order.
#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1 = bytes;
        }
        Ok(())
    }
}

/// Every member's bytes through rarkit's own reader, directories left out.
fn read_back(volumes: &[Vec<u8>], row: &Row) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|volume| Arc::new(volume.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default()
        .with_password(row.password.then(|| Password::new(PASSWORD.as_bytes())));
    let mut sink = Collect::default();
    extract(sources, &options, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{}: rarkit's own reader: {e}", row.label));
    sink.members.sort();
    sink.members
}

/// What the set holds, as [`read_back`] gives it: by name, since a solid
/// archive lists its members in spec G 3.9.1's order.
fn wanted(members: &[Member]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut wanted: Vec<(Vec<u8>, Vec<u8>)> = members
        .iter()
        .map(|member| (member.name.clone(), member.data.clone()))
        .collect();
    wanted.sort();
    wanted
}

/// `row`'s options with the members written in `add` order, so that a
/// test can name a member by its place in the set.
fn as_added(row: &Row) -> rarkit::WriteOptions {
    rarkit::WriteOptions {
        order: rarkit::MemberOrder::AsAdded,
        ..row.options()
    }
}

/// The rows a ceiling the caller named does not narrow.
fn is_default_policy(row: &Row) -> bool {
    row.ceiling.is_none()
}

#[test]
fn readers_give_the_set_that_bytes_in_memory_give() {
    let mut staged_again = 0;
    for (members, rows, in_add_order) in sets() {
        let wanted = wanted(&members);
        for row in rows {
            let options = || options_of(&row, in_add_order);
            writers::reset_readers_batched();
            writers::reset_team_prepared();
            let (readers, _) = write(options(), &members, Hand::Reader, &mut ());
            let (batched, twice) = writers::readers_batched();
            let prepared = writers::team_prepared();
            let (bytes, _) = write(options(), &members, Hand::Bytes, &mut ());
            assert_eq!(
                readers.len(),
                bytes.len(),
                "{}: the volume count",
                row.label
            );
            assert_eq!(
                set_digest(&readers),
                set_digest(&bytes),
                "{}: readers and bytes in memory wrote different sets",
                row.label
            );
            // Not `assert_eq!`: a failure would print both sets whole.
            assert!(
                read_back(&readers, &row) == wanted,
                "{}: the set did not read back",
                row.label
            );
            // The rows compare what they say they compare: a solid run's
            // readers went through a batch, a non-solid set's through the
            // worker team.
            if row.solid && row.ceiling.is_some_and(|ceiling| ceiling < 512 << 20) {
                // A ceiling the caller named under the floor keeps the
                // member-at-a-time walk, and its peak.
                assert_eq!(
                    batched, 0,
                    "{}: readers were batched under a ceiling below the floor",
                    row.label
                );
            } else if row.solid {
                assert!(
                    batched > 0,
                    "{}: no reader of a solid volume set was batched",
                    row.label
                );
                staged_again += twice;
                // The set built to straddle boundaries does, in every row.
                assert!(
                    !in_add_order || twice > 0,
                    "{}: no batch of readers was discarded at a boundary and \
                     staged again, which is what this set is built to meet",
                    row.label
                );
            } else if is_default_policy(&row) {
                assert!(
                    prepared > 0,
                    "{}: the worker team took no reader of a non-solid volume set",
                    row.label
                );
            }
        }
    }
    assert!(staged_again > 0);
}

#[test]
fn the_depth_and_the_width_move_no_byte() {
    for (members, rows, in_add_order) in sets() {
        for row in rows
            .into_iter()
            .filter(|row| row.level == 3 || (row.solid && row.level == 5))
        {
            let options = || options_of(&row, in_add_order);
            let (default, _) = write(options(), &members, Hand::Reader, &mut ());
            let default = set_digest(&default);
            if row.solid {
                // Depth 1 stages one member a batch: the member-at-a-time
                // walk.
                for depth in [1, 2, 5] {
                    let (at, _) = writers::with_batch_depth(depth, || {
                        write(options(), &members, Hand::Reader, &mut ())
                    });
                    assert_eq!(
                        set_digest(&at),
                        default,
                        "{}: depth {depth} wrote a different set",
                        row.label
                    );
                }
            }
            let mut one = options();
            one.workers = Some(1);
            let (one, _) = write(one, &members, Hand::Reader, &mut ());
            assert_eq!(
                set_digest(&one),
                default,
                "{}: one thread wrote a different set",
                row.label
            );
        }
    }
}

/// What a write reported, in the order it reported it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    /// A member's reader was read for the first time.
    Read(usize),
    /// `Progress::member_started`.
    Started(usize),
    /// `Progress::volume_done`.
    Volume(u32),
}

type Log = Arc<Mutex<Vec<Event>>>;

struct Recorder(Log);

impl Progress for Recorder {
    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.0.lock().unwrap().push(Event::Volume(volume));
        Ok(())
    }

    fn member_started(&mut self, index: usize) -> Result<()> {
        self.0.lock().unwrap().push(Event::Started(index));
        Ok(())
    }
}

/// A member's bytes, saying when they are first read.
struct Logged<'a> {
    index: usize,
    bytes: &'a [u8],
    read: bool,
    log: Log,
}

impl Read for Logged<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if !self.read && !buffer.is_empty() {
            self.read = true;
            self.log.lock().unwrap().push(Event::Read(self.index));
        }
        let count = buffer.len().min(self.bytes.len());
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

/// One write of `row` through logging readers: the set and its events.
fn logged(row: &Row, members: &[Member], hand: Hand) -> (String, Vec<Event>) {
    let log: Log = Arc::default();
    let mut readers: Vec<Logged<'_>> = members
        .iter()
        .enumerate()
        .map(|(index, member)| Logged {
            index,
            bytes: &member.data,
            read: false,
            log: Arc::clone(&log),
        })
        .collect();
    let (volumes, _) = write_from(
        as_added(row),
        members,
        &mut readers,
        hand,
        &mut Recorder(Arc::clone(&log)),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", row.label));
    let events = log.lock().unwrap().clone();
    (set_digest(&volumes), events)
}

/// The events a caller's per-member report is built from: which member
/// the writer is on, and where the volumes close.
fn writer_side(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .copied()
        .filter(|event| !matches!(event, Event::Read(_)))
        .collect()
}

#[test]
fn member_started_follows_the_writer_and_not_the_pulls() {
    let members = members();
    let with_payload: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, member)| !member.directory && !member.data.is_empty())
        .map(|(index, _)| index)
        .collect();
    let mut pulled_ahead = 0;
    for row in rows()
        .into_iter()
        .filter(|row| row.level == 3 && is_default_policy(row))
    {
        let (set, events) = logged(&row, &members, Hand::Reader);
        // Once for each member with a payload, in the order written, and
        // never for a directory or an empty member.
        let started: Vec<usize> = events
            .iter()
            .filter_map(|event| match event {
                Event::Started(index) => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(started, with_payload, "{}: the members started", row.label);
        // Every reader is read once, in the order written.
        let read: Vec<usize> = events
            .iter()
            .filter_map(|event| match event {
                Event::Read(index) => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(read, with_payload, "{}: the readers read", row.label);
        // A batch reads a member before the writer has reached the one
        // before it: the reason a caller cannot read the member being
        // written off its reader's first read.
        for (at, event) in events.iter().enumerate() {
            if let Event::Read(index) = event {
                let before = with_payload.iter().position(|member| member == index);
                let earlier = before.and_then(|place| place.checked_sub(1));
                if let Some(earlier) = earlier.map(|place| with_payload[place]) {
                    if !events[..at].contains(&Event::Started(earlier)) {
                        pulled_ahead += 1;
                    }
                }
            }
        }
        // What the writer reports is the same whoever pulled what and
        // when: bytes in memory, which pull nothing, and a member at a
        // time, which pulls each member as the writer reaches it.
        let (bytes_set, bytes_events) = logged(&row, &members, Hand::Bytes);
        assert_eq!(bytes_set, set, "{}: bytes in memory", row.label);
        assert_eq!(
            writer_side(&bytes_events),
            writer_side(&events),
            "{}: the writer's reports differ between readers and bytes in memory",
            row.label
        );
        if row.solid {
            let (alone_set, alone_events) =
                writers::with_batch_depth(1, || logged(&row, &members, Hand::Reader));
            assert_eq!(alone_set, set, "{}: a member at a time", row.label);
            assert_eq!(
                writer_side(&alone_events),
                writer_side(&events),
                "{}: the writer's reports differ between a batch and a member at a time",
                row.label
            );
        }
    }
    assert!(
        pulled_ahead > 0,
        "no reader was read ahead of the writer, so these rows did not \
         meet what member_started is for"
    );
}

/// A reader that ends `short` bytes before its declared size.
struct Short<'a> {
    bytes: &'a [u8],
}

impl Read for Short<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = buffer.len().min(self.bytes.len());
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn a_reader_that_ends_early_ends_the_write_at_its_member() {
    let members = members();
    // A small member well inside the set, so a batch pulls it ahead.
    let failing = members
        .iter()
        .position(|member| member.name == b"tree/c03.c")
        .expect("the set has this member");
    for row in rows()
        .into_iter()
        .filter(|row| row.level == 3 && row.cap == SMALL_CAP && is_default_policy(row))
    {
        let log: Log = Arc::default();
        let mut readers: Vec<Short<'_>> = members
            .iter()
            .enumerate()
            .map(|(index, member)| Short {
                bytes: if index == failing {
                    &member.data[..member.data.len() - 1]
                } else {
                    &member.data
                },
            })
            .collect();
        let error = match write_from(
            as_added(&row),
            &members,
            &mut readers,
            Hand::Reader,
            &mut Recorder(Arc::clone(&log)),
        ) {
            Ok(_) => panic!("{}: a short reader was accepted", row.label),
            Err(error) => error,
        };
        assert!(
            matches!(error.kind(), ErrorKind::Truncated),
            "{}: {error}",
            row.label
        );
        // Every member before it was taken up, as a member at a time
        // would have written each of them first, and none after it.
        let last = log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                Event::Started(index) => Some(*index),
                _ => None,
            })
            .max();
        assert_eq!(
            last,
            Some(failing),
            "{}: the last member the writer took up",
            row.label
        );
    }
}

/// A reader that serves `good` bytes, fails ONCE with an error of its
/// own, and after that reads as ended: what the command line's source does
/// once a read of its file has failed.
struct Failing<'a> {
    bytes: &'a [u8],
    good: usize,
    failed: bool,
}

impl Read for Failing<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.failed {
            return Ok(0);
        }
        if self.good == 0 {
            self.failed = true;
            return Err(std::io::Error::other("the reader's own failure"));
        }
        let count = buffer.len().min(self.bytes.len()).min(self.good);
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        self.good -= count;
        Ok(count)
    }
}

/// A reader is pulled ONCE: one whose pull failed ahead of the writer is
/// not pulled again when the writer, or a batch staged again after a
/// volume boundary, reaches its member, and the write ends in the
/// reader's own error, as it does a member at a time. Pulled twice, this
/// reader would read as ended and the write would end `Truncated`.
#[test]
fn a_reader_that_fails_is_pulled_once_and_its_own_error_ends_the_write() {
    // In the set built to overrun its volumes, a small member in the run a
    // boundary discards; in the mixed set, the member the samples judge.
    for (members, rows, in_add_order) in sets() {
        let name: &[u8] = if in_add_order {
            b"r/noise25.dat"
        } else {
            b"tree/sampled.txt"
        };
        let failing = members
            .iter()
            .position(|member| member.name == name)
            .expect("the set has this member");
        for row in rows
            .into_iter()
            .filter(|row| row.level == 3 && row.cap == SMALL_CAP && is_default_policy(row))
        {
            for depth in [1, usize::MAX] {
                let mut readers: Vec<Failing<'_>> = members
                    .iter()
                    .enumerate()
                    .map(|(index, member)| Failing {
                        bytes: &member.data,
                        good: if index == failing {
                            member.data.len() / 2
                        } else {
                            usize::MAX
                        },
                        failed: false,
                    })
                    .collect();
                let mut write = || {
                    write_from(
                        as_added(&row),
                        &members,
                        &mut readers,
                        Hand::Reader,
                        &mut (),
                    )
                };
                let outcome = if depth == 1 {
                    writers::with_batch_depth(1, write)
                } else {
                    write()
                };
                let error = match outcome {
                    Ok(_) => panic!("{}: a failing reader was accepted", row.label),
                    Err(error) => error,
                };
                assert!(
                    matches!(error.kind(), ErrorKind::Caller),
                    "{} at depth {depth}: the write ended in {error} and not in the reader's own error",
                    row.label
                );
            }
        }
    }
}

#[test]
fn what_the_kept_bytes_cost_is_stated_and_bounded() {
    let members = members();
    for row in rows().into_iter().filter(|row| row.solid && row.level == 3) {
        let (_, readers) = write(row.options(), &members, Hand::Reader, &mut ());
        let (_, bytes) = write(row.options(), &members, Hand::Bytes, &mut ());
        // Beside what bytes in memory hold, a set of readers holds what
        // it pulled: the batch being written (kept until the batch after
        // is staged), a discarded tail waiting to be staged again, and
        // the batch pulled ahead. None is more than a batch's input,
        // which a window bounds here, and a pulled member's own buffer.
        let most = bytes.peak_working_memory + 4 * DICTIONARY;
        assert!(
            readers.peak_working_memory <= most,
            "{}: readers stated {} bytes, bytes in memory {}",
            row.label,
            readers.peak_working_memory,
            bytes.peak_working_memory
        );
    }
}

/// Reference `unrar`, if this box has it.
fn unrar() -> Option<&'static str> {
    Command::new("unrar").output().ok().map(|_| "unrar")
}

#[test]
fn reference_unrar_takes_every_set() {
    let Some(unrar) = unrar() else {
        eprintln!("SKIPPED: unrar is not on PATH");
        return;
    };
    let root = std::env::temp_dir().join(format!("rarkit-vrb-{}", std::process::id()));
    let all: Vec<(usize, Row, bool)> = sets()
        .into_iter()
        .enumerate()
        .flat_map(|(set, (_, rows, in_add_order))| {
            rows.into_iter().map(move |row| (set, row, in_add_order))
        })
        .collect();
    let inputs: Vec<Vec<Member>> = sets().into_iter().map(|(members, ..)| members).collect();
    for (at, (set, row, in_add_order)) in all.into_iter().enumerate() {
        let options = options_of(&row, in_add_order);
        let (volumes, _) = write(options, &inputs[set], Hand::Reader, &mut ());
        let dir = root.join(format!("row{at}"));
        std::fs::create_dir_all(&dir).unwrap();
        let total = volumes.len() as u32;
        for (index, volume) in volumes.iter().enumerate() {
            let name = rarkit::volume_file_name("set", index as u32, total, VolumeNaming::Numbered);
            std::fs::write(dir.join(name), volume).unwrap();
        }
        let first = dir.join(rarkit::volume_file_name(
            "set",
            0,
            total,
            VolumeNaming::Numbered,
        ));
        let password = if row.password {
            format!("-p{PASSWORD}")
        } else {
            "-p-".to_owned()
        };
        let out = Command::new(unrar)
            .arg("t")
            .arg(&password)
            .arg(&first)
            .output()
            .expect("unrar t");
        // Both streams: unrar reports a fragment's checksum error on
        // stderr and still ends "All OK" with a success status.
        assert!(
            out.status.success() && out.stderr.is_empty(),
            "{}: unrar t exited {:?}\n{}\n{}",
            row.label,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    let _ = std::fs::remove_dir_all(&root);
}
