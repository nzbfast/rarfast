//! Headers a hostile producer wrote: each archive here is built by hand,
//! with every header checksum right, so the walk takes it and the field
//! under test is the only thing wrong with it.
//!
//! Width and memory: every read here is `Archive::open`, which runs on the
//! calling thread alone, or an extraction at ONE worker. No test here
//! depends on the machine's pool, and none holds more than a few kilobytes.

use std::sync::Arc;

use rarkit::{
    Archive, Corruption, Disposition, ErrorKind, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, RangeSource, Rar4Version, ReadOptions, Sink, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};

// ------------------------------------------------------------ RAR 1.5 to 4

/// The seven byte mark head.
const MARK4: &[u8] = b"Rar!\x1a\x07\x00";

/// Fill in a RAR 1.5 to 4 block's size and its header checksum, the low
/// half of the CRC-32 over everything after the checksum itself.
fn stamp4(mut header: Vec<u8>) -> Vec<u8> {
    let size = header.len() as u16;
    header[5..7].copy_from_slice(&size.to_le_bytes());
    let checksum = crc32fast::hash(&header[2..]) as u16;
    header[..2].copy_from_slice(&checksum.to_le_bytes());
    header
}

/// One RAR 1.5 to 4 file header, every field the tests here move named.
#[derive(Clone)]
struct File4<'a> {
    name: &'a [u8],
    /// Flag bits beside 0x8000 (a data area follows), which is always set.
    flags: u16,
    packed: u64,
    unpacked: u64,
    crc32: u32,
    host: u8,
    version: u8,
    method: u8,
    attributes: u32,
    /// What follows the name inside the header: a salt, an extended time.
    after_name: &'a [u8],
}

impl<'a> File4<'a> {
    /// A stored member of `data`, as RAR 2.9 for Windows writes one.
    fn stored(name: &'a [u8], data: &[u8]) -> File4<'a> {
        File4 {
            name,
            flags: 0,
            packed: data.len() as u64,
            unpacked: data.len() as u64,
            crc32: crc32fast::hash(data),
            host: 2,
            version: 29,
            method: 0x30,
            attributes: 0x20,
            after_name: &[],
        }
    }

    fn header(&self) -> Vec<u8> {
        let flags = 0x8000 | self.flags;
        let mut header = vec![0, 0, 0x74];
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&[0; 2]); // size, stamped below
        header.extend_from_slice(&(self.packed as u32).to_le_bytes());
        header.extend_from_slice(&(self.unpacked as u32).to_le_bytes());
        header.push(self.host);
        header.extend_from_slice(&self.crc32.to_le_bytes());
        header.extend_from_slice(&0x5A21_0000u32.to_le_bytes()); // DOS time
        header.push(self.version);
        header.push(self.method);
        header.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
        header.extend_from_slice(&self.attributes.to_le_bytes());
        if flags & 0x0100 != 0 {
            header.extend_from_slice(&((self.packed >> 32) as u32).to_le_bytes());
            header.extend_from_slice(&((self.unpacked >> 32) as u32).to_le_bytes());
        }
        header.extend_from_slice(self.name);
        header.extend_from_slice(self.after_name);
        stamp4(header)
    }
}

/// The mark head and a main header whose flags are `flags`.
fn start4(flags: u16) -> Vec<u8> {
    let mut out = MARK4.to_vec();
    let mut main = vec![0, 0, 0x73];
    main.extend_from_slice(&flags.to_le_bytes());
    main.extend_from_slice(&[0; 2]);
    main.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&stamp4(main));
    out
}

/// The end of archive block.
fn end4() -> Vec<u8> {
    stamp4(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0])
}

fn open(bytes: Vec<u8>) -> rarkit::Result<Archive> {
    let src: Arc<dyn RangeSource> = Arc::new(bytes);
    Archive::open(src, &ReadOptions::default())
}

/// The error an archive that must not open is refused with.
fn refusal(bytes: Vec<u8>, why: &str) -> rarkit::Error {
    match open(bytes) {
        Err(err) => err,
        Ok(archive) => panic!("{why}: opened, listing {:?}", names(&archive)),
    }
}

fn names(archive: &Archive) -> Vec<String> {
    archive
        .members()
        .map(|m| String::from_utf8_lossy(m.name).into_owned())
        .collect()
}

// ------------------------------------------------------------ RAR 5

fn vint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A RAR 5 block of these fields: its size and its CRC-32 in front.
fn block5(fields: &[u8]) -> Vec<u8> {
    let mut sized = Vec::new();
    vint(&mut sized, fields.len() as u64);
    sized.extend_from_slice(fields);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

/// A RAR 5 file header of a stored member `name` holding `data`, whose
/// header DECLARES a data area of `declared` bytes.
fn file5(name: &[u8], data: &[u8], declared: u64) -> Vec<u8> {
    let mut file = Vec::new();
    vint(&mut file, 2); // FILE
    vint(&mut file, 2); // a data area follows
    vint(&mut file, declared);
    vint(&mut file, 0x04); // CRC32 present
    vint(&mut file, data.len() as u64);
    vint(&mut file, 0); // attributes
    file.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    vint(&mut file, 0); // stored
    vint(&mut file, 1); // host OS: Unix
    vint(&mut file, name.len() as u64);
    file.extend_from_slice(name);
    block5(&file)
}

// ------------------------------------------------------------ M-18

/// A data area whose declared size carries the block's end past the top of
/// a u64 is data the source does not hold: `Truncated`, the verdict any
/// other over-long data area gets (spec F 3.5.5). It is never a wrapped
/// end, which would walk the member's own packed bytes as headers and list
/// what every other reader skips.
#[test]
fn a_rar4_packed_size_past_the_top_of_a_u64_is_truncated() {
    // What the outer member's data area holds: a whole file header and an
    // end block, which a walk that wrapped would take for the archive's.
    let mut hidden = File4::stored(b"hidden", b"secret").header();
    hidden.extend_from_slice(b"secret");
    hidden.extend_from_slice(&end4());

    let mut outer = File4::stored(b"outer", &hidden);
    outer.flags = 0x0100;
    outer.packed = (0xFFFF_FFFFu64 << 32) | 0xFFFF_FFF0;
    let mut bytes = start4(0);
    bytes.extend_from_slice(&outer.header());
    bytes.extend_from_slice(&hidden);

    match open(bytes) {
        Err(err) => assert!(
            matches!(err.kind(), ErrorKind::Truncated),
            "wanted Truncated, got {:?}",
            err.kind()
        ),
        Ok(archive) => panic!("opened, listing {:?}", names(&archive)),
    }
}

/// RAR 5 cannot reach the same sum: a vint above `2^63 - 1` is refused
/// where it is read (spec F 3.2.1), and a header sits below that in any
/// source, so the largest data size there is answers `Truncated` already.
#[test]
fn the_largest_rar5_data_size_is_truncated_and_a_larger_vint_is_corrupt() {
    let archive = |declared: u64| {
        let mut bytes = b"Rar!\x1a\x07\x01\x00".to_vec();
        bytes.extend_from_slice(&block5(&[1, 0, 0]));
        bytes.extend_from_slice(&file5(b"outer", b"secret", declared));
        bytes.extend_from_slice(b"secret");
        bytes.extend_from_slice(&block5(&[5, 0, 0]));
        bytes
    };
    let err = refusal(archive(i64::MAX as u64), "too long");
    assert!(
        matches!(err.kind(), ErrorKind::Truncated),
        "{:?}",
        err.kind()
    );
    let err = refusal(archive(u64::MAX - 8), "no such vint");
    assert!(
        matches!(err.kind(), ErrorKind::Corrupt(_)),
        "{:?}",
        err.kind()
    );
}

/// The control: the largest data area that does NOT wrap already answers
/// `Truncated`, so the two tests above ask for the verdict the reader gave
/// one byte earlier.
#[test]
fn a_rar4_packed_size_just_short_of_wrapping_is_truncated() {
    let mut outer = File4::stored(b"outer", b"");
    outer.flags = 0x0100;
    outer.packed = u64::MAX / 2;
    let mut bytes = start4(0);
    bytes.extend_from_slice(&outer.header());
    bytes.extend_from_slice(&end4());
    let err = refusal(bytes, "a data area the source lacks");
    assert!(
        matches!(err.kind(), ErrorKind::Truncated),
        "{:?}",
        err.kind()
    );
}

// ------------------------------------------------------------ M-19

const PASSWORD: &str = "cut short";

/// One archive with ENCRYPTED headers, two stored members, written by this
/// engine's own writer.
fn encrypted_headers(format: WriteFormat) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format,
        method: WriteMethod::Stored,
        password: Some(Password::new(PASSWORD)),
        encrypt_headers: true,
        entropy: rarkit::Entropy::Seeded([9u8; 32]),
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in [(&b"one"[..], &[1u8; 100][..]), (b"two", &[2u8; 300])] {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn open_with_password(bytes: Vec<u8>) -> rarkit::Result<Archive> {
    let src: Arc<dyn RangeSource> = Arc::new(bytes);
    let options = ReadOptions::default().with_password(Some(Password::new(PASSWORD)));
    Archive::open(src, &options)
}

/// An archive with encrypted headers that is cut off PARTWAY THROUGH a
/// header is `Truncated`, as the same cut is with clear headers (spec F
/// 3.5.5). A clean end is a source with NO bytes where the next header
/// would start, and nothing else: bytes that are there and are too few for
/// a header are a damaged archive, never a complete one.
#[test]
fn a_cut_inside_an_encrypted_header_is_truncated() {
    for format in [WriteFormat::Rar4(Rar4Version::V29), WriteFormat::Rar5] {
        let whole = encrypted_headers(format);
        let archive = open_with_password(whole.clone())
            .unwrap_or_else(|e| panic!("{format:?}: the whole archive: {e}"));
        assert_eq!(names(&archive), ["one", "two"], "{format:?}");
        assert!(archive.tail().is_none(), "{format:?}");
        // Where the last block, the end of archive header, starts.
        let last = archive.blocks().last().expect("blocks").range.start as usize;
        assert!(last < whole.len() && whole.len() - last >= 16, "{format:?}");

        // Every cut that leaves SOME of the end block and not all of it.
        for keep in last + 1..whole.len() {
            match open_with_password(whole[..keep].to_vec()) {
                Err(err) => assert!(
                    matches!(err.kind(), ErrorKind::Truncated),
                    "{format:?} cut to {keep} of {}: {:?}",
                    whole.len(),
                    err.kind()
                ),
                Ok(archive) => panic!(
                    "{format:?} cut to {keep} of {}: opened, tail {:?}",
                    whole.len(),
                    archive.tail().map(|e| format!("{:?}", e.kind()))
                ),
            }
        }

        // A cut AT the block's start leaves no bytes there: the clean end
        // the same archive gives with clear headers and no end block.
        let archive = open_with_password(whole[..last].to_vec())
            .unwrap_or_else(|e| panic!("{format:?}: cut at the end block: {e}"));
        assert_eq!(names(&archive), ["one", "two"], "{format:?}");
    }
}

// ------------------------------------------------------------ L-27

/// One stored member whose extended time area is `area`.
fn extended_time(area: &[u8]) -> Vec<u8> {
    let mut file = File4::stored(b"timed", b"data");
    file.flags = 0x1000;
    file.after_name = area;
    let mut bytes = start4(0);
    bytes.extend_from_slice(&file.header());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&end4());
    bytes
}

/// `Timestamp::nanos` is documented as always under one thousand million.
/// Three fraction bytes count 100 ns units up to 16,777,215 of them, which
/// is more than a second, so the reader must not hand the product out as
/// it stands. (The sweep item names extended flags 0x8300 for this; the
/// modification time's group is the TOP nibble, so three fraction bytes
/// are 0xB000.)
#[test]
fn an_extended_time_fraction_over_a_second_stays_inside_the_documented_range() {
    // The modification group 0xB: present, no added second, three bytes.
    let plain = open(extended_time(&[0x00, 0x80])).expect("no fraction");
    let base = plain
        .members()
        .next()
        .expect("a member")
        .mtime
        .expect("a time");
    assert_eq!(base.nanos, 0);

    let archive = open(extended_time(&[0x00, 0xB0, 0xFF, 0xFF, 0xFF])).expect("opens");
    let got = archive
        .members()
        .next()
        .expect("a member")
        .mtime
        .expect("a time");
    assert!(got.nanos < 1_000_000_000, "nanos {}", got.nanos);
    // The whole second is carried, as reference unrar 7.23 lists it:
    // `mtime: 2025-01-01 00:00:01,677721500` for this header, against
    // `00:00:00,000000000` with no fraction (`unrar lt`, 4 Oct 2026).
    assert_eq!(
        (got.unix_seconds, got.nanos),
        (base.unix_seconds + 1, 677_721_500)
    );
    // With the group's added second as well (0xF): `00:00:02,677721500`.
    let archive = open(extended_time(&[0x00, 0xF0, 0xFF, 0xFF, 0xFF])).expect("opens");
    let got = archive
        .members()
        .next()
        .expect("a member")
        .mtime
        .expect("a time");
    assert_eq!(
        (got.unix_seconds, got.nanos),
        (base.unix_seconds + 2, 677_721_500)
    );

    // The largest fraction that IS under a second is untouched.
    let ticks = 9_999_999u32.to_le_bytes();
    let archive = open(extended_time(&[0x00, 0xB0, ticks[0], ticks[1], ticks[2]])).expect("opens");
    let got = archive
        .members()
        .next()
        .expect("a member")
        .mtime
        .expect("a time");
    assert_eq!(
        (got.unix_seconds, got.nanos),
        (base.unix_seconds, 999_999_900)
    );
}

// ------------------------------------------------------------ L-25

/// One member's name, its checksum verdict and how many bytes it decoded
/// to.
type Verdict = (String, Option<bool>, u64);

/// Every member's verdict, in close order. A link is verified, or with
/// `skip_links` skipped; it is never written (spec F 3.8.1).
#[derive(Default)]
struct Verdicts {
    skip_links: bool,
    closed: Vec<Verdict>,
}

impl Sink for Verdicts {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        if member.redirection.is_some() {
            return Ok(if self.skip_links {
                Disposition::Skip
            } else {
                Disposition::Verify
            });
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed.push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
            outcome.bytes,
        ));
        Ok(())
    }
}

/// Extract `bytes` at ONE worker: the verdicts, and the error the read
/// ended with.
fn extract_one_wide(bytes: Vec<u8>, skip_links: bool) -> (Vec<Verdict>, Option<rarkit::Error>) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes)];
    let mut sink = Verdicts {
        skip_links,
        closed: Vec::new(),
    };
    let options = ReadOptions::default().with_workers(Some(1));
    let end = rarkit::extract(sources, &options, &mut sink, &mut ()).err();
    (sink.closed, end)
}

/// A SOLID RAR 2.9 archive of three compressed members `a`, `b`, `c` in
/// that order, `b` 70,000 bytes long.
fn solid_three() -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V29),
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid: true,
        order: rarkit::MemberOrder::AsAdded,
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    let members = [
        (&b"a"[..], rarkit_testdata::chatter(1, 9_000)),
        (b"b", rarkit_testdata::chatter(2, 70_000)),
        (b"c", rarkit_testdata::chatter(3, 9_000)),
    ];
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// `src` with the file header of member `name` turned into a Unix
/// symbolic link (host 3, mode 0o120777), its checksum rewritten and
/// nothing else touched.
fn as_unix_link(src: &[u8], name: &[u8]) -> Vec<u8> {
    let u16_at = |p: usize| u16::from_le_bytes([src[p], src[p + 1]]) as usize;
    let u32_at = |p: usize| u32::from_le_bytes(src[p..p + 4].try_into().unwrap()) as usize;
    let mut out = src.to_vec();
    let mut p = MARK4.len();
    while p + 7 <= src.len() {
        let (kind, flags, size) = (src[p + 2], u16_at(p + 3), u16_at(p + 5));
        let mut data = 0;
        if kind == 0x74 {
            data = u32_at(p + 7);
            let name_len = u16_at(p + 26);
            if &src[p + 32..p + 32 + name_len] == name {
                out[p + 15] = 3;
                out[p + 28..p + 32].copy_from_slice(&0o120777u32.to_le_bytes());
                let crc = crc32fast::hash(&out[p + 2..p + size]) as u16;
                out[p..p + 2].copy_from_slice(&crc.to_le_bytes());
                return out;
            }
        } else if flags & 0x8000 != 0 {
            data = u32_at(p + 7);
        }
        p += size + data;
    }
    panic!("no member {name:?}");
}

/// A RAR 4 family link whose target is over the 64 KiB bound is refused
/// unread (spec F 3.3.12). In a SOLID archive its bytes then never reach
/// the window, so the member after it cannot be decoded: it is refused
/// `Corrupt(Stream)`, as after any other member the reader skipped out of
/// a chain (spec F 3.2.6). It is never decoded against the window the
/// link's bytes are missing from.
#[test]
fn a_refused_rar4_link_breaks_its_solid_chain() {
    let whole = solid_three();
    let (verdicts, end) = extract_one_wide(whole.clone(), false);
    assert!(end.is_none(), "the archive as written: {end:?}");
    assert_eq!(
        verdicts,
        [
            ("a".to_string(), Some(true), 9_000),
            ("b".to_string(), Some(true), 70_000),
            ("c".to_string(), Some(true), 9_000)
        ]
    );

    let link = as_unix_link(&whole, b"b");
    let (verdicts, end) = extract_one_wide(link.clone(), false);
    assert_eq!(verdicts[0], ("a".to_string(), Some(true), 9_000));
    assert_eq!(verdicts[1], ("b".to_string(), Some(false), 0));
    assert_eq!(verdicts[2], ("c".to_string(), Some(false), 0));
    // The read ends with its FIRST member error, which is the link's.
    let end = end.expect("two members refused");
    assert!(
        matches!(end.kind(), ErrorKind::Corrupt(Corruption::Redirection)),
        "{:?}",
        end.kind()
    );

    // With the link SKIPPED by the caller the first error is `c`'s own,
    // and it is the chain's refusal: not whatever a decoder says of packed
    // bytes read against a window the link's bytes never reached.
    let (verdicts, end) = extract_one_wide(link, true);
    assert_eq!(
        verdicts,
        [
            ("a".to_string(), Some(true), 9_000),
            ("c".to_string(), Some(false), 0)
        ]
    );
    let end = end.expect("c refused");
    assert!(
        matches!(end.kind(), ErrorKind::Corrupt(Corruption::Stream)),
        "{:?}",
        end.kind()
    );
}

// ------------------------------------------------------------ L-38

/// The RAR 1.3 keystream of SPEC-K 3.3, as the writer of an archive runs
/// it: key setup from the password, then one step a byte.
struct Stream13([u8; 3]);

impl Stream13 {
    fn new(password: &[u8]) -> Stream13 {
        let mut k = [0u8; 3];
        for p in password {
            k[0] = k[0].wrapping_add(*p);
            k[1] ^= *p;
            k[2] = k[2].wrapping_add(*p).rotate_left(1);
        }
        Stream13(k)
    }

    fn encipher(&mut self, plain: &[u8]) -> Vec<u8> {
        let k = &mut self.0;
        plain
            .iter()
            .map(|p| {
                k[1] = k[1].wrapping_add(k[2]);
                k[0] = k[0].wrapping_add(k[1]);
                p.wrapping_add(k[0])
            })
            .collect()
    }
}

/// One RAR 1.3 volume holding one fragment of the stored member `M.BIN`.
fn volume13(fragment: &[u8], unpacked: u32, sum16: u16, flags: u8) -> Vec<u8> {
    let name = b"M.BIN";
    let mut out = b"RE~^".to_vec();
    out.extend_from_slice(&7u16.to_le_bytes());
    out.push(0x81); // a volume
    out.extend_from_slice(&(fragment.len() as u32).to_le_bytes());
    out.extend_from_slice(&unpacked.to_le_bytes());
    out.extend_from_slice(&sum16.to_le_bytes());
    out.extend_from_slice(&(21 + name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0x512d_6354u32.to_le_bytes()); // DOS time
    out.push(0x20); // attributes
    out.push(flags);
    out.push(2); // unpack version
    out.push(name.len() as u8);
    out.push(0); // stored
    out.extend_from_slice(name);
    out.extend_from_slice(fragment);
    out
}

/// A RAR 1.3 member split across two volumes is enciphered under ONE
/// keystream, which runs on across the volume crossing.
///
/// SPEC-K 3.3 says the keystream restarts at each volume's fragment, and
/// marks that rule unconfirmed (its question 2: flip it if the reference
/// disagrees). The reference disagrees. MEASURED 4 Oct 2026 with unrar
/// 7.23, `unrar t -ppassword`, on the two sets this test builds: the set
/// with one keystream across both fragments tests `All OK`, and the set
/// whose second fragment starts from key setup again is `Checksum error
/// in the encrypted file M.BIN`. The reader has always done what the
/// reference does; this pins it. Both sets are hand-built (no genuine DOS
/// RAR 1.40 encrypted volume set is in the corpus), stored, one worker.
#[test]
fn a_rar13_keystream_runs_on_across_a_volume_crossing() {
    let data: Vec<u8> = (0..3000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let sum16 = data
        .iter()
        .fold(0u16, |s, b| s.wrapping_add(u16::from(*b)).rotate_left(1));
    let (first, second) = data.split_at(1700);
    let read = |one: Vec<u8>, two: Vec<u8>| {
        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(one), Arc::new(two)];
        let mut sink = Verdicts::default();
        let options = ReadOptions::default()
            .with_workers(Some(1))
            .with_password(Some(Password::new("password")));
        let end = rarkit::extract(sources, &options, &mut sink, &mut ()).err();
        (sink.closed, end.map(|e| format!("{:?}", e.kind())))
    };

    // One keystream across both fragments: what the reference passes.
    let mut stream = Stream13::new(b"password");
    let (verdicts, end) = read(
        volume13(&stream.encipher(first), 3000, sum16, 0x06),
        volume13(&stream.encipher(second), 3000, sum16, 0x05),
    );
    assert_eq!(end, None);
    assert_eq!(verdicts, [("M.BIN".to_string(), Some(true), 3000)]);

    // Key setup again at the second fragment: what the reference fails.
    let (verdicts, _) = read(
        volume13(
            &Stream13::new(b"password").encipher(first),
            3000,
            sum16,
            0x06,
        ),
        volume13(
            &Stream13::new(b"password").encipher(second),
            3000,
            sum16,
            0x05,
        ),
    );
    assert_eq!(verdicts, [("M.BIN".to_string(), Some(false), 3000)]);
}
