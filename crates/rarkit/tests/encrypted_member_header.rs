//! Spec G 3.3.3 and 3.12, spec K 3.7: the encrypted member's header.
//!
//! Pins the file header and its encryption record that the RAR 5 writer
//! emits under `-p` (a password, headers in clear) against reference
//! `rar` 7.23's own archives in `specs/vectors-K`, so that any later
//! change to that header is deliberate.
//!
//! Why this exists: the rivals round of 24 Sep 2026 saw macOS `bsdtar`
//! 3.5.3 (libarchive 3.7.4) exit 0 with wrong bytes on a rarkit archive
//! and refuse a rar one. That `bsdtar` ignores the file encryption
//! record: it copies a stored member's ciphertext out and exits 0, and
//! runs a compressed member's ciphertext through its decoder, where a rare
//! ciphertext passes the first block header and exits 0. Moving the two
//! archives' ciphertexts into each other's header framing moved the exit
//! 0 with the ciphertext (24 Sep 2026), so no
//! header field was implicated. The record is rar's field for field,
//! which the two tests below hold.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract, ChecksumKind, Disposition, Entropy, EntropySource, Layout, MemberInfo, MemberOutcome,
    MemberSpec, Password, Payload, RangeSource, ReadOptions, Sink, Timestamp, WriteOptions, Writer,
};

fn vector(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-K"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// Spec K 5.4, `r5_p_m0_crc.rar`: the archive's salt, then each member's
/// initialisation vector in member order.
const CRC_SALT: &str = "4a 25 a3 f5 58 dd b7 2b c0 40 16 e2 a4 25 ec c2";
const CRC_IV_HELLO: &str = "ab cd f5 a3 1e 1a e7 bb 38 08 50 66 8e 10 0f ae";
const CRC_IV_DATA: &str = "42 d5 e8 b1 a8 d2 29 0e 71 64 a5 84 01 87 b3 28";
/// The check record spec K 5.4 gives for that salt and `Secret`.
const CRC_CHECK: &str = "65 57 68 1c c3 12 3e 38 5a 43 c6 96";

/// Hands out, in order, the byte strings the reference drew, one per
/// request, and refuses a request of any other length: spec G 3.13 says
/// the writer draws a salt per archive, then an IV per member.
struct Replay(Vec<Vec<u8>>);

impl EntropySource for Replay {
    fn fill(&mut self, buf: &mut [u8]) -> rarkit::Result<()> {
        assert!(
            !self.0.is_empty(),
            "the writer drew more than the reference did"
        );
        let next = self.0.remove(0);
        assert_eq!(buf.len(), next.len(), "a draw of an unexpected length");
        buf.copy_from_slice(&next);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Member {
    name: Vec<u8>,
    data: Vec<u8>,
    mtime: Option<Timestamp>,
    attributes: u32,
    host_os: rarkit::HostOs,
}

#[derive(Default)]
struct Collect(Vec<Member>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        assert!(!member.is_directory && !member.split_before);
        self.0.push(Member {
            name: member.name.to_vec(),
            data: Vec::new(),
            mtime: member.mtime,
            attributes: member.attributes,
            host_os: member.host_os,
        });
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.0.last_mut()) {
            last.data = bytes;
        }
        Ok(())
    }
}

struct NoProgress;

impl rarkit::Progress for NoProgress {}

fn password() -> Password {
    Password::from("Secret")
}

/// The members of a K vector, read with its password.
fn members_of(archive: &[u8]) -> Vec<Member> {
    let mut sink = Collect::default();
    let read = ReadOptions::default().with_password(Some(password()));
    extract(
        vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>],
        &read,
        &mut sink,
        &mut NoProgress,
    )
    .expect("reading the reference's archive with its password");
    sink.0
}

fn write(
    layout: Layout,
    checksum: ChecksumKind,
    draws: Vec<Vec<u8>>,
    members: &[Member],
) -> Vec<u8> {
    let options = WriteOptions {
        layout,
        checksum,
        host_os: rarkit::HostOs::Unix,
        password: Some(password()),
        entropy: Entropy::Source(Box::new(Replay(draws))),
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    for m in members {
        writer
            .add(MemberSpec {
                name: &m.name,
                payload: Payload::Bytes(&m.data),
                mtime: m.mtime,
                attributes: m.attributes,
                host_os: m.host_os,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

// ---- a clear-header block walk, from spec G 3.2 --------------------------

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
    }
    panic!("a vint longer than ten bytes");
}

/// One file header (type 2), with every field in its read-back value, so
/// that two headers can be compared regardless of the width their size
/// fields were written at (spec G 3.2, 3.6.4).
#[derive(Debug, PartialEq, Eq)]
struct FileHeader {
    header_flags: u64,
    extra_size: u64,
    data_size: u64,
    file_flags: u64,
    unpacked: u64,
    attributes: u64,
    mtime: Option<[u8; 4]>,
    crc: Option<[u8; 4]>,
    compression: u64,
    host: u64,
    name: Vec<u8>,
    /// The extra area verbatim, every record in order.
    extra: Vec<u8>,
}

/// Every file header of a clear-header RAR 5 archive, in order.
fn file_headers(archive: &[u8]) -> Vec<FileHeader> {
    assert_eq!(&archive[..8], b"Rar!\x1a\x07\x01\x00");
    let mut out = Vec::new();
    let mut at = 8;
    while at < archive.len() {
        let crc_at = at;
        let mut i = at + 4;
        let size = vint(archive, &mut i) as usize;
        let end = i + size;
        assert_eq!(
            crc32(&archive[crc_at + 4..end]),
            u32::from_le_bytes(archive[crc_at..crc_at + 4].try_into().unwrap()),
            "header checksum at {crc_at}"
        );
        let kind = vint(archive, &mut i);
        let header_flags = vint(archive, &mut i);
        let extra_size = if header_flags & 1 != 0 {
            vint(archive, &mut i)
        } else {
            0
        };
        let data_size = if header_flags & 2 != 0 {
            vint(archive, &mut i)
        } else {
            0
        };
        if kind == 2 {
            let file_flags = vint(archive, &mut i);
            let unpacked = vint(archive, &mut i);
            let attributes = vint(archive, &mut i);
            let mut four = |present: bool| {
                present.then(|| {
                    let v: [u8; 4] = archive[i..i + 4].try_into().unwrap();
                    i += 4;
                    v
                })
            };
            let mtime = four(file_flags & 2 != 0);
            let crc = four(file_flags & 4 != 0);
            let compression = vint(archive, &mut i);
            let host = vint(archive, &mut i);
            let len = vint(archive, &mut i) as usize;
            let name = archive[i..i + len].to_vec();
            i += len;
            assert_eq!(
                i,
                end - extra_size as usize,
                "type fields end where the extra area starts"
            );
            out.push(FileHeader {
                header_flags,
                extra_size,
                data_size,
                file_flags,
                unpacked,
                attributes,
                mtime,
                crc,
                compression,
                host,
                name,
                extra: archive[i..end].to_vec(),
            });
        }
        at = end + data_size as usize;
    }
    out
}

/// CRC32 (the IEEE polynomial, reflected), written out here so this file
/// needs nothing from the crate's internals to check a header.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The file encryption record spec K 3.7 describes, as it must appear in
/// the extra area: size 48, type 1, version 0, flags 0x0003 (check value
/// present, checksums MAC converted), exponent 15, salt, IV, check record.
fn expected_record(salt: &[u8], iv: &[u8], check: &[u8]) -> Vec<u8> {
    let mut record = vec![0x30, 0x01, 0x00, 0x03, 0x0f];
    record.extend_from_slice(salt);
    record.extend_from_slice(iv);
    record.extend_from_slice(check);
    record
}

/// Spec G 3.6 with spec K 3.7.7: under the reference layout, fed the
/// reference's own salt and initialisation vectors, the writer reproduces
/// `rar` 7.23's password protected archive byte for byte, headers,
/// encryption records, ciphertext and MAC converted checksums included.
#[test]
fn the_reference_layout_reproduces_the_references_password_archive_byte_for_byte() {
    let theirs = vector("r5_p_m0_crc.rar");
    let members = members_of(&theirs);
    let draws = vec![hex(CRC_SALT), hex(CRC_IV_HELLO), hex(CRC_IV_DATA)];
    let ours = write(
        Layout::Reference { quick_open: true },
        ChecksumKind::Crc32,
        draws,
        &members,
    );
    assert_eq!(ours.len(), theirs.len(), "length against the reference's");
    assert_eq!(ours, theirs, "bytes differ from the reference's");
}

/// Spec G 3.5 with spec K 3.7: the DEFAULT layout's encrypted member header
/// is rar's field for field. Every field reads back to the reference's
/// value and the extra area, the encryption record then the time record,
/// is the reference's byte for byte; the only permitted difference is the width of the size
/// fields, which the default layout writes in the shortest form
/// (spec G 3.2) and the reference pads (spec G 3.6.4).
#[test]
fn the_default_layouts_encrypted_member_header_is_the_references_field_for_field() {
    let theirs = vector("r5_p_m0_crc.rar");
    let members = members_of(&theirs);
    let draws = vec![hex(CRC_SALT), hex(CRC_IV_HELLO), hex(CRC_IV_DATA)];
    let ours = write(Layout::default(), ChecksumKind::Crc32, draws, &members);

    let ours = file_headers(&ours);
    let theirs = file_headers(&theirs);
    assert_eq!(ours.len(), 2);
    assert_eq!(
        ours, theirs,
        "the encrypted member headers differ from the reference's"
    );

    let salt = hex(CRC_SALT);
    let check = hex(CRC_CHECK);
    for (header, iv) in ours.iter().zip([CRC_IV_HELLO, CRC_IV_DATA]) {
        assert_eq!(
            header.header_flags, 0x3,
            "extra area and data area, nothing else"
        );
        // Spec G 3.3.3's record order: encryption (49 bytes with its size
        // field) first, then the time record these sub-second members
        // carry (spec G 3.4.2): size 10, type 3, and nothing after it.
        assert_eq!(header.extra_size, 60);
        assert_eq!(header.extra[..49], expected_record(&salt, &hex(iv), &check));
        assert_eq!(
            header.extra[49..51],
            [0x0a, 0x03],
            "the time record follows"
        );
        assert_eq!(
            header.mtime, None,
            "a sub-second time is not in the 4 byte field"
        );
        assert_eq!(
            header.file_flags & 0x4,
            0x4,
            "the (MAC converted) CRC32 field"
        );
        assert_eq!(header.compression, 0, "stored: method 0, power 0");
        assert_eq!(
            header.data_size % 16,
            0,
            "the packed size is the padded length"
        );
    }
    assert_eq!(
        ours[0].data_size, 32,
        "hello.txt: 27 bytes pad to 32 (spec K 5.4)"
    );
    assert_eq!(
        ours[0].crc,
        Some(0x7F0D_EE3Eu32.to_le_bytes()),
        "spec K 5.4's MAC"
    );
    assert_eq!(
        ours[1].crc,
        Some(0x8524_593Eu32.to_le_bytes()),
        "spec K 5.4's MAC"
    );
}
