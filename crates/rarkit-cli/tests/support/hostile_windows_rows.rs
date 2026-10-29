//! Hostile Windows path forms as RAR 5 and RAR 4 archives, one archive a
//! row, for the security briefs' Windows rows (brief 3, and brief 2's
//! Windows link forms). Built from spec F 3.2.2, 3.2.6 and 3.2.6.2, and
//! for RAR 4 spec F section 2, alone, through the `rewrite` helper the
//! including file declares.
//!
//! Every escape a row tries aims at one directory, `<root>\escaped`, which
//! holds a canary file, laid out so that the member names' climbs reach it:
//! the archive sits in `<root>\<arm>\<tag>` and is extracted into `out`
//! there, so `..\..\..\escaped` from `out` is the canary directory. A row
//! that escapes therefore writes only into that directory, never anywhere
//! else on the machine.

use super::rewrite;

/// The canary's file name and its contents, which a member that reads
/// outside the destination (a copy, a hard link) would carry back in.
pub const CANARY: &str = "canary.txt";
pub const CANARY_BODY: &[u8] = b"CANARY SECRET, KEEP\n";

/// What a member is.
pub enum Member {
    /// A stored file of these bytes, its name written by this host:
    /// 1 Unix, 0 Windows (spec F 3.2.6).
    File {
        name: String,
        data: Vec<u8>,
        host: u64,
    },
    /// A redirection (spec F 3.2.6.2): kind 1 Unix symbolic link, 2
    /// Windows symbolic link, 3 junction, 4 hard link, 5 file copy; `dir`
    /// sets the directory flag the Windows writer sets on a directory link.
    Link {
        name: String,
        kind: u64,
        target: String,
        dir: bool,
        host: u64,
    },
    /// A RAR 4 member whose header carries flag 0x0200 and this name field
    /// as it stands (spec F 3.3.7): a stored file, or with `link` a Unix
    /// symbolic link whose target is `data`. RAR 5 has no such field, so
    /// [`archive`] leaves it out.
    Field4 {
        field: Vec<u8>,
        data: Vec<u8>,
        host: u64,
        link: bool,
    },
}

pub fn file(name: &str, data: &str) -> Member {
    Member::File {
        name: name.to_owned(),
        data: data.as_bytes().to_vec(),
        host: 1,
    }
}

pub fn windows_file(name: &str, data: &str) -> Member {
    Member::File {
        name: name.to_owned(),
        data: data.as_bytes().to_vec(),
        host: 0,
    }
}

pub fn link(name: &str, kind: u64, target: &str, dir: bool) -> Member {
    Member::Link {
        name: name.to_owned(),
        kind,
        target: target.to_owned(),
        dir,
        host: if kind == 1 { 1 } else { 0 },
    }
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of these members, stored, in the order given.
pub fn archive(members: &[Member]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for member in members {
        let (name, data, host, extra, dir): (&str, &[u8], u64, Vec<u8>, bool) = match member {
            Member::File { name, data, host } => (name, data, *host, Vec::new(), false),
            Member::Link {
                name,
                kind,
                target,
                dir,
                host,
            } => (
                name,
                b"",
                *host,
                rewrite::area(&[(
                    5,
                    rewrite::redirect(*kind, u64::from(*dir), target.as_bytes()),
                )]),
                *dir,
            ),
            Member::Field4 { .. } => continue,
        };
        let mut flags = 0;
        if !extra.is_empty() {
            flags |= 0x1;
        }
        if !data.is_empty() {
            flags |= 0x2;
        }
        let mut body = rewrite::vint(2); // file header
        body.extend(rewrite::vint(flags));
        if !extra.is_empty() {
            body.extend(rewrite::vint(extra.len() as u64));
        }
        if !data.is_empty() {
            body.extend(rewrite::vint(data.len() as u64));
        }
        // CRC32 present, and the directory flag on a directory link.
        body.extend(rewrite::vint(if dir { 0x5 } else { 0x4 }));
        body.extend(rewrite::vint(data.len() as u64));
        let attributes: u64 = match (member, host, dir) {
            (Member::Link { .. }, 1, _) => 0o120_777,
            (Member::Link { .. }, _, true) => 0x430,
            (Member::Link { .. }, _, false) => 0x420,
            (Member::File { .. }, 1, _) => 0o100_644,
            _ => 0x20,
        };
        body.extend(rewrite::vint(attributes));
        body.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(host));
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        body.extend(extra);
        block(&body, &mut out);
        out.extend_from_slice(data);
    }
    block(&[5, 0, 0], &mut out);
    out
}

/// A RAR 4 archive of these members, stored, in the order given (spec F
/// section 2: the mark, a main header, a file header a member). A file's
/// host 1 is written Unix (3) and 0 Win32 (2), and a name is stored as its
/// bytes with no Unicode field, but for a [`Member::Field4`], which carries
/// its own field and flag 0x0200. RAR 4 has only one redirection, the Unix
/// symbolic link whose target is its content; any other link kind is left
/// out.
pub fn archive_rar4(members: &[Member]) -> Vec<u8> {
    fn stamp(mut header: Vec<u8>) -> Vec<u8> {
        let size = header.len() as u16;
        header[5..7].copy_from_slice(&size.to_le_bytes());
        let checksum = rewrite::crc32(&header[2..]) as u16;
        header[..2].copy_from_slice(&checksum.to_le_bytes());
        header
    }
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    out.extend(stamp(vec![0, 0, 0x73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    for member in members {
        let (name, data, host, attributes, flags): (&[u8], &[u8], u8, u32, u16) = match member {
            Member::File { name, data, host } => {
                if *host == 1 {
                    (name.as_bytes(), data, 3, 0o100_644, 0x8000)
                } else {
                    (name.as_bytes(), data, 2, 0x20, 0x8000)
                }
            }
            Member::Link {
                name, kind, target, ..
            } if *kind == 1 => (name.as_bytes(), target.as_bytes(), 3, 0o120_777, 0x8000),
            Member::Link { .. } => continue,
            Member::Field4 {
                field,
                data,
                host,
                link,
            } => match (*link, *host) {
                (true, _) => (field, data, 3, 0o120_777, 0x8200),
                (false, 1) => (field, data, 3, 0o100_644, 0x8200),
                (false, _) => (field, data, 2, 0x20, 0x8200),
            },
        };
        let mut header = vec![0, 0, 0x74];
        // A long block, and the two-part name of a `Field4`.
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&[0; 2]); // size, stamped below
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.push(host);
        header.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
        header.extend_from_slice(&0x5A21_0000u32.to_le_bytes()); // DOS time
        header.push(29); // unpack version
        header.push(0x30); // stored
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&attributes.to_le_bytes());
        header.extend_from_slice(name);
        out.extend(stamp(header));
        out.extend_from_slice(data);
    }
    out.extend(stamp(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0]));
    out
}

/// The RAR 4 rows: brief 3's rows as RAR 4 archives, less the names that
/// are not ASCII (a RAR 4 name is 8-bit without its Unicode field), and
/// brief 2 as Unix symbolic links, the one link RAR 4 stores, with
/// Windows-form targets and a file written through one.
pub fn rows_rar4(escaped: &str, drive: char) -> Vec<(&'static str, Vec<Member>)> {
    let canary = format!("{escaped}\\{CANARY}");
    let climb = "..\\..\\..\\escaped";
    let mut out: Vec<(&'static str, Vec<Member>)> = rows(escaped, drive)
        .into_iter()
        .filter_map(|(tag, members)| {
            let tag = match tag {
                "b3-ads" => "r4-b3-ads",
                "b3-devices" => "r4-b3-devices",
                "b3-absolute-unix-host" => "r4-b3-absolute-unix-host",
                "b3-absolute-windows-host" => "r4-b3-absolute-windows-host",
                "b3-trailing" => "r4-b3-trailing",
                _ => return None,
            };
            let ascii = members
                .into_iter()
                .filter(|m| match m {
                    Member::File { name, .. } | Member::Link { name, .. } => name.is_ascii(),
                    Member::Field4 { .. } => true,
                })
                .collect();
            Some((tag, ascii))
        })
        .collect();
    out.push((
        "r4-b2-unix-links",
        vec![
            link("abs", 1, escaped, false),
            link("abs-file", 1, &canary, false),
            link("climb", 1, climb, false),
            link("verbatim", 1, &format!("\\\\?\\{escaped}"), false),
            link("nt", 1, &format!("\\??\\{escaped}"), false),
            link(
                "drive-rel",
                1,
                &format!("{drive}:..\\..\\..\\escaped"),
                false,
            ),
            link("inside", 1, "plain-dir", false),
            file("plain-dir/kept.txt", "a real directory the safe link names"),
            link("lnk", 1, climb, false),
            file(&format!("lnk/{CANARY}"), "PWNED through a climbing link"),
            link("lnk2", 1, escaped, false),
            file(&format!("lnk2\\{CANARY}"), "PWNED through an absolute link"),
        ],
    ));
    out
}

/// A two-part name field (spec F 3.3.7): the fallback, one zero byte, a
/// shared high byte of zero, then every unit by selector 2 (two bytes, low
/// first), four selectors to a selector byte. Selector 2 carries any unit,
/// a lone surrogate and a zero unit included.
pub fn two_part(fallback: &[u8], units: &[u16]) -> Vec<u8> {
    let mut field = fallback.to_vec();
    field.extend_from_slice(&[0, 0]);
    for four in units.chunks(4) {
        field.push(0xAA);
        for unit in four {
            field.extend_from_slice(&unit.to_le_bytes());
        }
    }
    field
}

/// A stored file under a two-part name: `fallback` beside the encoded
/// `name`, written by host 1 (Unix) or 0 (Win32).
fn unicode_file(fallback: &str, name: &str, data: &str, host: u64) -> Member {
    unicode_units(
        fallback,
        &name.encode_utf16().collect::<Vec<_>>(),
        data,
        host,
    )
}

fn unicode_units(fallback: &str, units: &[u16], data: &str, host: u64) -> Member {
    Member::Field4 {
        field: two_part(fallback.as_bytes(), units),
        data: data.as_bytes().to_vec(),
        host,
        link: false,
    }
}

/// A Unix symbolic link under a two-part name, its target as UTF-8 bytes.
fn unicode_link(fallback: &str, name: &str, target: &str) -> Member {
    Member::Field4 {
        field: two_part(
            fallback.as_bytes(),
            &name.encode_utf16().collect::<Vec<_>>(),
        ),
        data: target.as_bytes().to_vec(),
        host: 1,
        link: true,
    }
}

/// A name field taken as it stands under flag 0x0200: the fallback is the
/// name when nothing after it decodes (spec F 3.3.7 N10).
fn field_only(field: &[u8]) -> Member {
    Member::Field4 {
        field: field.to_vec(),
        data: b"PWNED by a fallback name".to_vec(),
        host: 0,
        link: false,
    }
}

/// The RAR 4 rows whose names are NOT ASCII, carried by the two-part name
/// of spec F 3.3.7: brief 3's forms with non-ASCII names, a hostile name in
/// either part with a harmless one in the other, characters that look like
/// a separator, a dot or a colon, the encoding's edges (a zero unit, a lone
/// surrogate, a pair), and brief 2 as Unix symbolic links under such names.
pub fn rows_rar4_unicode(escaped: &str, drive: char) -> Vec<(&'static str, Vec<Member>)> {
    let unc = format!("\\\\localhost\\{drive}${}", &escaped[2..]);
    let pwned = "PWNED by a non-ASCII name";
    let units = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    let joined = |parts: &[&[u16]]| parts.concat();
    vec![
        (
            "r4u-b3-climbs",
            vec![
                unicode_file("plain.txt", "plain-\u{fc}.txt", "kept", 0),
                unicode_file("s1.txt", "..\\..\\..\\escaped\\\u{fc}-climb.txt", pwned, 0),
                unicode_file("s2.txt", "../../../escaped/\u{fc}-slash.txt", pwned, 1),
                unicode_file("s3.txt", &format!("{escaped}\\\u{fc}-abs.txt"), pwned, 0),
                unicode_file(
                    "s4.txt",
                    &format!("\\\\?\\{escaped}\\\u{fc}-verbatim.txt"),
                    pwned,
                    0,
                ),
                unicode_file(
                    "s5.txt",
                    &format!("\\\\.\\{escaped}\\\u{fc}-device.txt"),
                    pwned,
                    0,
                ),
                unicode_file("s6.txt", &format!("{unc}\\\u{fc}-unc.txt"), pwned, 0),
                unicode_file(
                    "s7.txt",
                    &format!("{drive}:..\\..\\..\\escaped\\\u{fc}-drive.txt"),
                    pwned,
                    0,
                ),
                unicode_file(
                    "s8.txt",
                    "\u{fc}\\..\\..\\..\\..\\escaped\\\u{fc}-inner.txt",
                    pwned,
                    0,
                ),
                unicode_file("s9.txt", "\\\u{fc}-rooted.txt", pwned, 0),
            ],
        ),
        (
            "r4u-b3-hostile-fallback",
            vec![
                unicode_file("..\\..\\..\\escaped\\fb1.txt", "\u{fc}-fb1.txt", "fb1", 0),
                unicode_file(&format!("{escaped}\\fb2.txt"), "\u{fc}-fb2.txt", "fb2", 0),
                unicode_file(
                    &format!("{drive}:..\\..\\..\\escaped\\fb3.txt"),
                    "\u{fc}-fb3.txt",
                    "fb3",
                    0,
                ),
            ],
        ),
        (
            "r4u-b3-fallback-only",
            vec![
                file("plain.txt", "kept"),
                field_only(b"..\\..\\..\\escaped\\fo1.txt"),
                field_only(b"..\\..\\..\\escaped\\fo2.txt\0"),
                field_only(b"..\\..\\..\\escaped\\fo3.txt\0\0"),
                field_only(format!("{escaped}\\fo4.txt\0").as_bytes()),
            ],
        ),
        (
            "r4u-b3-lookalikes",
            vec![
                unicode_file(
                    "l1.txt",
                    "\u{ff0e}\u{ff0e}\u{ff3c}\u{ff0e}\u{ff0e}\u{ff3c}\u{ff0e}\u{ff0e}\u{ff3c}escaped\u{ff3c}fw.txt",
                    "fullwidth",
                    0,
                ),
                unicode_file(
                    "l2.txt",
                    "..\u{2215}..\u{2215}..\u{2215}escaped\u{2215}div.txt",
                    "division slash",
                    0,
                ),
                unicode_file(
                    "l3.txt",
                    "..\u{2216}..\u{2216}..\u{2216}escaped\u{2216}minus.txt",
                    "set minus",
                    0,
                ),
                unicode_file(
                    "l4.txt",
                    "..\u{a5}..\u{a5}..\u{a5}escaped\u{a5}yen.txt",
                    "yen",
                    0,
                ),
                unicode_file(
                    "l5.txt",
                    "..\u{20a9}..\u{20a9}..\u{20a9}escaped\u{20a9}won.txt",
                    "won",
                    0,
                ),
                unicode_file(
                    "l6.txt",
                    "..\u{2044}..\u{2044}..\u{2044}escaped\u{2044}frac.txt",
                    "fraction slash",
                    0,
                ),
                unicode_file(
                    "l7.txt",
                    "\u{2024}\u{2024}\\\u{2024}\u{2024}\\\u{2024}\u{2024}\\escaped\\leader.txt",
                    "one dot leader",
                    0,
                ),
                unicode_file("l8.txt", "ads\u{ff1a}evil.txt", "fullwidth colon", 0),
            ],
        ),
        (
            "r4u-b3-ads",
            vec![
                unicode_file("a1.txt", "\u{fc}-ads.txt:evil", "stream", 0),
                unicode_file("a2.txt", "\u{fc}:evil", "stream", 0),
                unicode_file(
                    "a3.txt",
                    "\u{fc}\\..\\..\\..\\..\\escaped\\canary.txt:evil",
                    pwned,
                    0,
                ),
                unicode_file("a4.txt", &format!("{drive}:\u{fc}-canary.txt:evil"), "drive", 0),
            ],
        ),
        (
            "r4u-b3-devices",
            vec![
                unicode_file("d1", "COM\u{b9}", "device", 0),
                unicode_file("d2.txt", "LPT\u{b3}.txt", "device", 0),
                unicode_file("d3", "CON.\u{fc}", "device", 0),
                unicode_file("d4", "nul.\u{fc}", "device", 0),
                unicode_file("d5", "\u{fc}\\PRN", "device", 0),
            ],
        ),
        (
            "r4u-b3-trailing",
            vec![
                unicode_file("t1", "\u{fc}", "plain", 0),
                unicode_file("t2", "\u{fc}.", "dot", 0),
                unicode_file("t3", "\u{fc} ", "space", 0),
                unicode_file("t4", "\u{fc}-d.\\x.txt", "dotted dir", 0),
                unicode_file("t5", "\u{fc}-d\\x.txt", "plain dir", 0),
            ],
        ),
        (
            "r4u-encoding-edges",
            vec![
                unicode_units(
                    "e1.txt",
                    &joined(&[&units("safe"), &[0], &units("..\\..\\..\\escaped\\zero.txt")]),
                    "cut at the zero unit",
                    0,
                ),
                unicode_units(
                    "e2.txt",
                    &joined(&[&units("\u{fc}"), &[0xD800], &units(".txt")]),
                    "lone surrogate",
                    0,
                ),
                unicode_file("e3.txt", "\u{1F600}.txt", "pair", 0),
                unicode_units(
                    "..\\..\\..\\escaped\\e4.txt",
                    &joined(&[&[0], &units("x.txt")]),
                    pwned,
                    0,
                ),
                unicode_units(
                    "e5.txt",
                    &joined(&[&units(".."), &[0xD800], &units("\\..\\..\\..\\escaped\\sur.txt")]),
                    pwned,
                    0,
                ),
            ],
        ),
        (
            "r4u-b2-unix-links",
            vec![
                unicode_link("i", "inside-\u{fc}", "plain-\u{fc}"),
                unicode_file("k", "plain-\u{fc}/kept.txt", "a real directory", 1),
                unicode_link("l", "lnk-\u{fc}", "..\\..\\..\\escaped"),
                unicode_file(
                    "c",
                    &format!("lnk-\u{fc}/{CANARY}"),
                    "PWNED through a climbing link",
                    1,
                ),
                unicode_link("m", "lnk2-\u{fc}", escaped),
                unicode_file(
                    "d",
                    &format!("lnk2-\u{fc}\\{CANARY}"),
                    "PWNED through an absolute link",
                    0,
                ),
                unicode_link("n", "climb-\u{fc}", "../../../escaped/\u{fc}"),
            ],
        ),
    ]
}

/// Every row: its tag and its members. `escaped` is the canary directory
/// as an absolute Windows path (`F:\root\escaped`), and `drive` its drive
/// letter.
pub fn rows(escaped: &str, drive: char) -> Vec<(&'static str, Vec<Member>)> {
    let canary = format!("{escaped}\\{CANARY}");
    let unc_local = format!(
        "\\\\localhost\\{drive}${}",
        escaped.get(2..).unwrap_or_default()
    );
    let verbatim = format!("\\\\?\\{escaped}");
    let device = format!("\\\\.\\{escaped}");
    let nt = format!("\\??\\{escaped}");
    let climb = "..\\..\\..\\escaped";
    let climb_slash = "../../../escaped";
    vec![
        // BRIEF 3: alternate data streams.
        (
            "b3-ads",
            vec![
                file("ads.txt:evil", "stream named evil"),
                file("ads2.txt::$DATA", "default stream spelled out"),
                file(
                    "dir:$I30:$INDEX_ALLOCATION/inner.txt",
                    "directory index stream",
                ),
                file(":lead", "a name that is only a stream"),
                file(&format!("{climb}\\{CANARY}:evil"), "climbing stream"),
                file(&format!("{canary}:evil"), "absolute stream"),
                file(&format!("{drive}:{CANARY}:evil"), "drive-relative stream"),
            ],
        ),
        // BRIEF 3: reserved device names, bare, with an extension, nested.
        (
            "b3-devices",
            vec![
                file("CON", "con"),
                file("nul.txt", "nul with an extension"),
                file("COM1.log", "com1 with an extension"),
                file("lpt9", "lpt9 lower case"),
                file("AUX .txt", "aux with a space before the dot"),
                file("sub/PRN.x.y", "prn nested, two extensions"),
                file("CONIN$", "conin"),
                file("CONOUT$", "conout"),
                file("COM\u{b9}", "com superscript one"),
                file("LPT\u{b3}.txt", "lpt superscript three"),
                file("con.", "con with a trailing dot"),
                file("nul ", "nul with a trailing space"),
            ],
        ),
        // BRIEF 3: absolute, UNC, device namespace and climbing forms, Unix
        // host (a `\` is a separator to Windows).
        (
            "b3-absolute-unix-host",
            vec![
                file("plain.txt", "benign"),
                file(
                    &format!("{escaped}\\abs-backslash.txt"),
                    "absolute backslash",
                ),
                file(
                    &format!("{}/abs-slash.txt", escaped.replace('\\', "/")),
                    "absolute slash",
                ),
                file(&format!("{unc_local}\\unc.txt"), "unc"),
                file(&format!("{verbatim}\\verbatim.txt"), "verbatim"),
                file(&format!("{device}\\device.txt"), "device namespace"),
                file(&format!("{nt}\\nt.txt"), "nt namespace"),
                file(&format!("{climb}\\climb-backslash.txt"), "climb backslash"),
                file(&format!("{climb_slash}/climb-slash.txt"), "climb slash"),
                file("a\\..\\..\\..\\..\\escaped\\inner-climb.txt", "inner climb"),
                file(
                    &format!("{drive}:..\\..\\..\\escaped\\drive-climb.txt"),
                    "drive climb",
                ),
                file("\\rooted.txt", "rooted"),
                file("\\\\.\\NUL", "device nul"),
            ],
        ),
        // The same forms written by a Windows host.
        (
            "b3-absolute-windows-host",
            vec![
                windows_file("plain.txt", "benign"),
                windows_file(
                    &format!("{escaped}\\abs-backslash.txt"),
                    "absolute backslash",
                ),
                windows_file(&format!("{unc_local}\\unc.txt"), "unc"),
                windows_file(&format!("{verbatim}\\verbatim.txt"), "verbatim"),
                windows_file(&format!("{climb}\\climb-backslash.txt"), "climb backslash"),
                windows_file(&format!("{climb_slash}/climb-slash.txt"), "climb slash"),
                windows_file("\\rooted.txt", "rooted"),
            ],
        ),
        // BRIEF 3: trailing dots and spaces that Win32 strips; each pair
        // differs only by that, the safe one first.
        (
            "b3-trailing",
            vec![
                file("t", "plain t"),
                file("t.", "t with a dot"),
                file("t ", "t with a space"),
                file("u. ", "u dot space"),
                file("u .", "u space dot"),
                file("v...", "v three dots"),
                file("w./x.txt", "inside a dotted directory"),
                file("w/x.txt", "inside the plain directory"),
            ],
        ),
        // BRIEF 2, Windows forms: symbolic links whose target leaves.
        (
            "b2-winlink-targets",
            vec![
                link("abs", 2, escaped, true),
                link("abs-file", 2, &canary, false),
                link("climb", 2, climb, true),
                link("climb-slash", 2, climb_slash, true),
                link("verbatim", 2, &verbatim, true),
                link("device", 2, &device, true),
                link("nt", 2, &nt, true),
                link("unc", 2, &unc_local, true),
                link(
                    "drive-rel",
                    2,
                    &format!("{drive}:..\\..\\..\\escaped"),
                    true,
                ),
                link("devnul", 2, "\\\\.\\NUL", false),
                link("nul", 2, "NUL", false),
                link("inside", 2, "plain-dir", true),
                file("plain-dir/kept.txt", "a real directory the safe link names"),
            ],
        ),
        // BRIEF 2, Windows forms: a link, then a file written through it.
        (
            "b2-write-through",
            vec![
                link("abs", 2, escaped, true),
                file(&format!("abs/{CANARY}"), "PWNED through an absolute link"),
                link("climb", 2, climb, true),
                file(&format!("climb/{CANARY}"), "PWNED through a climbing link"),
                link("j", 3, &nt, true),
                file(&format!("j/{CANARY}"), "PWNED through a junction"),
                link("a", 2, ".", true),
                link("a/b", 2, "..", true),
                file("a/b/sibling.txt", "PWNED through a chain of links"),
            ],
        ),
        // BRIEF 2, Windows forms: junctions.
        (
            "b2-junctions",
            vec![
                link("j-nt", 3, &nt, true),
                link(
                    "j-slash",
                    3,
                    &format!("/??/{}", escaped.replace('\\', "/")),
                    true,
                ),
                link("j-climb", 3, climb, true),
                link("j-inside", 3, "plain-dir", true),
                file("plain-dir/kept.txt", "a real directory"),
            ],
        ),
        // BRIEF 2, Windows forms: hard links and file copies whose target is
        // outside, then a member written over the hard link.
        (
            "b2-hard-and-copy",
            vec![
                file("first.txt", "an earlier member"),
                link("h-abs", 4, &canary, false),
                link("h-climb", 4, &format!("{climb}\\{CANARY}"), false),
                link("h-verbatim", 4, &format!("{verbatim}\\{CANARY}"), false),
                link("h-good", 4, "first.txt", false),
                link("c-abs", 5, &canary, false),
                link("c-climb", 5, &format!("{climb}\\{CANARY}"), false),
                link("c-good", 5, "first.txt", false),
                file("h-abs", "PWNED over a hard link"),
                file("h-climb", "PWNED over a hard link"),
            ],
        ),
    ]
}
