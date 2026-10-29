//! Test and bench support for spec K: a minimal RAR 5 header walker (from
//! RARLAB's public RAR 5.0 technote) and a builder and walker for stored
//! RAR 1.5 to 4.x archives, driving rarkit's crypto package end to end
//! until spec F's real walkers exist. Not a reader: it handles exactly the
//! structures the spec K vectors and the benches contain.
#![allow(dead_code)]

use std::ops::Range;

use rarkit::internals::crypto::*;
use rarkit::{ErrorKind, Format, Password, RangeSource, Unsupported};

/// Out of this walker's scope: it stores no codec and no name decoder, so
/// it refuses what it cannot deliver faithfully rather than returning
/// bytes it has not decoded. Spec F's real walkers and spec H's codecs
/// take these over.
pub fn out_of_scope(format: Format, code: u32) -> rarkit::Error {
    rarkit::Error::new(ErrorKind::Unsupported(Unsupported::Method { format, code }))
}

/// Whether `e` is an [`out_of_scope`] refusal.
pub fn is_out_of_scope(e: &rarkit::Error) -> bool {
    matches!(e.kind(), ErrorKind::Unsupported(Unsupported::Method { .. }))
}

/// (name, data, checksum ok) per member.
pub type Extracted = Vec<(Vec<u8>, Vec<u8>, bool)>;

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Where a member's plaintext goes: kept whole (extract) or streamed
/// through one reused 1 MiB buffer into the CRC (test).
pub struct Out {
    keep: bool,
    pub data: Vec<u8>,
    scratch: Vec<u8>,
    crc: crc32fast::Hasher,
    left: u64,
}

impl Out {
    pub fn new(keep: bool, unpacked: u64) -> Out {
        // Extract keeps one allocation per member (support code: capped).
        let cap = if keep {
            unpacked.min(1 << 30) as usize + 16
        } else {
            0
        };
        Out {
            keep,
            data: Vec::with_capacity(cap),
            scratch: Vec::new(),
            crc: crc32fast::Hasher::new(),
            left: unpacked,
        }
    }

    fn take(&mut self, pt_len: usize) -> usize {
        let n = (pt_len as u64).min(self.left) as usize;
        self.left -= n as u64;
        n
    }

    /// Decrypt `ct` through `dec` into this output.
    pub fn feed(&mut self, dec: &mut MemberDecryptor, ct: &[u8]) {
        if self.keep {
            // Room for the straddling block's head in front, so the
            // plaintext lands contiguous with no shift.
            let start = self.data.len();
            let k = dec.pending();
            self.data.resize(start + k, 0);
            self.data.extend_from_slice(ct);
            let got = dec.update(&mut self.data[start + k..]);
            let (h, body) = (got.head.len(), got.body);
            let head: [u8; 16] = {
                let mut b = [0u8; 16];
                b[..h].copy_from_slice(got.head);
                b
            };
            self.data[start..start + h].copy_from_slice(&head[..h]);
            let n = self.take(h + body);
            self.data.truncate(start + n);
            return;
        }
        self.scratch.resize(1 << 20, 0);
        for piece in ct.chunks(1 << 20) {
            let buf = &mut self.scratch[..piece.len()];
            buf.copy_from_slice(piece);
            let got = dec.update(buf);
            let n = self.take(got.head.len());
            self.crc.update(&got.head[..n]);
            let body = got.body;
            let n = self.take(body);
            self.crc.update(&self.scratch[..n]);
        }
    }

    /// Check the member ended on a block boundary; the CRC32 of the data.
    pub fn finish(self, dec: MemberDecryptor) -> rarkit::Result<(Vec<u8>, u32)> {
        dec.finish()?;
        if self.keep {
            let crc = crc32(&self.data);
            Ok((self.data, crc))
        } else {
            Ok((Vec::new(), self.crc.finalize()))
        }
    }
}

fn vint(b: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at).ok_or("vint past end")?;
        *at += 1;
        v |= u64::from(x & 0x7F) << shift;
        if x & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err("long vint".into())
}

fn u32le(b: &[u8], at: &mut usize) -> Result<u32, String> {
    let s = b.get(*at..*at + 4).ok_or("u32 past end")?;
    *at += 4;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// One file header of one RAR 5 volume.
#[derive(Debug, Clone)]
pub struct Frag5 {
    pub name: Vec<u8>,
    pub unpacked: u64,
    /// Compression method from the header's compression information
    /// (0 is stored); this walker decodes nothing else.
    pub method: u8,
    /// The header's solid bit.
    pub solid: bool,
    pub crc: Option<u32>,
    pub blake: Option<[u8; 32]>,
    pub record: Option<Vec<u8>>,
    pub data: Range<usize>,
    pub split_before: bool,
    pub split_after: bool,
}

/// Walk one RAR 5 volume. Encrypted headers are decrypted with
/// `password` through `cache` and judged against the archive record.
pub fn walk5(
    vol: &[u8],
    password: Option<&Password>,
    cache: &mut KeyCache,
) -> rarkit::Result<Vec<Frag5>> {
    let bad = |m: &str| -> rarkit::Error {
        let _ = m;
        rarkit::Error::new(ErrorKind::NotAnArchive)
    };
    if vol.get(..8) != Some(b"Rar!\x1a\x07\x01\x00") {
        return Err(bad("signature"));
    }
    let src: &dyn RangeSource = &vol;
    let mut pos = 8usize;
    let mut reader = HeaderReader::new();
    let mut hkeys: Option<Rar5Keys> = None;
    let mut out = Vec::new();
    loop {
        let (hdr, hdr_end): (Vec<u8>, usize) = match &hkeys {
            Some(keys) => {
                let span = reader.rar5(src, pos as u64, keys)?;
                (reader.plain().to_vec(), span.end as usize)
            }
            None => {
                let mut at = pos + 4;
                let size = vint(vol, &mut at).map_err(|e| bad(&e))? as usize;
                let end = at + size;
                let h = vol.get(pos..end).ok_or_else(|| bad("header past end"))?;
                (h.to_vec(), end)
            }
        };
        let mut at = 4;
        let size = vint(&hdr, &mut at).map_err(|e| bad(&e))? as usize;
        let body_end = at + size;
        let ty = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
        let flags = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
        let extra = if flags & 1 != 0 {
            vint(&hdr, &mut at).map_err(|e| bad(&e))? as usize
        } else {
            0
        };
        let data_size = if flags & 2 != 0 {
            vint(&hdr, &mut at).map_err(|e| bad(&e))? as usize
        } else {
            0
        };
        let data = hdr_end..hdr_end + data_size;
        match ty {
            4 => {
                let rec = Rar5Record::parse(&hdr[at..body_end], false)?;
                let pw = password.ok_or_else(|| rarkit::Error::new(ErrorKind::PasswordRequired))?;
                let keys = cache.rar5(pw, &rec.salt, rec.log2)?.clone();
                if let Some(check) = &rec.check {
                    keys.judge_record(check)?;
                }
                hkeys = Some(keys);
            }
            2 | 3 => {
                let file_flags = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
                let unpacked = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
                let _attr = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
                if file_flags & 2 != 0 {
                    at += 4;
                }
                let crc = if file_flags & 4 != 0 {
                    Some(u32le(&hdr, &mut at).map_err(|e| bad(&e))?)
                } else {
                    None
                };
                let comp = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
                let _os = vint(&hdr, &mut at).map_err(|e| bad(&e))?;
                let nlen = vint(&hdr, &mut at).map_err(|e| bad(&e))? as usize;
                let name = hdr.get(at..at + nlen).ok_or_else(|| bad("name"))?.to_vec();
                let mut frag = Frag5 {
                    name,
                    unpacked,
                    method: ((comp >> 7) & 7) as u8,
                    solid: comp & 0x40 != 0,
                    crc,
                    blake: None,
                    record: None,
                    data: data.clone(),
                    split_before: flags & 0x08 != 0,
                    split_after: flags & 0x10 != 0,
                };
                let mut e = body_end - extra;
                while e < body_end {
                    let rsize = vint(&hdr, &mut e).map_err(|x| bad(&x))? as usize;
                    let rstart = e;
                    let rtype = vint(&hdr, &mut e).map_err(|x| bad(&x))?;
                    let rend = rstart + rsize;
                    let body = hdr.get(e..rend).ok_or_else(|| bad("extra"))?;
                    match rtype {
                        1 => frag.record = Some(body.to_vec()),
                        2 if body.first() == Some(&0) && body.len() == 33 => {
                            frag.blake = Some(body[1..].try_into().unwrap());
                        }
                        _ => {}
                    }
                    e = rend;
                }
                if ty == 2 {
                    out.push(frag);
                }
            }
            5 => return Ok(out),
            _ => {}
        }
        pos = data.end;
        if pos >= vol.len() {
            return Ok(out);
        }
    }
}

/// Extract every file member of a RAR 5 volume set whose data is stored
/// (method 0): decrypt through one `MemberDecryptor` per member across its
/// fragments, cut to the unpacked size, and check the checksum (MAC
/// converted when the record says so). Returns (name, data, checksum ok).
pub fn extract5_stored(vols: &[&[u8]], password: &Password) -> rarkit::Result<Extracted> {
    stored5(vols, password, true)
}

/// `extract5_stored`, or with `keep` false the test form: data dropped,
/// checksums still judged.
pub fn stored5(vols: &[&[u8]], password: &Password, keep: bool) -> rarkit::Result<Extracted> {
    let mut cache = KeyCache::new(None);
    let mut out = Vec::new();
    let mut open: Option<(Frag5, MemberDecryptor, Out, Option<Rar5Keys>)> = None;
    for vol in vols {
        for frag in walk5(vol, Some(password), &mut cache)? {
            if frag.method != 0 || frag.solid {
                return Err(out_of_scope(Format::Rar5, u32::from(frag.method)));
            }
            let (head, mut dec, mut buf, keys) = match open.take() {
                Some(mut o) if frag.split_before => {
                    o.1.next_fragment();
                    o.0 = frag.clone();
                    o
                }
                _ => {
                    let (cipher, keys) = match &frag.record {
                        Some(r) => {
                            let rec = Rar5Record::parse(r, true)?;
                            let keys = cache.rar5(password, &rec.salt, rec.log2)?.clone();
                            if let Some(check) = &rec.check {
                                keys.judge_record(check)?;
                            }
                            let mac = rec.mac();
                            (
                                MemberCipher::aes256(&keys, rec.iv.as_ref().unwrap()),
                                mac.then_some(keys),
                            )
                        }
                        None => (MemberCipher::None, None),
                    };
                    (
                        frag.clone(),
                        MemberDecryptor::new(cipher),
                        Out::new(keep, frag.unpacked),
                        keys,
                    )
                }
            };
            buf.feed(&mut dec, &vol[frag.data.clone()]);
            if frag.split_after {
                open = Some((head, dec, buf, keys));
                continue;
            }
            let (buf, plain_crc) = buf.finish(dec)?;
            // The FINAL fragment's record decides the MAC (3.7.6).
            let keys = match &head.record {
                Some(r) if Rar5Record::parse(r, true)?.mac() => keys.or_else(|| {
                    let rec = Rar5Record::parse(r, true).ok()?;
                    cache.rar5(password, &rec.salt, rec.log2).ok().cloned()
                }),
                _ => None,
            };
            let ok = match (head.crc, head.blake, &keys) {
                (Some(c), _, Some(k)) => k.stored_word_under_key(plain_crc) == c,
                (Some(c), _, None) => plain_crc == c,
                (None, Some(_), _) => true,
                (None, None, _) => true,
            };
            out.push((head.name, buf, ok));
        }
    }
    Ok(out)
}

// ---- RAR 1.5 to 4.x ---------------------------------------------------------

pub const MARK4: &[u8] = b"Rar!\x1a\x07\x00";

fn stamp4(mut h: Vec<u8>) -> Vec<u8> {
    let size = h.len() as u16;
    h[5..7].copy_from_slice(&size.to_le_bytes());
    let crc = crc32(&h[2..]) as u16;
    h[..2].copy_from_slice(&crc.to_le_bytes());
    h
}

/// A RAR 1.5 to 4.x archive of stored members, each encrypted with the
/// cipher `unpack_version` selects (15, 20 or 29; 29 salted with `salt`).
/// With `encrypt_headers` (29 only), every block after the main header is
/// `salt | AES-128-CBC(header)`.
pub fn build4(
    members: &[(&[u8], &[u8])],
    password: &[u8],
    unpack_version: u8,
    salt: [u8; 8],
    encrypt_headers: bool,
) -> Vec<u8> {
    let mut out = MARK4.to_vec();
    let main_flags: u16 = if encrypt_headers { 0x0080 } else { 0 };
    let mut main = vec![0, 0, 0x73];
    main.extend_from_slice(&main_flags.to_le_bytes());
    main.extend_from_slice(&[0; 2]);
    main.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&stamp4(main));
    let key = (unpack_version >= 29).then(|| Rar4Key::derive(password, Some(salt)).unwrap());
    let put_header = |out: &mut Vec<u8>, h: Vec<u8>| {
        if encrypt_headers {
            let key = key.as_ref().unwrap();
            let mut padded = h;
            padded.resize(padded.len().div_ceil(16) * 16, 0);
            rar4_encrypt_header(key, &mut padded).unwrap();
            out.extend_from_slice(&salt);
            out.extend_from_slice(&padded);
        } else {
            out.extend_from_slice(&h);
        }
    };
    for &(name, data) in members {
        let (name, data): (&[u8], &[u8]) = (name, data);
        let mut packed = data.to_vec();
        match unpack_version {
            15 => Rar15Stream::new(password).apply(&mut packed),
            20 => {
                packed.resize(packed.len().div_ceil(16) * 16, 0);
                Rar20Block::new(password).encrypt_blocks(&mut packed);
            }
            _ => {
                packed.resize(packed.len().div_ceil(16) * 16, 0);
                Aes128Enc::new(key.as_ref().unwrap())
                    .encrypt(&mut packed)
                    .unwrap();
            }
        }
        let mut flags: u16 = 0x8000 | 0x0004;
        if unpack_version >= 29 {
            flags |= 0x0400;
        }
        let mut h = vec![0, 0, 0x74];
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&[0; 2]);
        h.extend_from_slice(&(<[u8]>::len(&packed) as u32).to_le_bytes());
        h.extend_from_slice(&(<[u8]>::len(data) as u32).to_le_bytes());
        h.push(2); // host OS: Win32
        h.extend_from_slice(&crc32(data).to_le_bytes());
        h.extend_from_slice(&0x5A21_0000u32.to_le_bytes()); // DOS time
        h.push(unpack_version);
        h.push(0x30); // stored
        h.extend_from_slice(&(<[u8]>::len(name) as u16).to_le_bytes());
        h.extend_from_slice(&0x20u32.to_le_bytes());
        h.extend_from_slice(name);
        if unpack_version >= 29 {
            h.extend_from_slice(&salt);
        }
        put_header(&mut out, stamp4(h));
        out.extend_from_slice(&packed);
    }
    put_header(&mut out, stamp4(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0]));
    out
}

/// Walk and extract a `build4` archive (stored members) with rarkit's
/// crypto package: (name, data, CRC32 ok).
pub fn extract4_stored(arc: &[u8], password: &Password) -> rarkit::Result<Extracted> {
    stored4(arc, password, true)
}

/// `extract4_stored`, or with `keep` false the test form.
pub fn stored4(arc: &[u8], password: &Password, keep: bool) -> rarkit::Result<Extracted> {
    let src: &dyn RangeSource = &arc;
    let mut cache = KeyCache::new(None);
    let mut reader = HeaderReader::new();
    let bad = || rarkit::Error::new(ErrorKind::NotAnArchive);
    if arc.get(..7) != Some(MARK4) {
        return Err(bad());
    }
    let main_size = usize::from(u16::from_le_bytes([arc[12], arc[13]]));
    let encrypted = u16::from_le_bytes([arc[10], arc[11]]) & 0x0080 != 0;
    let mut pos = 7 + main_size;
    let mut out = Vec::new();
    while pos < arc.len() {
        let (h, data_at) = if encrypted {
            let span = reader.rar4(src, pos as u64, password, &mut cache)?;
            (reader.plain().to_vec(), span.end as usize)
        } else {
            let size = usize::from(u16::from_le_bytes([arc[pos + 5], arc[pos + 6]]));
            (arc[pos..pos + size].to_vec(), pos + size)
        };
        let flags = u16::from_le_bytes([h[3], h[4]]);
        let add = if flags & 0x8000 != 0 {
            u32::from_le_bytes(h[7..11].try_into().unwrap()) as usize
        } else {
            0
        };
        if h[2] == 0x7B {
            break;
        }
        if h[2] == 0x74 {
            // Stored members with a plain name, whole, under 4 GiB: the
            // only shape this walker delivers faithfully.
            if h[25] != 0x30 {
                return Err(out_of_scope(Format::Rar4Family, u32::from(h[25])));
            }
            if flags & (0x0001 | 0x0002 | 0x0100 | 0x0200) != 0 {
                return Err(out_of_scope(Format::Rar4Family, u32::from(flags)));
            }
            let unp = u32::from_le_bytes(h[11..15].try_into().unwrap()) as usize;
            let crc = u32::from_le_bytes(h[16..20].try_into().unwrap());
            let ver = h[24];
            let nlen = usize::from(u16::from_le_bytes([h[26], h[27]]));
            let name = h[32..32 + nlen].to_vec();
            let salt = (flags & 0x0400 != 0)
                .then(|| <[u8; 8]>::try_from(&h[32 + nlen..40 + nlen]).unwrap());
            let key = if ver >= 29 {
                Some(cache.rar4(password, salt)?.clone())
            } else {
                None
            };
            let cipher = rar4_family_cipher(ver, password.as_bytes(), key.as_ref())?;
            let mut dec = MemberDecryptor::new(cipher);
            let mut o = Out::new(keep, unp as u64);
            o.feed(&mut dec, &arc[data_at..data_at + add]);
            let (buf, got) = o.finish(dec)?;
            let ok = got == crc;
            out.push((name, buf, ok));
        }
        pos = data_at + add;
    }
    Ok(out)
}

/// One member header of a RAR 1.5 to 4.x archive: enough to compare a
/// member LIST with the old engine's, without decoding any data.
#[derive(Debug, Clone)]
pub struct Entry4 {
    /// The name exactly as stored (an encoded unicode name is not decoded
    /// here: that is spec F's).
    pub name: Vec<u8>,
    /// The unpacked size from the header.
    pub unpacked: u64,
    /// The method byte (0x30 is stored).
    pub method: u8,
    /// The member flags word.
    pub flags: u16,
    /// The unpack version byte.
    pub version: u8,
    /// Whether the header's attribute bits mark a directory.
    pub is_dir: bool,
}

impl Entry4 {
    /// Whether the name field holds an encoded unicode name (flag 0x0200).
    pub fn unicode_name(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

/// List the members of a RAR 1.5 to 4.x archive, decrypting its headers
/// through rarkit's crypto package (3.6.3) when the main header says they
/// are encrypted. No member data is read, so a compressed member is
/// listed like any other.
pub fn list4(arc: &[u8], password: &Password) -> rarkit::Result<Vec<Entry4>> {
    let src: &dyn RangeSource = &arc;
    let mut cache = KeyCache::new(None);
    let mut reader = HeaderReader::new();
    let bad = || rarkit::Error::new(ErrorKind::NotAnArchive);
    if arc.get(..7) != Some(MARK4) {
        return Err(bad());
    }
    let main_size = usize::from(u16::from_le_bytes([arc[12], arc[13]]));
    let encrypted = u16::from_le_bytes([arc[10], arc[11]]) & 0x0080 != 0;
    let mut pos = 7 + main_size;
    let mut out = Vec::new();
    while pos + 7 <= arc.len() {
        let (h, data_at) = if encrypted {
            let span = reader.rar4(src, pos as u64, password, &mut cache)?;
            (reader.plain().to_vec(), span.end as usize)
        } else {
            let size = usize::from(u16::from_le_bytes([arc[pos + 5], arc[pos + 6]]));
            let end = pos
                .checked_add(size)
                .filter(|e| *e <= arc.len())
                .ok_or_else(bad)?;
            (arc[pos..end].to_vec(), end)
        };
        if h.len() < 7 {
            return Err(bad());
        }
        let flags = u16::from_le_bytes([h[3], h[4]]);
        let add = if flags & 0x8000 != 0 {
            if h.len() < 11 {
                return Err(bad());
            }
            u32::from_le_bytes(h[7..11].try_into().unwrap()) as usize
        } else {
            0
        };
        if h[2] == 0x7B {
            break;
        }
        if h[2] == 0x74 {
            if h.len() < 32 {
                return Err(bad());
            }
            let nlen = usize::from(u16::from_le_bytes([h[26], h[27]]));
            let name = h.get(32..32 + nlen).ok_or_else(bad)?.to_vec();
            let attr = u32::from_le_bytes(h[28..32].try_into().unwrap());
            let mut unpacked = u64::from(u32::from_le_bytes(h[11..15].try_into().unwrap()));
            if flags & 0x0100 != 0 {
                // A 64-bit size: the high words follow the name.
                let at = 32 + nlen;
                let high = h.get(at + 4..at + 8).ok_or_else(bad)?;
                unpacked |= u64::from(u32::from_le_bytes(high.try_into().unwrap())) << 32;
            }
            out.push(Entry4 {
                name,
                unpacked,
                method: h[25],
                flags,
                version: h[24],
                // 0xE0 in the dictionary bits marks a directory.
                is_dir: flags & 0xE0 == 0xE0 || attr & 0x10 != 0,
            });
        }
        pos = data_at + add;
    }
    Ok(out)
}
