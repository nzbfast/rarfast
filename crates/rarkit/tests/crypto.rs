//! Spec K end to end: the committed RAR 5 vectors (`specs/vectors-K`),
//! and differential tests against the old engine through `rarkit-oracle`.
//!
//! Spec K section 6's differential plan in full, now that the adapters
//! it names exist: both key derivations' material against
//! `rar5_keys` / `rar5_keys_check_record` / `rar4_key_iv`, the three
//! legacy ciphers against `legacy_decrypt`, whole archives (including
//! header-encrypted ones, which `extract` now takes a password for)
//! against `extract`, and the old engine's own encrypted fixture corpus
//! through `fixture_names` / `fixture` / `fixture_password`, listed
//! against `list`.
// The exporter cut the cases of this file that need a crate this tree
// does not have; imports and helpers only they used are left in place.
#![allow(unused_imports, dead_code, unused_macros)]

#[path = "support/rarwalk.rs"]
mod rarwalk;

use rarkit::internals::crypto::*;
use rarkit::{ErrorKind, Password, Unsupported};
use rarwalk::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-K");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap()
}

fn secret() -> Password {
    Password::from("Secret")
}

type Members = Vec<(Vec<u8>, Vec<u8>)>;

fn ours(members: Vec<(Vec<u8>, Vec<u8>, bool)>) -> Vec<(Vec<u8>, Vec<u8>)> {
    members
        .into_iter()
        .map(|(n, d, ok)| {
            assert!(ok, "checksum of {}", String::from_utf8_lossy(&n));
            (n, d)
        })
        .collect()
}

#[test]
fn rar5_mac_and_pad_facts() {
    let arc = read("r5_p_m0_crc.rar");
    let mut cache = KeyCache::new(None);
    let frags = walk5(&arc, None, &mut cache).unwrap();
    let hello = &frags[0];
    assert_eq!(hello.crc, Some(0x7F0D_EE3E));
    assert_eq!(hello.data.len(), 32);
    let rec = Rar5Record::parse(hello.record.as_ref().unwrap(), true).unwrap();
    assert_eq!(rec.flags, 0x0003);
    let keys = Rar5Keys::derive(b"Secret", &rec.salt, rec.log2, None).unwrap();
    let mut d = MemberDecryptor::new(MemberCipher::aes256(&keys, rec.iv.as_ref().unwrap()));
    let mut buf = arc[hello.data.clone()].to_vec();
    assert_eq!(d.update(&mut buf).body, 32);
    assert_eq!(&buf[27..], &[0u8; 5], "the pad is zero bytes");
    assert_eq!(frags[1].crc, Some(0x8524_593E));
}

#[test]
fn rar5_chunking_invariance_across_volumes() {
    let parts: Vec<Vec<u8>> = (1..=3)
        .map(|i| read(&format!("r5_p_vol.part{i}.rar")))
        .collect();
    let mut cache = KeyCache::new(None);
    let mut cipher_bytes = Vec::new();
    let mut rec = None;
    for p in &parts {
        for f in walk5(p, None, &mut cache).unwrap() {
            rec.get_or_insert(f.record.clone().unwrap());
            cipher_bytes.push(p[f.data.clone()].to_vec());
        }
    }
    let rec = Rar5Record::parse(rec.as_ref().unwrap(), true).unwrap();
    let keys = cache.rar5(&secret(), &rec.salt, rec.log2).unwrap().clone();
    let want = read("in/data.bin");
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..50 {
        let mut d = MemberDecryptor::new(MemberCipher::aes256(&keys, rec.iv.as_ref().unwrap()));
        let mut out = Vec::new();
        for frag in &cipher_bytes {
            d.next_fragment();
            let mut at = 0;
            while at < frag.len() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let n = (1 + (x % 5000) as usize).min(frag.len() - at);
                let mut buf = frag[at..at + n].to_vec();
                let got = d.update(&mut buf);
                out.extend_from_slice(got.head);
                out.extend_from_slice(&buf[..got.body]);
                at += n;
            }
        }
        d.finish().unwrap();
        out.truncate(want.len());
        assert_eq!(out, want);
    }
}

/// `vectors-K/README.md`: rewrite the exponent byte of hello.txt's record
/// in `r5_p_m0_blake.rar` and re-stamp the header CRC.
fn blake_with_exponent(log2: u8) -> Vec<u8> {
    let mut arc = read("r5_p_m0_blake.rar");
    assert_eq!(arc[56], 15);
    arc[56] = log2;
    let crc = crc32(&arc[27..147]);
    arc[23..27].copy_from_slice(&crc.to_le_bytes());
    arc
}

#[test]
#[ignore = "runs 2^24 + 32 HMAC iterations, about 5 s"]
fn rar5_exponent_24_is_a_wrong_password() {
    let arc = blake_with_exponent(24);
    let err = extract5_stored(&[&arc], &secret()).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::WrongPassword));
}

/// Spec K 3.7.3 step 1: a check record that fails its own checksum is
/// treated as absent, and the member's own checksum judges it. (This row
/// asserted `Corrupt` until the evidence pass of 6 Oct 2026 found the
/// reference tests such an archive "All OK".)
#[test]
fn rar5_damaged_check_record_is_treated_as_absent() {
    // Flip a check byte inside hello.txt's record and re-stamp the header.
    let mut arc = read("r5_p_m0_blake.rar");
    let mut cache = KeyCache::new(None);
    let f = &walk5(&arc, None, &mut cache).unwrap()[0];
    let rec = f.record.clone().unwrap();
    let at = arc[23..147]
        .windows(rec.len())
        .position(|w| w == rec.as_slice())
        .unwrap()
        + 23;
    arc[at + rec.len() - 12] ^= 1;
    let crc = crc32(&arc[27..147]);
    arc[23..27].copy_from_slice(&crc.to_le_bytes());
    let whole = ours(extract5_stored(&[&read("r5_p_m0_blake.rar")], &secret()).unwrap());
    let got = ours(extract5_stored(&[&arc], &secret()).unwrap());
    assert_eq!(got, whole);
}

#[test]
fn rar5_key_cache_derives_once_for_a_volume_set() {
    let parts: Vec<Vec<u8>> = (1..=3)
        .map(|i| read(&format!("r5_p_vol.part{i}.rar")))
        .collect();
    let mut cache = KeyCache::new(None);
    for p in &parts {
        for f in walk5(p, None, &mut cache).unwrap() {
            let rec = Rar5Record::parse(f.record.as_ref().unwrap(), true).unwrap();
            cache.rar5(&secret(), &rec.salt, rec.log2).unwrap();
        }
    }
    assert_eq!(cache.derivations(), 1);
}

/// Spec K 3.7.7: ONE salt per archive. A RAR 5 archive this crate writes
/// with encrypted headers keys the archive encryption header and every
/// member from the same salt, so a reader walking it and keying every
/// member derives exactly once, as it does for an archive `rar` made
/// (an open item of 25 Sep 2026; the encrypted-rows research, 30 Sep
/// 2026). The writer drew a second salt for the headers until
/// then, and this count read 2.
#[test]
fn rar5_header_encrypted_write_keys_headers_and_members_from_one_salt() {
    let pw = Password::from("one salt");
    let bodies: Vec<Vec<u8>> = (0..5usize)
        .map(|i| (0..(i * 300 + 7)).map(|b| (b * 31 + i) as u8).collect())
        .collect();
    for workers in [1usize, 8] {
        let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
            method: rarkit::WriteMethod::Stored,
            password: Some(pw.clone()),
            encrypt_headers: true,
            entropy: rarkit::Entropy::Seeded([23; 32]),
            memory: rarkit::MemoryPolicy {
                max_workers: workers,
                ..Default::default()
            },
            ..rarkit::WriteOptions::default()
        })
        .expect("options");
        let names: Vec<String> = (0..bodies.len()).map(|i| format!("m{i}.bin")).collect();
        for (name, body) in names.iter().zip(&bodies) {
            writer
                .add(rarkit::MemberSpec {
                    name: name.as_bytes(),
                    payload: rarkit::Payload::Bytes(body),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut arc = Vec::new();
        writer.finish_into(&mut arc).expect("finish");

        let mut cache = KeyCache::new(None);
        let frags = walk5(&arc, Some(&pw), &mut cache).unwrap();
        assert_eq!(frags.len(), bodies.len(), "workers {workers}: members");
        assert_eq!(cache.derivations(), 1, "workers {workers}: the header key");
        for f in &frags {
            let rec = Rar5Record::parse(f.record.as_ref().unwrap(), true).unwrap();
            cache.rar5(&pw, &rec.salt, rec.log2).unwrap();
        }
        assert_eq!(
            cache.derivations(),
            1,
            "workers {workers}: a member's salt differs from the header's"
        );
        let got = extract5_stored(&[&arc], &pw).unwrap();
        assert_eq!(got.len(), bodies.len());
    }
}

// ---- Section 6's key-derivation differentials --------------------------------

/// A printable ASCII password of `n` bytes. Both derivations take bytes,
/// but the RAR 4 family's runs through UTF-16 re-encoding and the old
/// engine refuses a password that is not UTF-8 (`rar4_key_iv`'s rustdoc),
/// so the shared domain is text.
fn text_password(rng: &mut rarkit_testdata::Seeded, n: usize) -> String {
    (0..n)
        .map(|_| {
            let c = (rng.next_u64() % 94) as u8 + 33;
            char::from(c)
        })
        .collect()
}

/// rarkit's decrypt direction for the legacy cipher of `unpack_version`,
/// as `legacy_decrypt` names them (2, 15, 20).
fn legacy_ours(unpack_version: u8, password: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = ct.to_vec();
    match unpack_version {
        2 => Rar13Stream::new(password).decrypt(&mut out),
        15 => Rar15Stream::new(password).apply(&mut out),
        20 => Rar20Block::new(password).decrypt_blocks(&mut out),
        v => panic!("no legacy cipher for version {v}"),
    }
    out
}

// ---- Section 6's end-to-end differential over the old fork's fixtures -------

/// Group the corpus's volume sets: `x.part1.rar ...`, or old-style
/// `x.rar, x.r00, x.r01`, and everything else alone.
fn volume_sets(names: &[String]) -> Vec<(String, Vec<String>)> {
    let mut sets: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for n in names {
        let (stem, ext) = match n.rsplit_once('.') {
            Some(p) => p,
            None => continue,
        };
        let is_volume = ext.eq_ignore_ascii_case("rar")
            || (ext.len() == 3
                && ext.starts_with('r')
                && ext[1..].bytes().all(|b| b.is_ascii_digit()));
        if !is_volume {
            continue;
        }
        let stem = match stem.rsplit_once(".part") {
            Some((head, tail)) if tail.bytes().all(|b| b.is_ascii_digit()) => head.to_string(),
            _ => stem.to_string(),
        };
        sets.entry(stem).or_default().push(n.clone());
    }
    let mut out: Vec<(String, Vec<String>)> = sets.into_iter().collect();
    for (_, vols) in &mut out {
        vols.sort();
        // Old-style naming: the first volume is `.rar`, then `.r00`.
        if vols.len() > 1 && vols.iter().any(|v| v.ends_with(".r00")) {
            if let Some(i) = vols.iter().position(|v| v.ends_with(".rar")) {
                let first = vols.remove(i);
                vols.insert(0, first);
            }
        }
    }
    out
}

// ---- The table of spec K 5.1, for the standing test that draws from it -----
//
// The row tests of this table and of SPEC-API 4.5's stand in the lib tests
// (`src/crypto/tests.rs`), where a plain run reaches them.

const UNIT: [&str; 1] = ["unit-vectors/unit-vectors-7.23-macos-arm64.tsv"];

/// A table's rows under its heading, each as its fields.
fn table(name: &str) -> Vec<Vec<String>> {
    String::from_utf8(read(name))
        .unwrap()
        .lines()
        .skip(1)
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect()
}
