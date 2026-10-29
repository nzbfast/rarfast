//! Spec K section 5 vectors (and spec B 3.4), plus the behaviour of
//! section 3 and 4 that needs no archive. Archive-level tests, including
//! the differential ones, are in `tests/crypto.rs`.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use aes::cipher::{
    Array, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::legacy::S0;
use super::*;
use crate::checksum::CRC32_TABLE as T;
use crate::error::{ErrorKind, Unsupported};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

/// The check record `keys` writes (3.7.2), alone.
fn written_record(keys: &Rar5Keys) -> [u8; 12] {
    let mut body = Vec::new();
    keys.append_check_record(&mut body);
    body.try_into().expect("a check record is 12 bytes")
}

// ---- 3.1 ------------------------------------------------------------------

#[test]
fn crc_table_check_values() {
    assert_eq!(T[1], 0x7707_3096);
    assert_eq!(T[128], 0xEDB8_8320);
    assert_eq!(T[255], 0x2D02_EF8D);
}

// ---- 3.3 / 3.4 / 3.5 key setup and 5.1 unit vectors ------------------------

#[test]
fn rar20_s0_is_a_permutation() {
    let mut seen = [false; 256];
    for &x in &S0 {
        assert!(!seen[usize::from(x)]);
        seen[usize::from(x)] = true;
    }
}

// ---- 5.2 genuine legacy archives, first blocks ------------------------------

#[test]
fn legacy_genuine_first_blocks() {
    let cases: [(u8, &str, &str); 6] = [
        (
            13,
            "47 28 a3 5a 31 a8 f5 df 24 ed 44 f8 e5 a9 23 fe",
            "0e 7f ed fa 8a 1d e9 b5 3f b0 12 34 f2 ea fb d0",
        ),
        (
            13,
            "54 7f 30 ff 04 74 70 f3 25 cd c1 2d dd c3 25 bc",
            "1b d6 7a 9f 5d e9 64 c9 40 90 8f 69 ea 04 fd 8e",
        ),
        (
            15,
            "18 c7 fe f3 af 7b 08 b0 20 74 15 5b 60 9c 91 f9",
            "0e 7f ed fa 8a 1d e9 b5 3f b0 12 34 f2 ea fb d0",
        ),
        (
            15,
            "05 6e 69 96 78 8f 85 cd 51 a4 05 52 35 de 79 df",
            "13 d6 7a 9f 5d e9 64 c8 4e 60 02 3d a7 a8 13 f6",
        ),
        (
            20,
            "8c 6b b5 f7 33 c1 6b 56 20 f7 fd 6b 8d 74 ae 97",
            "11 54 00 00 11 15 55 54 05 52 5b 6d cd 4b 6d b6",
        ),
        (
            20,
            "1f 91 2a b3 1c fb f2 b6 27 3e 88 e9 50 e6 f5 4f",
            "00 40 00 00 00 00 00 00 00 05 ff ee dd 00 00 00",
        ),
    ];
    for (v, ct, pt) in cases {
        let cipher = match v {
            13 => MemberCipher::V13(Rar13Stream::new(b"Secret")),
            _ => rar4_family_cipher(v, b"Secret", None).unwrap(),
        };
        let mut d = MemberDecryptor::new(cipher);
        let mut buf = hex(ct);
        assert_eq!(d.update(&mut buf).body, 16);
        assert_eq!(buf, hex(pt), "v{v} {ct}");
    }
}

// ---- spec B 3.4 and spec K 5.3: the RAR 3 KDF and AES-128 -------------------

#[test]
fn rar4_kdf_rejects_non_utf8() {
    assert!(Rar4Key::derive(b"\xffpassword", None).is_err());
    let err = rar4_derive_read(b"\xffpassword", None, Astral::Low16).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::WrongPassword));
    let err = rar4_check_write_password(&Password::new(&b"\xffpassword"[..])).unwrap_err();
    assert!(matches!(
        err.kind(),
        ErrorKind::Unsupported(Unsupported::WriteFeature(_))
    ));
    // And any password that IS UTF-8 is taken by all three: letters and
    // digits, drawn once.
    let sound = b"yM8DTR";
    assert!(Rar4Key::derive(sound, None).is_ok());
    assert!(rar4_derive_read(sound, None, Astral::Low16).is_ok());
    assert!(rar4_check_write_password(&Password::new(&sound[..])).is_ok());
}

#[test]
fn rar4_unaligned_encrypt_refused() {
    let key = Rar4Key::derive(b"password", None).unwrap();
    let mut buf = [0u8; 15];
    assert!(Aes128Enc::new(&key).encrypt(&mut buf).is_err());
    assert_eq!(buf, [0u8; 15]);
    assert!(rar4_decrypt_header(&key, &mut buf).is_err());
}

#[test]
fn rar4_genuine_keys_and_first_blocks() {
    let cases = [
        (
            "81 0d 2d ef 75 c5 55 90",
            "66 5f aa 13 2a a5 a9 46 74 4a f8 ed cd 95 08 bd",
            "41 7b 0e fc af 9f a6 4a 51 16 63 20 6f 73 dd ce",
            "d5 71 0f 5a 78 0a 94 ae 69 d1 9b da 1f 90 b3 82",
            "0d 0d 7c 8d 11 55 4c 01 11 15 94 95 73 e5 5f 39",
        ),
        (
            "3d 7d 28 f3 e3 7e d6 f8",
            "db bb 9d e2 fd ea 79 c6 e4 f9 7b a7 32 81 97 ba",
            "06 e2 fe aa de e7 c1 9e a0 68 ad 0f 2e 9d ba 91",
            "a3 41 f0 d1 d6 09 6e 72 d7 09 fe b6 1c aa 07 70",
            "0d 0d 7c 8c d4 c1 50 01 15 16 14 6b 27 b5 9c da",
        ),
        (
            "13 e4 14 6c 3f b2 47 56",
            "a0 d8 c7 98 f3 24 d9 e2 1e 04 0f 18 89 cb 3a 09",
            "56 bb 18 64 09 0a 99 03 01 46 8b ac dc 17 68 3c",
            "0e f7 72 00 29 3d 60 f5 6c 1f d6 32 de 00 63 1e",
            "0d 0d 3c 8d 15 14 fc 51 11 61 4a 59 3e 96 73 a4",
        ),
    ];
    for (salt, k, iv, ct, pt) in cases {
        let key = Rar4Key::derive(b"Secret", Some(arr(salt))).unwrap();
        assert_eq!(key.key().to_vec(), hex(k));
        assert_eq!(key.iv().to_vec(), hex(iv));
        let mut d = MemberDecryptor::new(rar4_family_cipher(29, b"Secret", Some(&key)).unwrap());
        let mut buf = hex(ct);
        assert_eq!(d.update(&mut buf).body, 16);
        assert_eq!(buf, hex(pt));
    }
    // Encrypted header, r393_hp.rar at offset 20.
    let key = Rar4Key::derive(b"Secret", Some(arr("9c 7c 04 f0 d6 5f c8 67"))).unwrap();
    let open = rar4_open_header(&key, arr("66 41 bc 88 ea cb 99 bd 56 04 9f 62 1d 3a e5 1d"));
    assert_eq!(
        open.to_vec(),
        hex("57 76 74 24 84 31 00 10 00 00 00 00 00 00 00 03")
    );
    assert_eq!(u16::from_le_bytes([open[5], open[6]]), 49);
}

#[test]
fn rar4_family_cipher_selection() {
    for v in [0u8, 2, 10, 14, 16, 19, 21, 25, 27, 28] {
        let err = rar4_family_cipher(v, b"x", None).err().unwrap();
        assert!(
            matches!(err.kind(), ErrorKind::Unsupported(Unsupported::Encryption { code, .. }) if *code == u32::from(v)),
            "{v}"
        );
    }
    assert!(matches!(
        rar4_family_cipher(15, b"x", None),
        Ok(MemberCipher::V15(_))
    ));
    assert!(matches!(
        rar4_family_cipher(26, b"x", None),
        Ok(MemberCipher::V20(_))
    ));
    let err = rar4_family_cipher(36, b"x", None).err().unwrap();
    assert!(matches!(err.kind(), ErrorKind::PasswordRequired));
}

// ---- 5.4 RAR 5 --------------------------------------------------------------

#[test]
fn rar5_kdf_vectors() {
    let salt = arr("4a 25 a3 f5 58 dd b7 2b c0 40 16 e2 a4 25 ec c2");
    let keys = Rar5Keys::derive(b"Secret", &salt, 15, None).unwrap();
    assert_eq!(
        keys.key().to_vec(),
        hex("eb ab a0 78 29 e7 3a 09 54 f5 8c c0 91 35 38 51 50 3f 01 7c bc 6b de 9a b3 b9 fd fa 56 44 8b 55")
    );
    assert_eq!(
        keys.hash_key().to_vec(),
        hex("86 65 76 44 b5 72 d0 24 89 d6 d9 45 11 6e 6c 18 d5 95 be 7e e9 15 38 76 98 af 49 c7 29 65 90 ca")
    );
    assert_eq!(keys.check().to_vec(), hex("65 57 68 1c c3 12 3e 38"));
    let record: [u8; 12] = arr("65 57 68 1c c3 12 3e 38 5a 43 c6 96");
    assert_eq!(written_record(&keys), record);
    keys.judge_record(&record).unwrap();
    assert_eq!(keys.stored_word_under_key(0x562C_7F62), 0x7F0D_EE3E);
    assert_eq!(keys.stored_word_under_key(0xF1A9_D9F7), 0x8524_593E);

    let mut d = MemberDecryptor::new(MemberCipher::aes256(
        &keys,
        &arr("ab cd f5 a3 1e 1a e7 bb 38 08 50 66 8e 10 0f ae"),
    ));
    let mut buf = hex("cb 18 77 76 63 00 3a 29 8d 51 ca e8 27 66 f5 52");
    assert_eq!(d.update(&mut buf).body, 16);
    assert_eq!(&buf, b"rarkit spec K ve");

    let salt = arr("f1 bb 58 f7 ad 53 e3 22 3c 23 1c 7f 65 98 0c c5");
    let keys = Rar5Keys::derive(b"Secret", &salt, 15, None).unwrap();
    assert_eq!(
        keys.hash_key().to_vec(),
        hex("f9 58 38 a4 7c ba 11 d2 73 2a 34 a2 a7 8c 60 87 2d 40 2c 07 d7 f2 c8 80 02 76 32 fa bf b4 64 05")
    );
    let digest = arr("37 24 05 7c ed 5e 1b ac a2 5d 9d 4f 12 6e 21 6b 77 d3 50 8d 6e 5c 14 dc 9d 0e 98 15 06 d4 83 b3");
    assert_eq!(
        keys.mac_digest(&digest).to_vec(),
        hex("cc ed fe 40 63 46 8d c6 e2 c6 4b 01 7d cc 1b d7 96 a5 5f 2b 66 cd 54 00 67 76 a5 63 74 ef 25 63")
    );

    let salt = arr("28 54 77 ed 94 43 b0 35 b7 23 ba 7c 22 c1 fa f1");
    let keys = Rar5Keys::derive(b"Secret", &salt, 15, None).unwrap();
    assert_eq!(
        keys.key().to_vec(),
        hex("ad 68 23 f1 75 d9 57 2d 47 48 88 25 65 04 2a 92 9d cf 45 6f dd c2 f1 44 68 d5 56 37 9c f0 bf 59")
    );
    keys.judge_record(&arr("3b 17 0b 1b 4c 1a d8 97 60 73 b7 39"))
        .unwrap();
    let open = rar5_open_header(
        &keys,
        &arr("4f ed 0e d8 78 8e e4 b4 da 8e 9c f3 21 1a 15 5a"),
        arr("0b ef 4c 86 d3 56 88 64 10 bb 20 e0 ce 45 08 9c"),
    );
    assert_eq!(
        open.to_vec(),
        hex("33 92 b5 e5 0a 01 05 06 00 05 01 01 80 80 00 00")
    );
}

/// The block-driven derivation against the `Mac`-driven one, which is a
/// different road to the same RFC 2104 and 8018 arithmetic: every output,
/// over key lengths either side of SHA-256's 64-byte block (a key over 64
/// bytes is hashed first) and exponents up to 6. Permanent: it is the
/// block form's differential.
#[test]
fn rar5_kdf_block_form_matches_mac_form() {
    let mut rng = rarkit_testdata::Seeded::new(0x9e37_79b9_7f4a_7c15);
    let mut lens: Vec<usize> = vec![0, 1, 6, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 300];
    lens.extend((0..40).map(|_| rng.index(200)));
    for (k, len) in lens.into_iter().enumerate() {
        let pw = rng.bytes(len);
        let salt: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let log2 = (k % 7) as u8;
        let a = Rar5Keys::derive_blocks(&pw, &salt, log2, None).unwrap();
        let b = Rar5Keys::derive_hmac(&pw, &salt, log2, None).unwrap();
        assert_eq!(a.key(), b.key(), "key, len {len} log2 {log2}");
        assert_eq!(
            a.hash_key(),
            b.hash_key(),
            "hash key, len {len} log2 {log2}"
        );
        assert_eq!(a.check(), b.check(), "check, len {len} log2 {log2}");
    }
    // Both forms honour the cancel flag.
    let cancel = AtomicBool::new(true);
    for f in [Rar5Keys::derive_blocks, Rar5Keys::derive_hmac] {
        let err = f(b"pw", &[0; 16], 17, Some(&cancel)).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Cancelled));
    }
}

/// Run `f` with the register kernel hidden on this thread, so the
/// derivation takes `compress256` whatever the processor has.
fn without_kernel<T>(f: impl FnOnce() -> T) -> T {
    super::rar5::HIDE_KERNEL.with(|h| h.set(true));
    let out = f();
    super::rar5::HIDE_KERNEL.with(|h| h.set(false));
    out
}

/// Whether this machine runs the register kernel, so a test
/// can say which road it compared.
fn kernel_present() -> bool {
    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("sha2");
    #[cfg(target_arch = "x86_64")]
    return std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1");
    #[allow(unreachable_code)]
    false
}

/// The register kernel's permanent differential: the derivation through the
/// register kernel against the same derivation through `sha2`'s
/// `compress256`, at EVERY exponent the format allows (0 to 24), each
/// with its own random key and salt, the key lengths walking either side
/// of SHA-256's 64-byte block. Every output compared. On a machine
/// without the instructions both roads are `compress256` and the test
/// says so; the vectors and the Mac differential hold the arithmetic.
#[test]
fn rar5_kdf_kernel_matches_sha2_at_every_exponent() {
    let mut rng = rarkit_testdata::Seeded::new(0x243f_6a88_85a3_08d3);
    let lens = [0usize, 6, 31, 32, 55, 56, 63, 64, 65, 100, 128, 200];
    for log2 in 0..=MAX_LOG2 {
        let len = lens[usize::from(log2) % lens.len()];
        let pw = rng.bytes(len);
        let salt: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let a = Rar5Keys::derive_blocks(&pw, &salt, log2, None).unwrap();
        let b = without_kernel(|| Rar5Keys::derive_blocks(&pw, &salt, log2, None).unwrap());
        assert_eq!(a.key(), b.key(), "key, len {len} log2 {log2}");
        assert_eq!(
            a.hash_key(),
            b.hash_key(),
            "hash key, len {len} log2 {log2}"
        );
        assert_eq!(a.check(), b.check(), "check, len {len} log2 {log2}");
    }
    println!("kernel present: {}", kernel_present());
}

/// The kernel against `compress256` and against the `hmac` crate's `Mac`
/// over many random keys and salts at small exponents, and the chunking
/// around the cancel poll points: a run that starts or ends off a poll
/// point, and a cancel honoured by the kernel road.
#[test]
fn rar5_kdf_kernel_matches_sha2_and_mac_on_random_keys() {
    let mut rng = rarkit_testdata::Seeded::new(0x1319_8a2e_0370_7344);
    for k in 0..120 {
        let len = rng.index(260);
        let pw = rng.bytes(len);
        let salt: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let log2 = (k % 9) as u8;
        let a = Rar5Keys::derive_blocks(&pw, &salt, log2, None).unwrap();
        let b = without_kernel(|| Rar5Keys::derive_blocks(&pw, &salt, log2, None).unwrap());
        let c = Rar5Keys::derive_hmac(&pw, &salt, log2, None).unwrap();
        for (x, road) in [(&b, "compress256"), (&c, "Mac")] {
            assert_eq!(a.key(), x.key(), "key vs {road}, len {len} log2 {log2}");
            assert_eq!(
                a.hash_key(),
                x.hash_key(),
                "hash key vs {road}, len {len} log2 {log2}"
            );
            assert_eq!(
                a.check(),
                x.check(),
                "check vs {road}, len {len} log2 {log2}"
            );
        }
    }
    // 2^17 iterations cross the poll point at 2^16 inside the first run.
    let cancel = AtomicBool::new(true);
    let err = Rar5Keys::derive_blocks(b"pw", &[3; 16], 17, Some(&cancel)).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Cancelled));
    let off = AtomicBool::new(false);
    let a = Rar5Keys::derive_blocks(b"pw", &[3; 16], 17, Some(&off)).unwrap();
    let b = without_kernel(|| Rar5Keys::derive_blocks(b"pw", &[3; 16], 17, None).unwrap());
    assert_eq!(a.key(), b.key());
    assert_eq!(a.check(), b.check());
}

/// The KDF probe: not a
/// test, run by hand in a release build on a box, direction only.
///
/// `KDF_PROBE_FORM` is `mac`, `blocks`, `nokernel` (the block form with
/// the register kernel hidden), `floor` or `all` (the default,
/// interleaved per rep); `KDF_PROBE_LOG2` the exponent (15); `KDF_PROBE_REPS`
/// the repetitions (15). `floor` is ONE `compress256` call over as many
/// chained blocks as the derivation hashes, the block function's own cost a
/// block with no call, wrapper or glue between blocks: the bound a kernel
/// holding the state in registers across the loop could reach. One form per
/// process at two exponents lets `perf stat` count a round by subtraction.
#[test]
#[ignore = "a probe, run by hand in release"]
fn kdf_probe() {
    use std::hint::black_box;
    use std::time::Instant;
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let form = env("KDF_PROBE_FORM", "all");
    let log2: u8 = env("KDF_PROBE_LOG2", "15").parse().unwrap();
    let reps: usize = env("KDF_PROBE_REPS", "15").parse().unwrap();
    let iters = (1u64 << log2) + 32;
    let forms: Vec<&str> = match form.as_str() {
        "all" => vec!["mac", "blocks", "nokernel", "floor"],
        f => vec![f],
    };
    // Constant blocks: SHA-256's work does not depend on the data, and a
    // generator here would be counted by `perf stat` beside the hashing.
    let blocks: Vec<[u8; 64]> = vec![[0x5a; 64]; 2 * iters as usize];
    let mut ns: Vec<Vec<f64>> = vec![Vec::new(); forms.len()];
    for _ in 0..reps {
        for (k, f) in forms.iter().enumerate() {
            let t = Instant::now();
            let per = match *f {
                "mac" => {
                    black_box(Rar5Keys::derive_hmac(b"Secret", &[7; 16], log2, None).unwrap());
                    iters
                }
                "blocks" => {
                    black_box(Rar5Keys::derive_blocks(b"Secret", &[7; 16], log2, None).unwrap());
                    iters
                }
                "nokernel" => {
                    without_kernel(|| {
                        black_box(Rar5Keys::derive_blocks(b"Secret", &[7; 16], log2, None).unwrap())
                    });
                    iters
                }
                "floor" => {
                    let mut s = black_box([0x6a09_e667u32; 8]);
                    sha2::block_api::compress256(&mut s, black_box(&blocks));
                    black_box(s);
                    // two blocks an iteration, so the figure reads per iteration
                    iters
                }
                other => panic!("unknown KDF_PROBE_FORM {other}"),
            };
            ns[k].push(t.elapsed().as_nanos() as f64 / per as f64);
        }
    }
    for (k, f) in forms.iter().enumerate() {
        let mut v = ns[k].clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "KDF_PROBE form={f} log2={log2} reps={reps} ns_per_iteration median={:.3} min={:.3} max={:.3}",
            v[v.len() / 2],
            v[0],
            v[v.len() - 1]
        );
    }
}

#[test]
fn rar5_judge_record_verdicts() {
    let keys = Rar5Keys::derive(b"pw", &[7; 16], 0, None).unwrap();
    let good = written_record(&keys);
    keys.judge_record(&good).unwrap();
    let other = Rar5Keys::derive(b"other", &[7; 16], 0, None).unwrap();
    assert!(matches!(
        other.judge_record(&good).unwrap_err().kind(),
        ErrorKind::WrongPassword
    ));
    // A record that fails its own checksum is no record at all (3.7.3
    // step 1): any single-byte damage breaks that checksum, and the parse
    // then holds no check record for either password to be judged by.
    let record_bytes = |check: &[u8; 12]| {
        let mut rec = vec![0u8, 0x03, 0];
        rec.extend_from_slice(&[7; 16]);
        rec.extend_from_slice(&[9; 16]);
        rec.extend_from_slice(check);
        rec
    };
    let sound = Rar5Record::parse(&record_bytes(&good), true).unwrap();
    assert_eq!(sound.check, Some(good));
    for i in 0..12 {
        let mut bad = good;
        bad[i] ^= 0x40;
        let parsed = Rar5Record::parse(&record_bytes(&bad), true).unwrap();
        assert_eq!(parsed.check, None, "byte {i}");
        assert_eq!((parsed.salt, parsed.iv), ([7; 16], Some([9; 16])));
        assert!(parsed.mac());
    }
}

#[test]
fn rar5_exponent_bound_and_cancel() {
    for log2 in [25u8, 31, 255] {
        let err = Rar5Keys::derive(b"pw", &[0; 16], log2, None).unwrap_err();
        assert!(matches!(
            err.kind(),
            ErrorKind::Unsupported(Unsupported::Encryption { code, .. }) if *code == u32::from(log2)
        ));
    }
    let cancel = AtomicBool::new(true);
    let err = Rar5Keys::derive(b"pw", &[0; 16], 17, Some(&cancel)).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Cancelled));
    // L = 0 is one iteration, and equals PBKDF2 with c = 1.
    let keys = Rar5Keys::derive(b"passwd", &[0x11; 16], 0, None).unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"passwd").unwrap();
    mac.update(&[0x11; 16]);
    mac.update(&[0, 0, 0, 1]);
    assert_eq!(keys.key()[..], mac.finalize().into_bytes()[..]);
}

#[test]
fn rar5_record_parse() {
    let keys = Rar5Keys::derive(b"pw", &[3; 16], 0, None).unwrap();
    let mut rec = vec![0u8, 0x03, 15];
    rec.extend_from_slice(&[3; 16]);
    rec.extend_from_slice(&[9; 16]);
    keys.append_check_record(&mut rec);
    let r = Rar5Record::parse(&rec, true).unwrap();
    assert!(r.mac());
    assert_eq!((r.log2, r.salt, r.iv), (15, [3; 16], Some([9; 16])));
    assert_eq!(r.check, Some(written_record(&keys)));
    // Archive record: no IV, so the same bytes have 16 left over.
    assert!(matches!(
        Rar5Record::parse(&rec, false).unwrap_err().kind(),
        ErrorKind::Corrupt(_)
    ));
    for cut in 0..rec.len() {
        assert!(matches!(
            Rar5Record::parse(&rec[..cut], true).unwrap_err().kind(),
            ErrorKind::Corrupt(_)
        ));
    }
    let mut long = rec.clone();
    long.push(0);
    assert!(Rar5Record::parse(&long, true).is_err());
    let mut v1 = rec.clone();
    v1[0] = 1;
    assert!(matches!(
        Rar5Record::parse(&v1, true).unwrap_err().kind(),
        ErrorKind::Unsupported(Unsupported::Encryption { code: 1, .. })
    ));
    let mut e25 = rec.clone();
    e25[2] = 25;
    assert!(matches!(
        Rar5Record::parse(&e25, true).unwrap_err().kind(),
        ErrorKind::Unsupported(Unsupported::Encryption { code: 25, .. })
    ));

    // What a FILE header keeps of a record its parse refused: the same
    // refusal, asked for before anything is keyed, and no MAC flag
    // whatever the code's bits. A record that parsed has none.
    assert!(Rar5Record::parse(&rec, true).unwrap().refusal().is_none());
    for (refused, code) in [(&v1, 1u32), (&e25, 25)] {
        let kept = Rar5Record::unusable(&Rar5Record::parse(refused, true).unwrap_err());
        assert!(matches!(
            kept.refusal().unwrap().kind(),
            ErrorKind::Unsupported(Unsupported::Encryption { code: c, .. }) if *c == code
        ));
        assert!(!kept.mac() && kept.check.is_none() && kept.iv.is_none());
    }
    let cut = Rar5Record::unusable(&Rar5Record::parse(&rec[..9], true).unwrap_err());
    assert!(matches!(
        cut.refusal().unwrap().kind(),
        ErrorKind::Corrupt(_)
    ));
    assert!(!cut.mac());
}

// ---- 5.5 primitive wiring ---------------------------------------------------

#[test]
fn primitive_vectors() {
    assert_eq!(
        Sha256::digest(b"").to_vec(),
        hex("e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855")
    );
    assert_eq!(
        Sha256::digest(b"abc").to_vec(),
        hex("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad")
    );
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0x0b; 20]).unwrap();
    mac.update(b"Hi There");
    assert_eq!(
        mac.finalize().into_bytes().to_vec(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    let pt: [u8; 16] = arr("00112233445566778899aabbccddeeff");
    let mut b = Array::from(pt);
    aes::Aes128::new(&arr::<16>("000102030405060708090a0b0c0d0e0f").into()).encrypt_block(&mut b);
    assert_eq!(b.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    let mut b = Array::from(pt);
    aes::Aes256::new(
        &arr::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").into(),
    )
    .encrypt_block(&mut b);
    assert_eq!(b.to_vec(), hex("8ea2b7ca516745bfeafc49904b496089"));
    // PBKDF2-HMAC-SHA256, RFC 7914 section 11: passwd / salt / c = 1.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"passwd").unwrap();
    mac.update(b"salt");
    mac.update(&[0, 0, 0, 1]);
    assert_eq!(
        mac.finalize().into_bytes().to_vec(),
        hex("55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05 f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc")
    );
}

// ---- the two lane CBC decrypt ---

/// A buffer at or above the two lane floor, in BYTES.
///
/// The floor is stated in blocks by `cbc::TWO_LANE_FLOOR` and is not
/// reachable from here, so these tests name their own sizes and the
/// assertion below is what keeps them honest: a length that stopped
/// reaching the split would make every comparison in this section pass
/// vacuously, which is the defect `probe::CIPHER_OVERLAPS` exists to
/// stop on the reader's side.
const OVER_FLOOR: usize = 16384 * 16;

/// Lengths the split is walked at: the floor exactly, an odd number of
/// blocks so the two lanes differ in size, a length whose half lands
/// mid-TILE, one whose half lands on a tile boundary, and each of those
/// with a partial trailing block the mode must leave alone.
fn two_lane_lengths() -> Vec<usize> {
    let mut out = Vec::new();
    for blocks in [16384usize, 16385, 16400, 32768, 32769, 32770, 40000] {
        out.push(blocks * 16);
        out.push(blocks * 16 + 1);
        out.push(blocks * 16 + 15);
    }
    out
}

fn aes256_dec() -> aes::Aes256Dec {
    aes::Aes256Dec::new(&[7u8; 32].into())
}

fn aes128_dec() -> aes::Aes128Dec {
    aes::Aes128Dec::new(&[9u8; 16].into())
}

/// The two lane split is the serial run, byte for byte, and leaves the
/// same chaining value behind it.
///
/// The chain is checked by CONTINUING: a second buffer is decrypted
/// through both decryptors after the first, so a split that got the
/// bytes right and the carry wrong still fails here. That is the half a
/// single-buffer comparison cannot see.
#[test]
fn two_lane_cbc_is_the_serial_form_byte_for_byte() {
    let mut rng = rarkit_testdata::Seeded::new(0x5ea1_2b7c_44d9_0e13);
    for len in two_lane_lengths() {
        let data = rng.bytes(len);
        let follow = rng.bytes(4096);

        let mut serial = CbcDec::new(aes256_dec(), [3; 16]);
        let mut split = CbcDec::new(aes256_dec(), [3; 16]);
        let mut a = data.clone();
        let mut b = data.clone();
        serial.decrypt_blocks(&mut a);
        split.decrypt_blocks_two_lane(&mut b);
        assert_eq!(a, b, "len {len}");

        let mut a2 = follow.clone();
        let mut b2 = follow.clone();
        serial.decrypt_blocks(&mut a2);
        split.decrypt_blocks(&mut b2);
        assert_eq!(a2, b2, "carried chain, len {len}");
    }
}

/// The same for AES-128, which is the RAR 2.9 to 4.x cipher.
///
/// That family carries a CRC32 and never a BLAKE2sp record, so it does
/// not reach `read::extract::copy_overlapped` and the engine never turns
/// the split on for it today. The capability is one function for both
/// key lengths, so it is tested for both rather than left to be
/// discovered by whichever later change gives RAR 4 an overlap.
#[test]
fn two_lane_cbc_holds_for_aes128_as_well() {
    let mut rng = rarkit_testdata::Seeded::new(0x77c1_9a30_5d62_be04);
    for len in [OVER_FLOOR, OVER_FLOOR + 16, OVER_FLOOR + 15] {
        let data = rng.bytes(len);
        let mut serial = CbcDec::new(aes128_dec(), [11; 16]);
        let mut split = CbcDec::new(aes128_dec(), [11; 16]);
        let mut a = data.clone();
        let mut b = data;
        serial.decrypt_blocks(&mut a);
        split.decrypt_blocks_two_lane(&mut b);
        assert_eq!(a, b, "len {len}");
    }
}

/// A buffer under the floor takes no lane and is still the serial run.
#[test]
fn two_lane_under_the_floor_is_the_serial_run() {
    let mut rng = rarkit_testdata::Seeded::new(0x2f10_88ab_c3d5_6e97);
    for len in [0usize, 1, 15, 16, 32, 4096, 65536] {
        let data = rng.bytes(len);
        let mut serial = CbcDec::new(aes256_dec(), [5; 16]);
        let mut split = CbcDec::new(aes256_dec(), [5; 16]);
        let mut a = data.clone();
        let mut b = data;
        serial.decrypt_blocks(&mut a);
        split.decrypt_blocks_two_lane(&mut b);
        assert_eq!(a, b, "len {len}");
    }
}

/// End to end through the writers' own CBC: what the split decrypts is
/// the plaintext that was encrypted, not merely what the other arm of
/// this crate produces.
///
/// The two previous tests compare this crate against itself, so a fault
/// common to both forms would pass them. This one closes that by going
/// through `Aes256Enc`, whose vectors are pinned separately above.
#[test]
fn two_lane_cbc_round_trips_the_writers_ciphertext() {
    let mut rng = rarkit_testdata::Seeded::new(0x91ab_0c4e_7f23_5d68);
    let keys = Rar5Keys::derive(b"two lanes", &[4; 16], 0, None).unwrap();
    let iv = [6u8; 16];
    for len in [OVER_FLOOR, OVER_FLOOR + 16 * 777] {
        let plain = rng.bytes(len);
        let mut cipher_text = plain.clone();
        Aes256Enc::new(&keys, &iv)
            .encrypt(&mut cipher_text)
            .unwrap();
        assert_ne!(cipher_text, plain, "len {len}");
        let mut got = cipher_text;
        CbcDec::new(aes::Aes256Dec::new(&keys.key.into()), iv).decrypt_blocks_two_lane(&mut got);
        assert_eq!(got, plain, "len {len}");
    }
}

/// The member decryptor with the split on is the member decryptor with
/// it off, at arbitrary chunk sizes.
///
/// This is the form the read path actually runs: chunks arrive in
/// whatever sizes the source gives, blocks straddle their boundaries,
/// and the straddling block's plaintext comes back out of the
/// decryptor's own storage. The split touches only the bulk run of whole
/// blocks between those, and this says so.
#[test]
fn member_decryptor_two_lane_matches_one_lane() {
    let mut rng = rarkit_testdata::Seeded::new(0x0bad_5eed_1234_abcd);
    let data = rng.bytes(3 * OVER_FLOOR + 16 * 13 + 64);
    for kind in [3usize, 4] {
        // The FIRST chunk is above the floor by construction, so the
        // split certainly runs; the rest are arbitrary, which is what
        // walks blocks across the chunk boundaries.
        let mut chunks = vec![OVER_FLOOR + rng.index(64)];
        let mut left = data.len() - chunks[0];
        while left > 0 {
            let n = match rng.index(3) {
                0 => 1 + rng.index(29),
                1 => OVER_FLOOR + rng.index(1024),
                _ => 1 + rng.index(3 * OVER_FLOOR),
            }
            .min(left);
            chunks.push(n);
            left -= n;
        }
        let one = run_lanes(fresh(kind, 3), &data, &chunks, false);
        let two = run_lanes(fresh(kind, 3), &data, &chunks, true);
        assert_eq!(one, two, "kind {kind} chunks {chunks:?}");
        // Not vacuous: at least one chunk is above the floor.
        assert!(chunks.iter().any(|&n| n >= OVER_FLOOR), "{chunks:?}");
    }
}

/// [`run`] with the two lane split dialled either way.
fn run_lanes(cipher: MemberCipher, data: &[u8], chunks: &[usize], two_lane: bool) -> Vec<u8> {
    let mut d = MemberDecryptor::new(cipher);
    d.set_two_lane(two_lane);
    let mut out = Vec::new();
    let mut at = 0;
    for &n in chunks {
        let mut buf = data[at..at + n].to_vec();
        let got = d.update(&mut buf);
        out.extend_from_slice(got.head);
        out.extend_from_slice(&buf[..got.body]);
        at += n;
    }
    out
}

// ---- the member decryptor ---------------------------------------------------

fn fresh(kind: usize, rng_key: u64) -> MemberCipher {
    let pw = format!("pw{rng_key}");
    match kind {
        0 => MemberCipher::V13(Rar13Stream::new(pw.as_bytes())),
        1 => MemberCipher::V15(Rar15Stream::new(pw.as_bytes())),
        2 => MemberCipher::V20(Box::new(Rar20Block::new(pw.as_bytes()))),
        3 => MemberCipher::aes128(&Rar4Key::derive(b"k", None).unwrap()),
        4 => MemberCipher::aes256(
            &Rar5Keys::derive(pw.as_bytes(), &[1; 16], 0, None).unwrap(),
            &[2; 16],
        ),
        _ => MemberCipher::None,
    }
}

/// Feed `data` in the given chunk sizes; collect the plaintext.
fn run(cipher: MemberCipher, data: &[u8], chunks: &[usize]) -> crate::Result<Vec<u8>> {
    let mut d = MemberDecryptor::new(cipher);
    let mut out = Vec::new();
    let mut at = 0;
    for &n in chunks {
        let mut buf = data[at..at + n].to_vec();
        let pending = d.pending();
        let got = d.update(&mut buf);
        assert!(got.body <= n);
        assert!(got.head.is_empty() || got.head.len() == pending);
        out.extend_from_slice(got.head);
        out.extend_from_slice(&buf[..got.body]);
        at += n;
    }
    d.finish()?;
    Ok(out)
}

#[test]
fn member_decryptor_chunking_invariance() {
    let mut rng = rarkit_testdata::Seeded::new(0x1234_5678_9abc_def1);
    for kind in 0..6 {
        for trial in 0..40 {
            let len = 16 * rng.index(300);
            let data = rng.bytes(len);
            let whole = run(fresh(kind, 7), &data, &[len]).unwrap();
            assert_eq!(whole.len(), len);
            let mut chunks = Vec::new();
            let mut left = len;
            while left > 0 {
                let n = match rng.index(4) {
                    0 => 1 + rng.index(3),
                    1 => 1 + rng.index(31),
                    2 => 16 * (1 + rng.index(4)),
                    _ => 1 + rng.index(700),
                }
                .min(left);
                chunks.push(n);
                left -= n;
            }
            let pieces = run(fresh(kind, 7), &data, &chunks).unwrap();
            assert_eq!(pieces, whole, "kind {kind} trial {trial} chunks {chunks:?}");
        }
    }
}

#[test]
fn member_decryptor_zero_length_updates() {
    let data = [5u8; 48];
    let chunks = [0, 7, 0, 0, 9, 0, 32, 0];
    let a = run(fresh(4, 1), &data, &chunks).unwrap();
    assert_eq!(a, run(fresh(4, 1), &data, &[48]).unwrap());
}

#[test]
fn member_decryptor_finish_on_partial_block() {
    for kind in [2, 3, 4] {
        let err = run(fresh(kind, 1), &[0u8; 33], &[20, 13]).err().unwrap();
        assert!(matches!(err.kind(), ErrorKind::Corrupt(_)));
    }
    // Streams have no blocks: any total is fine.
    for kind in [0, 1, 5] {
        assert_eq!(
            run(fresh(kind, 1), &[0u8; 33], &[20, 13]).unwrap().len(),
            33
        );
    }
}

#[test]
fn rar13_restarts_per_fragment_others_carry_on() {
    let data = [0x5Au8; 64];
    let mut d = MemberDecryptor::new(MemberCipher::V13(Rar13Stream::new(b"Secret")));
    let mut a = data[..32].to_vec();
    d.update(&mut a);
    d.next_fragment();
    let mut b = data[32..].to_vec();
    d.update(&mut b);
    assert_eq!(a, b, "RAR 1.3 keystream restarts at each fragment");

    let mut d = MemberDecryptor::new(MemberCipher::V15(Rar15Stream::new(b"Secret")));
    let mut a = data[..32].to_vec();
    d.update(&mut a);
    d.next_fragment();
    let mut b = data[32..].to_vec();
    d.update(&mut b);
    assert_ne!(a, b, "RAR 1.5 keystream carries across fragments");
}

// ---- key cache --------------------------------------------------------------

#[test]
fn key_cache_derives_once_per_salt_with_lru() {
    let pw = Password::from("pw");
    let mut cache = KeyCache::new(None);
    for _ in 0..3 {
        for s in 0..4u8 {
            cache.rar5(&pw, &[s; 16], 0).unwrap();
        }
    }
    assert_eq!(cache.derivations(), 4);
    // A different exponent is a different key.
    cache.rar5(&pw, &[0; 16], 1).unwrap();
    assert_eq!(cache.derivations(), 5);
    let a = cache.rar4(&pw, Some([1; 8])).unwrap().key().to_owned();
    cache.rar4(&pw, Some([1; 8])).unwrap();
    cache.rar4(&pw, None).unwrap();
    assert_eq!(cache.derivations(), 7);
    assert_eq!(&a, Rar4Key::derive(b"pw", Some([1; 8])).unwrap().key());
    // Fill past capacity: 7 + 20 distinct salts, keep touching salt 200.
    for s in 100..120u8 {
        cache.rar5(&pw, &[200; 16], 0).unwrap();
        cache.rar5(&pw, &[s; 16], 0).unwrap();
    }
    let before = cache.derivations();
    cache.rar5(&pw, &[200; 16], 0).unwrap();
    assert_eq!(cache.derivations(), before, "recently used entry survives");
    cache.rar5(&pw, &[0; 16], 0).unwrap();
    assert_eq!(cache.derivations(), before + 1, "oldest entry was evicted");
    assert_eq!(
        cache.slots.iter().filter(|s| s.is_some()).count(),
        CACHE_SLOTS
    );
}

#[test]
fn key_cache_polls_cancel() {
    let flag = Arc::new(AtomicBool::new(true));
    let mut cache = KeyCache::new(Some(flag));
    let err = cache.rar5(&Password::from("pw"), &[0; 16], 20).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Cancelled));
}

#[test]
fn nothing_secret_in_debug() {
    let keys = Rar5Keys::derive(b"Secret", &[0; 16], 0, None).unwrap();
    assert_eq!(format!("{keys:?}"), "Rar5Keys(..)");
    let key = Rar4Key::derive(b"Secret", None).unwrap();
    assert_eq!(format!("{key:?}"), "Rar4Key(..)");
}

// ---- encrypted headers over a source ----------------------------------------

#[test]
fn header_reader_rar5_round_trip_and_bounds() {
    let pw = Password::from("pw");
    let keys = Rar5Keys::derive(b"pw", &[4; 16], 0, None).unwrap();
    // A plaintext header: CRC32, size vint, then `size` bytes.
    let body: Vec<u8> = (0..40u8).collect();
    let mut plain = vec![0u8; 4];
    plain.push(body.len() as u8);
    plain.extend_from_slice(&body);
    let crc = crc32fast::hash(&plain[4..]);
    plain[..4].copy_from_slice(&crc.to_le_bytes());
    let mut padded = plain.clone();
    padded.resize(plain.len().div_ceil(16) * 16, 0);
    let iv = [8u8; 16];
    rar5_encrypt_header(&keys, &iv, &mut padded).unwrap();
    let mut src = vec![0xEEu8; 3];
    src.extend_from_slice(&iv);
    src.extend_from_slice(&padded);
    src.extend_from_slice(b"DATA");
    let mut r = HeaderReader::new();
    let span = r.rar5(&src, 3, &keys).unwrap();
    assert_eq!(span.len, plain.len());
    assert_eq!(span.end, 3 + 16 + padded.len() as u64);
    assert_eq!(r.plain(), &plain[..]);
    // Every truncation is Truncated.
    for cut in 3..src.len() - 4 {
        let err = r.rar5(&src[..cut].to_vec(), 3, &keys).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Truncated), "cut {cut}");
    }
    // A wrong key fails the checksum or the bounds, never panics.
    let other = Rar5Keys::derive(b"px", &[4; 16], 0, None).unwrap();
    assert!(r.rar5(&src, 3, &other).is_err());
    let _ = pw;
}

/// One key schedule per key (30 Sep 2026): a
/// header is deciphered as ONE chain on the schedule the key cache holds,
/// its first block once, and the plaintext is the reference `cbc` crate's
/// at every padded length from one block to many, in both families. A
/// cache hit answers the SAME schedule (its slot never moves, so neither
/// does it), and a member cipher built on it deciphers what the reference
/// does.
#[test]
fn headers_decipher_one_chain_on_the_schedule_the_cache_holds() {
    let pw = Password::from("pw");
    let mut cache = KeyCache::new(None);
    let at5 = std::sync::Arc::as_ptr(&cache.rar5_cipher(&pw, &[5; 16], 0).unwrap().sched);
    let at4 = std::sync::Arc::as_ptr(&cache.rar4_cipher(&pw, Some([7; 8])).unwrap().sched);
    let keys = cache.rar5_cipher(&pw, &[5; 16], 0).unwrap().clone();
    // The copy of the cache's entry is on the same schedules, not a copy.
    assert!(std::ptr::eq(at5, std::sync::Arc::as_ptr(&keys.sched)));
    assert!(std::ptr::eq(
        at5,
        std::sync::Arc::as_ptr(&cache.rar5_cipher(&pw, &[5; 16], 0).unwrap().sched)
    ));
    assert!(std::ptr::eq(
        at4,
        std::sync::Arc::as_ptr(&cache.rar4_cipher(&pw, Some([7; 8])).unwrap().sched)
    ));
    let key4 = cache.rar4(&pw, Some([7; 8])).unwrap().clone();
    assert_eq!(cache.derivations(), 2);

    let iv = [0x3Cu8; 16];
    let mut r = HeaderReader::new();
    for size in [
        1usize, 2, 9, 10, 11, 12, 27, 28, 29, 60, 127, 128, 200, 1000, 5000,
    ] {
        // RAR 5: CRC32, the size vint, then `size` bytes.
        let body: Vec<u8> = (0..size).map(|i| (i * 7 + size) as u8).collect();
        let mut plain = vec![0u8; 4];
        let mut v = size;
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                plain.push(b);
                break;
            }
            plain.push(b | 0x80);
        }
        plain.extend_from_slice(&body);
        let crc = crc32fast::hash(&plain[4..]);
        plain[..4].copy_from_slice(&crc.to_le_bytes());
        let mut ct = plain.clone();
        ct.resize(plain.len().next_multiple_of(16), 0);
        ::cbc::Encryptor::<aes::Aes256>::new(&keys.keys.key.into(), &iv.into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut ct).0);
        let mut src = iv.to_vec();
        src.extend_from_slice(&ct);
        let mut from: &dyn crate::source::RangeSource = &src;
        let span = r.rar5_from(&mut from, 0, &keys).unwrap();
        assert_eq!(r.plain(), &plain[..], "rar5, size {size}");
        assert_eq!(span.end, 16 + ct.len() as u64);
        // The member cipher on the cache's schedule.
        let mut member = MemberDecryptor::new(MemberCipher::aes256_on(&keys, &iv));
        let mut buf = ct.clone();
        let got = member.update(&mut buf);
        assert_eq!(got.body, ct.len());
        assert_eq!(&buf[..plain.len()], &plain[..], "member, size {size}");

        // RAR 4: CRC16, type, flags, the u16 size, then the rest.
        let size4 = (size + 7).min(0xFFFF);
        let mut plain4: Vec<u8> = vec![0, 0, 0x74, 0, 0x80];
        plain4.extend_from_slice(&(size4 as u16).to_le_bytes());
        plain4.extend((7..size4).map(|i| (i * 5) as u8));
        let crc = crc32fast::hash(&plain4[2..]) as u16;
        plain4[..2].copy_from_slice(&crc.to_le_bytes());
        let mut ct4 = plain4.clone();
        ct4.resize(plain4.len().next_multiple_of(16), 0);
        ::cbc::Encryptor::<aes::Aes128>::new(&key4.key.into(), &key4.iv.into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut ct4).0);
        let mut src4 = vec![7u8; 8];
        src4.extend_from_slice(&ct4);
        let mut from4: &dyn crate::source::RangeSource = &src4;
        let span = r.rar4_from(&mut from4, 0, &pw, &mut cache).unwrap();
        assert_eq!(r.plain(), &plain4[..], "rar4, size {size4}");
        assert_eq!(span.end, 8 + ct4.len() as u64);
    }
    assert_eq!(cache.derivations(), 2, "a header derived again");
}

#[test]
fn header_reader_rar4_round_trip_and_wrong_password() {
    let pw = Password::from("Secret");
    let salt = [9u8; 8];
    let key = Rar4Key::derive(b"Secret", Some(salt)).unwrap();
    let mut plain = vec![0u8, 0, 0x74, 0x00, 0x80, 30, 0];
    plain.extend((0..23u8).map(|i| i * 3));
    let crc = crc32fast::hash(&plain[2..]) as u16;
    plain[..2].copy_from_slice(&crc.to_le_bytes());
    let mut padded = plain.clone();
    padded.resize(32, 0);
    rar4_encrypt_header(&key, &mut padded).unwrap();
    let mut src = salt.to_vec();
    src.extend_from_slice(&padded);
    let mut cache = KeyCache::new(None);
    let mut r = HeaderReader::new();
    let span = r.rar4(&src, 0, &pw, &mut cache).unwrap();
    assert_eq!((span.size, span.end), (30, 40));
    assert_eq!(r.plain(), &plain[..]);
    let mut wrong = KeyCache::new(None);
    let err = r
        .rar4(&src, 0, &Password::from("secret"), &mut wrong)
        .unwrap_err();
    assert!(matches!(
        err.kind(),
        ErrorKind::HeaderChecksum | ErrorKind::Corrupt(_) | ErrorKind::Truncated
    ));
    for cut in 0..src.len() {
        let err = r
            .rar4(&src[..cut].to_vec(), 0, &pw, &mut cache)
            .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Truncated), "cut {cut}");
    }
}

#[test]
fn cbc_decrypt_matches_rustcrypto_one_shot() {
    // The member decryptor's multi-block path equals a plain CBC decrypt.
    let mut rng = rarkit_testdata::Seeded::new(99);
    let keys = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    let data = rng.bytes(16 * 257);
    let mut want = data.clone();
    ::cbc::Decryptor::<aes::Aes256>::new(&keys.key.into(), &[6u8; 16].into())
        .decrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
    let got = run(MemberCipher::aes256(&keys, &[6; 16]), &data, &[data.len()]).unwrap();
    assert_eq!(got, want);
}

/// Lengths that put the tile boundary of `crypto::cbc` (`TILE`, 32 blocks
/// on every architecture) in every position that matters: inside the first tile,
/// exactly on it, one block over, and several tiles with a ragged last one.
const TILE_EDGES: [usize; 8] = {
    let t = super::cbc::TILE;
    [1, 2, t - 1, t, t + 1, 2 * t, 2 * t + 1, 8 * t + 1]
};

#[test]
fn cbc_decrypt_matches_the_mode_crate_at_every_tile_edge() {
    let mut rng = rarkit_testdata::Seeded::new(7);
    let keys = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    let key4 = Rar4Key::derive(b"x", Some([2; 8])).unwrap();
    for blocks in TILE_EDGES {
        let data = rng.bytes(16 * blocks);
        let mut want = data.clone();
        ::cbc::Decryptor::<aes::Aes256>::new(&keys.key.into(), &[6u8; 16].into())
            .decrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
        let got = run(MemberCipher::aes256(&keys, &[6; 16]), &data, &[data.len()]).unwrap();
        assert_eq!(got, want, "aes256, {blocks} blocks");

        let mut want = data.clone();
        ::cbc::Decryptor::<aes::Aes128>::new(&key4.key.into(), &key4.iv.into())
            .decrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
        let got = run(MemberCipher::aes128(&key4), &data, &[data.len()]).unwrap();
        assert_eq!(got, want, "aes128, {blocks} blocks");
    }
}

#[test]
fn cbc_encrypt_matches_the_mode_crate_at_every_tile_edge() {
    let mut rng = rarkit_testdata::Seeded::new(11);
    let keys = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    let key4 = Rar4Key::derive(b"x", Some([3; 8])).unwrap();
    for blocks in TILE_EDGES {
        let data = rng.bytes(16 * blocks);

        let mut want = data.clone();
        ::cbc::Encryptor::<aes::Aes256>::new(&keys.key.into(), &[6u8; 16].into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
        let mut got = data.clone();
        Aes256Enc::new(&keys, &[6; 16]).encrypt(&mut got).unwrap();
        assert_eq!(got, want, "aes256, {blocks} blocks");

        let mut want = data.clone();
        ::cbc::Encryptor::<aes::Aes128>::new(&key4.key.into(), &key4.iv.into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
        let mut got = data.clone();
        Aes128Enc::new(&key4).encrypt(&mut got).unwrap();
        assert_eq!(got, want, "aes128, {blocks} blocks");
    }
}

/// Encryption in several calls chains exactly as one call does, which is
/// what the writers do across their output buffers.
#[test]
fn cbc_encrypt_chains_across_calls() {
    let mut rng = rarkit_testdata::Seeded::new(13);
    let keys = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    let data = rng.bytes(16 * 100);
    let mut want = data.clone();
    Aes256Enc::new(&keys, &[9; 16]).encrypt(&mut want).unwrap();
    let mut got = data.clone();
    let mut enc = Aes256Enc::new(&keys, &[9; 16]);
    for part in got.chunks_mut(16 * 17) {
        enc.encrypt(part).unwrap();
    }
    assert_eq!(got, want);
}

/// The second table of `Rar15Stream::apply` is the first's low half
/// rotated right one bit, entry by entry.
#[test]
fn rar15_second_table_is_the_first_rotated() {
    let second = super::legacy::e_lo_ror_table();
    for x in 0..256 {
        assert_eq!(second[x], (T[x] as u16).rotate_right(1), "entry {x}");
    }
}

/// `Rar15Stream::apply`'s rearranged recurrence against the per-byte rule
/// of spec K 3.4 as written, side by side.
///
/// Every class of state: the setup of an empty password, of one byte, of
/// ordinary words, of a password cut at an embedded zero, of long and of
/// high-bit passwords, and then states drawn at random over all four
/// words, which covers every key a setup could reach and every one it
/// could not. Each runs a few hundred thousand bytes through both forms,
/// in buffers of random lengths including zero and one, so the carried
/// state is checked at every split as well as the output. About eight
/// million bytes in all.
#[test]
fn rar15_apply_matches_the_literal_recurrence() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let long: Vec<u8> = (0..200u32).map(|i| (i * 37 + 11) as u8).collect();
    let passwords: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"Secret".to_vec(),
        b"password".to_vec(),
        b"pass\0word".to_vec(),
        vec![0xFF; 64],
        vec![0x80, 0x81, 0xFE, 0x7F],
        long,
    ];
    let mut streams: Vec<Rar15Stream> = passwords.iter().map(|p| Rar15Stream::new(p)).collect();
    for _ in 0..24 {
        let r = next();
        streams.push(Rar15Stream::from_state([
            r as u16,
            (r >> 16) as u16,
            (r >> 32) as u16,
            (r >> 48) as u16,
        ]));
    }
    let mut total = 0usize;
    for stream in streams {
        let mut fast = stream.clone();
        let mut literal = stream;
        let mut left = 250_000usize;
        while left > 0 {
            let len = match next() % 8 {
                0 => 0,
                1 => 1,
                2 => (next() % 16) as usize,
                _ => (next() % 20_000) as usize,
            }
            .min(left);
            let data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let mut a = data.clone();
            let mut b = data;
            fast.apply(&mut a);
            literal.apply_literal(&mut b);
            assert_eq!(a, b, "output differs after {total} bytes");
            assert_eq!(
                fast.state(),
                literal.state(),
                "state differs after {total} bytes"
            );
            left -= len;
            total += len;
        }
    }
    assert!(total >= 8_000_000, "the test ran {total} bytes");
}

/// **Encrypting from a source into a destination is `encrypt` in place**,
/// held against the `cbc` crate at every tile edge in both key sizes
/// (a change to `crypto/cbc.rs` is held against `cbc` block for
/// block), and chained across calls that mix the two forms.
#[test]
fn cbc_encrypt_from_matches_the_mode_crate_and_the_in_place_form() {
    let mut rng = rarkit_testdata::Seeded::new(17);
    let keys = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    let key4 = Rar4Key::derive(b"x", Some([3; 8])).unwrap();
    for blocks in TILE_EDGES {
        let data = rng.bytes(16 * blocks);

        let mut want = data.clone();
        ::cbc::Encryptor::<aes::Aes256>::new(&keys.key.into(), &[6u8; 16].into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
        let mut got = vec![0u8; data.len()];
        Aes256Enc::new(&keys, &[6; 16])
            .encrypt_from(&data, &mut got)
            .unwrap();
        assert_eq!(got, want, "aes256, {blocks} blocks");

        let mut want = data.clone();
        ::cbc::Encryptor::<aes::Aes128>::new(&key4.key.into(), &key4.iv.into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
        let mut got = vec![0u8; data.len()];
        Aes128Enc::new(&key4).encrypt_from(&data, &mut got).unwrap();
        assert_eq!(got, want, "aes128, {blocks} blocks");
    }

    // Mixed calls: in place, then from, then in place, chain carried.
    let data = rng.bytes(16 * 300);
    let mut want = data.clone();
    Aes256Enc::new(&keys, &[9; 16]).encrypt(&mut want).unwrap();
    let mut got = data.clone();
    let mut enc = Aes256Enc::new(&keys, &[9; 16]);
    enc.encrypt(&mut got[..16 * 7]).unwrap();
    let mut middle = vec![0u8; 16 * 200];
    enc.encrypt_from(&data[16 * 7..16 * 207], &mut middle)
        .unwrap();
    got[16 * 7..16 * 207].copy_from_slice(&middle);
    enc.encrypt(&mut got[16 * 207..]).unwrap();
    assert_eq!(got, want, "mixed calls");

    // Refusals change nothing.
    let mut dst = vec![0xEEu8; 32];
    assert!(Aes256Enc::new(&keys, &[1; 16])
        .encrypt_from(&data[..31], &mut dst[..31])
        .is_err());
    assert!(Aes256Enc::new(&keys, &[1; 16])
        .encrypt_from(&data[..32], &mut dst[..16])
        .is_err());
    assert_eq!(dst, vec![0xEEu8; 32]);
}

/// **The writers' chain's permanent differential.** The writers' AES-CBC chain,
/// which drives the ARMv8 instructions directly on aarch64 and AES-NI on
/// x86-64 (see `the_writers_chain_is_the_instructions_where_present` for
/// which one a run exercised), is held block
/// for block against the `aes` and `cbc` crates: both key sizes, 64 random
/// keys each (so the key expansion is exercised, not one schedule), every
/// tile edge, both entry points (in place and from a source), buffers at
/// every misalignment of their address from 0 to 15, and the chain carried
/// across split calls. FIPS 197 appendix C's two single-block vectors are
/// checked through the same entry point, as the first block of a chain from
/// a zero IV.
#[test]
fn the_writers_cbc_chain_is_the_crates_block_for_block() {
    // FIPS 197 C.1 (AES-128) and C.3 (AES-256).
    let plain = hex("00112233445566778899aabbccddeeff");
    let key128: [u8; 16] = arr("000102030405060708090a0b0c0d0e0f");
    let key256: [u8; 32] = arr("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let mut k4 = Rar4Key::derive(b"x", Some([3; 8])).unwrap();
    k4.key = key128;
    k4.iv = [0; 16];
    let mut got = plain.clone();
    Aes128Enc::new(&k4).encrypt(&mut got).unwrap();
    assert_eq!(got, hex("69c4e0d86a7b0430d8cdb78070b4c55a"), "FIPS 197 C.1");
    let mut k5 = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    k5.key = key256;
    let mut got = plain.clone();
    Aes256Enc::new(&k5, &[0; 16]).encrypt(&mut got).unwrap();
    assert_eq!(got, hex("8ea2b7ca516745bfeafc49904b496089"), "FIPS 197 C.3");

    let mut rng = rarkit_testdata::Seeded::new(58);
    for trial in 0..64 {
        let key256: [u8; 32] = rng.bytes(32).try_into().unwrap();
        let key128: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let iv: [u8; 16] = rng.bytes(16).try_into().unwrap();
        k5.key = key256;
        k4.key = key128;
        k4.iv = iv;
        let blocks = TILE_EDGES[trial % TILE_EDGES.len()];
        let data = rng.bytes(16 * blocks);

        let mut want256 = data.clone();
        ::cbc::Encryptor::<aes::Aes256>::new(&key256.into(), &iv.into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut want256).0);
        let mut want128 = data.clone();
        ::cbc::Encryptor::<aes::Aes128>::new(&key128.into(), &iv.into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut want128).0);

        for offset in 0..16 {
            // In place, at this misalignment.
            let mut room = vec![0u8; data.len() + 16];
            room[offset..offset + data.len()].copy_from_slice(&data);
            let buf = &mut room[offset..offset + data.len()];
            Aes256Enc::new(&k5, &iv).encrypt(buf).unwrap();
            assert!(
                buf == &want256[..],
                "aes256 in place, trial {trial}, offset {offset}"
            );
            let mut room = vec![0u8; data.len() + 16];
            room[offset..offset + data.len()].copy_from_slice(&data);
            let buf = &mut room[offset..offset + data.len()];
            Aes128Enc::new(&k4).encrypt(buf).unwrap();
            assert!(
                buf == &want128[..],
                "aes128 in place, trial {trial}, offset {offset}"
            );

            // From a source at this misalignment, into a destination at
            // the opposite one, split at a block boundary across two calls.
            let mut src_room = vec![0u8; data.len() + 16];
            src_room[offset..offset + data.len()].copy_from_slice(&data);
            let src = &src_room[offset..offset + data.len()];
            let mut dst_room = vec![0u8; data.len() + 16];
            let dst = &mut dst_room[15 - offset..15 - offset + data.len()];
            let cut = 16 * (blocks / 2);
            let mut enc = Aes256Enc::new(&k5, &iv);
            enc.encrypt_from(&src[..cut], &mut dst[..cut]).unwrap();
            enc.encrypt_from(&src[cut..], &mut dst[cut..]).unwrap();
            assert!(
                dst == &want256[..],
                "aes256 from, trial {trial}, offset {offset}"
            );
            let mut enc = Aes128Enc::new(&k4);
            enc.encrypt_from(&src[..cut], &mut dst[..cut]).unwrap();
            enc.encrypt_from(&src[cut..], &mut dst[cut..]).unwrap();
            assert!(
                dst == &want128[..],
                "aes128 from, trial {trial}, offset {offset}"
            );
        }
    }
}

/// **Which chain the writers drive, pinned.** The differential
/// above proves whichever chain `EncChain::new` selected, so this pins the
/// selection itself: the instructions' own chain wherever the run-time
/// check finds them (`armv8` on aarch64, `x86` on x86-64 with AES-NI), and
/// the `aes` crate's chain only where it does not, at both key sizes. On
/// an Apple Silicon Mac an `x86_64-apple-darwin` build of this test runs
/// under Rosetta, which advertises AES, so it reads `x86` there too.
#[test]
fn the_writers_chain_is_the_instructions_where_present() {
    #[cfg(target_arch = "aarch64")]
    let want = if std::arch::is_aarch64_feature_detected!("aes") {
        "armv8"
    } else {
        "crate"
    };
    #[cfg(target_arch = "x86_64")]
    let want = if std::arch::is_x86_feature_detected!("aes") {
        "x86"
    } else {
        "crate"
    };
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let want = "crate";

    let k5 = Rar5Keys::derive(b"x", &[5; 16], 0, None).unwrap();
    assert_eq!(Aes256Enc::new(&k5, &[0; 16]).0.kind(), want, "aes256");
    let k4 = Rar4Key::derive(b"x", Some([3; 8])).unwrap();
    assert_eq!(Aes128Enc::new(&k4).0.kind(), want, "aes128");
}

/// `count` characters, each `ch`.
fn chars(ch: char, count: usize) -> String {
    std::iter::repeat_n(ch, count).collect()
}

/// Spec K 3.7.1: only the first 127 CHARACTERS of a password are used, and
/// the unit is the code point, not the byte and not the UTF-16 unit.
#[test]
fn rar5_password_is_cut_to_its_first_127_characters() {
    let salt = [9u8; 16];
    let whole = |pw: &str| Rar5Keys::derive_hmac(pw.as_bytes(), &salt, 2, None).unwrap();
    let used = |pw: &str| Rar5Keys::derive(pw.as_bytes(), &salt, 2, None).unwrap();
    let same = |a: &Rar5Keys, b: &Rar5Keys| {
        a.key() == b.key() && a.hash_key() == b.hash_key() && a.check() == b.check()
    };

    // 126 and 127 characters are all used.
    for count in [126, 127] {
        let pw = chars('x', count);
        assert!(same(&used(&pw), &whole(&pw)), "{count} characters");
    }
    // 128, 129 and 200 are cut to the first 127.
    let long: String = (0..200u8).map(|i| char::from(b'a' + i % 26)).collect();
    for count in [128, 129, 200] {
        let got = used(&long[..count]);
        assert!(same(&got, &whole(&long[..127])), "{count} characters");
        assert!(!same(&got, &whole(&long[..count])), "{count} characters");
    }
    // 127 two-byte characters (254 bytes) are all used; 128 are cut to 127.
    let two = chars('\u{e9}', 128);
    let cut = &two[..254];
    assert!(same(&used(cut), &whole(cut)));
    assert!(same(&used(&two), &whole(cut)));
    // Not a cut at 127 BYTES.
    let mixed = format!("{}{}", chars('x', 126), '\u{e9}');
    assert!(same(&used(&mixed), &whole(&mixed)));
    // 127 code points of which one is outside the basic plane (128 UTF-16
    // units) are all used, the outside one as its four UTF-8 bytes.
    for pw in [
        format!("{}\u{1f511}", chars('x', 126)),
        format!("{}\u{1f511}y", chars('x', 125)),
    ] {
        assert_eq!(pw.chars().count(), 127);
        assert!(same(&used(&pw), &whole(&pw)));
    }
}

/// The specification states the limit in characters and leaves open what a
/// password that is not UTF-8 is cut to: every byte of it is used, as
/// before the limit was applied.
#[test]
fn rar5_password_not_utf8_is_used_whole_specification_leaves_it_open() {
    let salt = [9u8; 16];
    let mut raw = vec![b'x'; 199];
    raw.push(0xff);
    let got = Rar5Keys::derive(&raw, &salt, 2, None).unwrap();
    let whole = Rar5Keys::derive_hmac(&raw, &salt, 2, None).unwrap();
    assert_eq!(got.key(), whole.key());
    assert_eq!(got.check(), whole.check());
}

/// Spec B 3.2: the RAR 3 derivation also uses the first 127 characters.
#[test]
fn rar4_password_is_cut_to_its_first_127_characters() {
    let salt = Some(*b"saltsalt");
    let key = |pw: &str| {
        let k = Rar4Key::derive(pw.as_bytes(), salt).unwrap();
        (*k.key(), *k.iv())
    };
    let long: String = (0..200u8).map(|i| char::from(b'a' + i % 26)).collect();
    assert_ne!(key(&long[..126]), key(&long[..127]));
    for count in [128, 129, 200] {
        assert_eq!(key(&long[..count]), key(&long[..127]), "{count} characters");
    }
    // The unit is the character: 127 two-byte characters are all used and
    // 128 of them are cut to 127.
    let two = chars('\u{e9}', 128);
    assert_ne!(key(&two[..252]), key(&two[..254]));
    assert_eq!(key(&two), key(&two[..254]));
}

/// A 30 byte RAR 4 file header, encrypted under `key` behind `salt`.
fn sealed_rar4_header(key: &Rar4Key, salt: [u8; 8]) -> (Vec<u8>, Vec<u8>) {
    let mut plain = vec![0u8, 0, 0x74, 0x00, 0x80, 30, 0];
    plain.extend((0..23u8).map(|i| i * 5));
    let crc = crc32fast::hash(&plain[2..]) as u16;
    plain[..2].copy_from_slice(&crc.to_le_bytes());
    let mut padded = plain.clone();
    padded.resize(32, 0);
    rar4_encrypt_header(key, &mut padded).unwrap();
    let mut src = salt.to_vec();
    src.extend_from_slice(&padded);
    (src, plain)
}

/// Spec B 3.2: a reader that opens what both kinds of build could have
/// written tries the observed reading of a character outside the basic
/// plane (its low 16 bits) and then the surrogate pair. Encrypted headers
/// carry a checksum, so the reader can tell; the reading that verified is
/// the session's for the member data that follows.
#[test]
fn rar4_encrypted_header_opens_under_either_reading_of_an_outside_character() {
    let text = "\u{1f511}key";
    let pw = Password::from(text);
    let salt = [4u8; 8];
    for reading in [Astral::Low16, Astral::Pair] {
        let key = Rar4Key::derive_reading(text.as_bytes(), Some(salt), reading).unwrap();
        let (src, plain) = sealed_rar4_header(&key, salt);
        let mut cache = KeyCache::new(None);
        let mut r = HeaderReader::new();
        let span = r.rar4(&src, 0, &pw, &mut cache).unwrap();
        assert_eq!((span.size, span.end), (30, 40), "{reading:?}");
        assert_eq!(r.plain(), &plain[..], "{reading:?}");
        let tries = if reading == Astral::Low16 { 1 } else { 2 };
        assert_eq!(cache.derivations(), tries, "{reading:?}");
        // The member data's key for the same salt is the one that opened
        // the header, and costs no further derivation.
        assert_eq!(cache.rar4(&pw, Some(salt)).unwrap().key(), key.key());
        r.rar4(&src, 0, &pw, &mut cache).unwrap();
        assert_eq!(cache.derivations(), tries, "{reading:?}");
    }
}

/// The second reading is tried only where it can differ, and a header
/// neither reading opens is the failed header check it was: two
/// derivations at most, and the session keeps the observed reading.
#[test]
fn rar4_encrypted_header_wrong_password_is_still_the_failed_check() {
    let salt = [4u8; 8];
    let key = Rar4Key::derive(b"Secret", Some(salt)).unwrap();
    let (src, _) = sealed_rar4_header(&key, salt);
    let mut r = HeaderReader::new();
    for (wrong, tries) in [("secret", 1), ("\u{1f511}key", 2)] {
        let mut cache = KeyCache::new(None);
        let pw = Password::from(wrong);
        for _ in 0..3 {
            let err = r.rar4(&src, 0, &pw, &mut cache).unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::HeaderChecksum), "{wrong}");
        }
        assert_eq!(cache.derivations(), tries, "{wrong}");
        let low = Rar4Key::derive(wrong.as_bytes(), Some(salt)).unwrap();
        assert_eq!(cache.rar4(&pw, Some(salt)).unwrap().key(), low.key());
    }
}

/// The salt, exponent and check record of the one member of the Windows
/// capture's `long-password/t.rar` (spec K 3.7.1, genuine `Rar.exe` 7.23):
/// bytes 0x3b to 0x4a, 0x3a and 0x5b to 0x66 of that file, carried here so
/// that this crate's lib tests read nothing outside it.
/// `tests/password_readings.rs` reads the archive itself.
fn windows_long_record() -> ([u8; 16], u8, [u8; 12]) {
    (
        arr("ae 94 e4 af 25 11 01 b6 e1 2c 15 4b e5 bf 06 a3"),
        0x0f,
        arr("d6 aa f4 e6 2d d3 0b 73 da 40 03 72"),
    )
}

/// The same three fields of the Linux-made twin
/// (`tests/password_readings/linux-long-password.rar`, genuine `rar` 7.23
/// for Linux under the same password): bytes 0x3d to 0x4c, 0x3c and 0x5d
/// to 0x68 of that file.
fn linux_long_record() -> ([u8; 16], u8, [u8; 12]) {
    (
        arr("52 8f 01 a4 6d a5 66 9b 23 20 04 b3 50 c9 8b 01"),
        0x0f,
        arr("c8 95 de b3 8e 38 85 08 b2 4c 90 01"),
    )
}

/// The genuine Linux record fits the first cut: the password as typed
/// costs ONE derivation there, and a session that turns to the unit cut
/// on the Windows record turns back on this one. One thread; 2^15
/// iterations a derivation.
#[test]
fn rar5_judged_linux_record_fits_the_first_cut() {
    let whole = format!("{}\u{1f511}yz", "x".repeat(125));
    let pw = Password::from(whole.as_str());
    let (salt, log2, check) = linux_long_record();
    let mut cache = KeyCache::new(None);
    cache.rar5_judged(&pw, &salt, log2, Some(&check)).unwrap();
    cache.rar5_judged(&pw, &salt, log2, Some(&check)).unwrap();
    assert_eq!(cache.derivations(), 1);

    let (wsalt, wlog2, wcheck) = windows_long_record();
    cache
        .rar5_judged(&pw, &wsalt, wlog2, Some(&wcheck))
        .unwrap();
    assert_eq!(cache.derivations(), 3);
    // The session now derives under the unit cut first, so the Linux salt
    // costs its one derivation under that cut before the session turns
    // back: two a salt at the very most, and then every key is held.
    cache.rar5_judged(&pw, &salt, log2, Some(&check)).unwrap();
    assert_eq!(cache.derivations(), 4);
    for _ in 0..3 {
        cache
            .rar5_judged(&pw, &wsalt, wlog2, Some(&wcheck))
            .unwrap();
        cache.rar5_judged(&pw, &salt, log2, Some(&check)).unwrap();
    }
    assert_eq!(cache.derivations(), 4);
}

/// Spec K 3.7.1: `kept_units` and `cuts_differ` name exactly the
/// passwords the two families key differently. One thread, no memory to
/// speak of.
#[test]
fn rar5_cuts_differ_only_for_a_long_password_with_an_outside_character_kept() {
    let key = '\u{1f511}';
    let x = |n: usize| "x".repeat(n);
    for (text, differ) in [
        // 127 units or fewer: nothing is cut.
        (x(127), false),
        (format!("{}{key}", x(125)), false),
        // Longer, every character in the basic plane: one cut.
        (x(200), false),
        ("\u{e9}".repeat(128), false),
        // The capture's password: 127 characters keep `y`, 127 units do
        // not.
        (format!("{}{key}yz", x(125)), true),
        (format!("{key}{}", x(127)), true),
        // The character lies past what either rule keeps.
        (format!("{}{key}", x(127)), false),
        // The unit cut would fall inside the pair: not established, one
        // reading.
        (format!("{}{key}", x(126)), false),
        (format!("{}{key}yz", x(126)), false),
    ] {
        assert_eq!(
            cuts_differ(text.as_bytes()),
            differ,
            "{} characters",
            text.chars().count()
        );
    }
    assert!(!cuts_differ(b"\xff\xfe"));
}

/// The second cut is derived only where the first does not fit the check
/// record and only for a password with two cuts; the cut that fitted is
/// the session's, so the next salt costs one derivation. Genuine record
/// (`Rar.exe` 7.23 for Windows). One thread; 2^15 iterations a derivation.
#[test]
fn rar5_judged_derives_the_second_cut_once_and_keeps_it() {
    let (salt, log2, check) = windows_long_record();
    let whole = format!("{}\u{1f511}yz", "x".repeat(125));
    let kept: String = whole.chars().take(126).collect();

    // The text the writer kept has one cut and one derivation.
    let mut cache = KeyCache::new(None);
    let pw = Password::from(kept.as_str());
    cache.rar5_judged(&pw, &salt, log2, Some(&check)).unwrap();
    assert_eq!(cache.derivations(), 1);
    let want = cache.rar5(&pw, &salt, log2).unwrap().clone();

    // The password as typed: the character cut fails, the unit cut fits.
    let mut cache = KeyCache::new(None);
    let pw = Password::from(whole.as_str());
    for _ in 0..3 {
        let got = cache.rar5_judged(&pw, &salt, log2, Some(&check)).unwrap();
        assert_eq!(got.keys().key, want.key);
        assert_eq!(got.keys().hash_key, want.hash_key);
    }
    assert_eq!(cache.derivations(), 2);
    // Another salt of the same session: derived under the kept cut first.
    let other = [9u8; 16];
    let under_units = Rar5Keys::derive_cut(whole.as_bytes(), &other, 0, None, Cut::Units).unwrap();
    let record = written_record(&under_units);
    cache.rar5_judged(&pw, &other, 0, Some(&record)).unwrap();
    assert_eq!(cache.derivations(), 3);
    // And a record made under the character cut, as rarkit's own writer
    // and the Linux and macOS programs make it, turns the session back.
    let third = [10u8; 16];
    let under_chars = Rar5Keys::derive(whole.as_bytes(), &third, 0, None).unwrap();
    let record = written_record(&under_chars);
    let got = cache.rar5_judged(&pw, &third, 0, Some(&record)).unwrap();
    assert_eq!(got.keys().key, under_chars.key);
    assert_eq!(cache.derivations(), 5);
    // With no record there is no verdict here and no second derivation.
    cache.rar5_judged(&pw, &[11; 16], 0, None).unwrap();
    assert_eq!(cache.derivations(), 6);
}

/// A password that is not it is `WrongPassword` as it always was, after
/// ONE derivation for a password with one cut and two for one with two,
/// however often the member is asked for; and the session's cut is left
/// where it was. One thread.
#[test]
fn rar5_judged_wrong_password_costs_at_most_one_more_derivation() {
    let (salt, log2, check) = windows_long_record();
    let key = '\u{1f511}';
    for (wrong, tries) in [
        ("Secret".to_owned(), 1),
        ("x".repeat(200), 1),
        ("\u{e9}".repeat(100), 1),
        (format!("{}{key}yz", "x".repeat(126)), 1),
        (format!("{}{key}", "x".repeat(125)).replace('x', "w"), 1),
        (format!("{}{key}yz", "w".repeat(125)), 2),
    ] {
        let mut cache = KeyCache::new(None);
        let pw = Password::from(wrong.as_str());
        for _ in 0..3 {
            let err = cache
                .rar5_judged(&pw, &salt, log2, Some(&check))
                .unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::WrongPassword));
        }
        assert_eq!(cache.derivations(), tries, "{}", wrong.chars().count());
        // The session still derives under the writer's cut.
        let first = Rar5Keys::derive(wrong.as_bytes(), &salt, log2, None).unwrap();
        assert_eq!(cache.rar5(&pw, &salt, log2).unwrap().key, first.key);
        assert_eq!(cache.derivations(), tries);
    }
}

// ---- The measured tables of spec K 5.1 and SPEC-API 4.5, a row a test ------
//
// The tables are the crate's own copies of `specs/vectors-K` (see
// `vectors-K/README`; `make mirror-check` holds them equal), each in its
// macOS and its Linux form: a row's test finds it in each and asks the
// same of both. Nothing of a row is written here but the name that finds
// it.

const UNIT: [(&str, &str); 2] = [
    (
        "macOS",
        include_str!("../../vectors-K/unit-vectors/unit-vectors-7.23-macos-arm64.tsv"),
    ),
    (
        "Linux",
        include_str!("../../vectors-K/unit-vectors/unit-vectors-7.23-linux-x86-64.tsv"),
    ),
];

const ZERO_BYTE: [(&str, &str); 2] = [
    (
        "macOS",
        include_str!("../../vectors-K/password-zero-byte/password-zero-byte-7.23-macos-arm64.tsv"),
    ),
    (
        "Linux",
        include_str!("../../vectors-K/password-zero-byte/password-zero-byte-7.23-linux-x86-64.tsv"),
    ),
];

/// The one archive the zero byte table names, which the reference wrote.
const UNDER_THE_HEAD: (&str, &[u8]) = (
    "rar5-member-encrypted-under-the-head.rar",
    include_bytes!("../../vectors-K/password-zero-byte/rar5-member-encrypted-under-the-head.rar"),
);

/// A table's rows under its heading, each as its fields.
fn table(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .skip(1)
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect()
}

/// The one file member of a RAR 5 archive as the reader delivers it under
/// `password`, or `None` where the reader refuses the archive or the
/// member's check fails.
fn rar5_member_under(archive: &[u8], password: &[u8]) -> Option<Vec<u8>> {
    use crate::{Disposition, MemberInfo, MemberOutcome, Sink};

    #[derive(Default)]
    struct Keep(Vec<(Vec<u8>, bool)>);
    impl Sink for Keep {
        type Out = Vec<u8>;
        fn open(&mut self, _: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Write(Vec::new()))
        }
        fn close(
            &mut self,
            _: &MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &MemberOutcome,
        ) -> crate::Result<()> {
            let sound = outcome.checksum_ok == Some(true) && !outcome.password_refused;
            self.0.push((out.unwrap_or_default(), sound));
            Ok(())
        }
    }
    let source: Arc<dyn crate::source::RangeSource> = Arc::new(archive.to_vec());
    let options = crate::ReadOptions::default().with_password(Some(Password::new(password)));
    let mut sink = Keep::default();
    crate::extract(vec![source], &options, &mut sink, &mut ()).ok()?;
    match sink.0.as_slice() {
        [(data, true)] => Some(data.clone()),
        _ => None,
    }
}

/// The bytes a table writes as hexadecimal digits.
fn bytes_of(digits: &str) -> Vec<u8> {
    assert_eq!(digits.len() % 2, 0, "{digits}");
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap())
        .collect()
}

/// A table's salt field: eight bytes, or `-` for a member with none.
fn salt_of(field: &str) -> Option<[u8; 8]> {
    (field != "-").then(|| bytes_of(field).try_into().unwrap())
}

/// The key of the RAR 3 derivation, for the unpack versions that take one.
fn aes_key(version: u8, password: &[u8], salt: Option<[u8; 8]>) -> Option<Rar4Key> {
    (version >= 29).then(|| Rar4Key::derive(password, salt).unwrap())
}

/// What the cipher spec K 3.2 selects delivers for `given`: the RAR 1.3
/// stream for the older container, and for every other the cipher the
/// unpack version names.
fn delivered_under(
    cipher: &str,
    version: u8,
    password: &[u8],
    salt: Option<[u8; 8]>,
    given: &[u8],
) -> Vec<u8> {
    let selected = if cipher == "RAR 1.3" {
        MemberCipher::V13(Rar13Stream::new(password))
    } else {
        let key = aes_key(version, password, salt);
        rar4_family_cipher(version, password, key.as_ref()).unwrap()
    };
    let mut member = MemberDecryptor::new(selected);
    let mut buf = given.to_vec();
    let plain = member.update(&mut buf);
    let mut out = plain.head.to_vec();
    let body = plain.body;
    out.extend_from_slice(&buf[..body]);
    member.finish().unwrap();
    out
}

/// The other direction: what a writer of that cipher makes of `plain`.
fn enciphered_under(
    cipher: &str,
    version: u8,
    password: &[u8],
    salt: Option<[u8; 8]>,
    plain: &[u8],
) -> Vec<u8> {
    let mut buf = plain.to_vec();
    match (cipher, version) {
        ("RAR 1.3", _) => Rar13Stream::new(password).encrypt(&mut buf),
        (_, 15) => Rar15Stream::new(password).apply(&mut buf),
        (_, 20 | 26) => Rar20Block::new(password).encrypt_blocks(&mut buf),
        _ => {
            let key = aes_key(version, password, salt).expect("an AES row");
            Aes128Enc::new(&key).encrypt(&mut buf).unwrap();
        }
    }
    buf
}

/// One row of spec K 5.1's table, found by its name in both forms of the
/// table: the encrypted bytes give the delivered ones under the row's
/// password and unpack version, the delivered ones give the encrypted
/// back, and the password with its last character changed gives others.
fn unit_row(name: &str) {
    for (form, text) in UNIT {
        let rows = table(text);
        let row = rows
            .iter()
            .find(|row| row[0] == name)
            .unwrap_or_else(|| panic!("{form} has no row {name}"));
        assert_eq!(row.len(), 10, "{form}: {name}");
        let (cipher, version) = (row[2].as_str(), row[3].parse::<u8>().unwrap());
        let password = row[4].as_bytes();
        assert_eq!(password.len(), row[5].parse::<usize>().unwrap(), "{name}");
        let salt = salt_of(&row[6]);
        let (given, delivered) = (bytes_of(&row[7]), bytes_of(&row[8]));
        assert_eq!(given.len(), delivered.len(), "{form}: {name}");
        assert_eq!(
            delivered_under(cipher, version, password, salt, &given),
            delivered,
            "{form}: {name}, read"
        );
        assert_eq!(
            enciphered_under(cipher, version, password, salt, &delivered),
            given,
            "{form}: {name}, written"
        );
        let mut another = password.to_vec();
        *another.last_mut().unwrap() ^= 1;
        assert_ne!(
            delivered_under(cipher, version, &another, salt, &given),
            delivered,
            "{form}: {name}, under another password"
        );
    }
}

/// A test for each row, and one that the table has these rows, in this
/// order, and no other.
macro_rules! unit_rows {
    ($($test:ident: $row:literal,)*) => {
        $(
            #[test]
            fn $test() {
                unit_row($row);
            }
        )*

        #[test]
        fn the_unit_table_has_the_rows_tested_and_no_other() {
            for (form, text) in UNIT {
                let rows: Vec<String> = table(text).into_iter().map(|row| row[0].clone()).collect();
                assert_eq!(rows, [$($row),*], "{form}");
            }
        }
    };
}

unit_rows! {
    unit_row_of_the_older_container: "1.3",
    unit_row_of_version_15: "1.5",
    unit_row_of_an_odd_password_under_version_20: "2.0 odd",
    unit_row_of_an_even_password_under_version_20: "2.0 even",
    unit_row_of_a_password_of_one_block: "2.0 at 16",
    unit_row_of_a_password_one_past_a_block: "2.0 at 17",
    unit_row_of_version_26: "2.0 by version 26",
    unit_row_of_a_member_with_no_salt: "3 no salt",
    unit_row_of_a_seed_under_one_block: "3 short seed",
    unit_row_of_a_seed_past_one_block: "3 long seed",
    unit_row_of_a_seed_one_short_of_a_block: "3 at 27",
    unit_row_of_a_seed_of_one_block: "3 at 28",
    unit_row_of_version_36: "3 by version 36",
}

/// One row of SPEC-API 4.5's table, found by its cipher and its program in
/// both forms: a password ends at its first zero byte. Under the head, a
/// zero byte and the tail the row's bytes are delivered, which are the
/// bytes delivered under the head alone, and not under head and tail
/// joined.
fn zero_byte_row(cipher: &str, program: &str) {
    for (form, text) in ZERO_BYTE {
        let rows = table(text);
        let row = rows
            .iter()
            .find(|row| row[0] == cipher && row[1] == program)
            .unwrap_or_else(|| panic!("{form} has no row {cipher}, {program}"));
        assert_eq!(row.len(), 9, "{form}: {cipher}, {program}");
        let (head, tail) = (row[2].as_bytes(), row[3].as_bytes());
        let with_zero = [head, &[0], tail].concat();
        let joined = [head, tail].concat();
        let delivered = bytes_of(&row[6]);
        let what = format!("{form}: {cipher}, {program}");
        if cipher == "RAR 5" {
            // The row names the archive kept beside the table, which the
            // reference wrote under the head.
            assert_eq!(row[5], UNDER_THE_HEAD.0, "{what}");
            for password in [head, &with_zero[..]] {
                assert_eq!(
                    rar5_member_under(UNDER_THE_HEAD.1, password).as_ref(),
                    Some(&delivered),
                    "{what}"
                );
            }
            assert_eq!(
                rar5_member_under(UNDER_THE_HEAD.1, &joined),
                None,
                "{what}: head and tail joined"
            );
            continue;
        }
        let version = match cipher {
            "RAR 1.3" => 2,
            "RAR 1.5" => 15,
            "RAR 2.0" => 20,
            "RAR 3/4 AES" | "RAR 3/4 AES, no salt" => 29,
            other => panic!("{form}: a cipher this test does not know: {other}"),
        };
        let salt = salt_of(&row[4]);
        let given = bytes_of(&row[5]);
        assert_eq!(
            delivered_under(cipher, version, &with_zero, salt, &given),
            delivered,
            "{what}: head, zero byte, tail"
        );
        assert_eq!(
            delivered_under(cipher, version, head, salt, &given),
            delivered,
            "{what}: the head alone"
        );
        assert_ne!(
            delivered_under(cipher, version, &joined, salt, &given),
            delivered,
            "{what}: head and tail joined"
        );
    }
}

/// A test for each row, and one that the table has these rows, in this
/// order, and no other.
macro_rules! zero_byte_rows {
    ($($test:ident: $cipher:literal, $program:literal;)*) => {
        $(
            #[test]
            fn $test() {
                zero_byte_row($cipher, $program);
            }
        )*

        #[test]
        fn the_zero_byte_table_has_the_rows_tested_and_no_other() {
            for (form, text) in ZERO_BYTE {
                let rows: Vec<(String, String)> = table(text)
                    .into_iter()
                    .map(|row| (row[0].clone(), row[1].clone()))
                    .collect();
                let tested: Vec<(String, String)> = [$(($cipher, $program)),*]
                    .iter()
                    .map(|(cipher, program)| ((*cipher).to_owned(), (*program).to_owned()))
                    .collect();
                assert_eq!(rows, tested, "{form}");
            }
        }
    };
}

zero_byte_rows! {
    zero_byte_under_rar_13_as_rar_reads_it: "RAR 1.3", "rar";
    zero_byte_under_rar_13_as_unrar_reads_it: "RAR 1.3", "unrar";
    zero_byte_under_rar_15_as_rar_reads_it: "RAR 1.5", "rar";
    zero_byte_under_rar_15_as_unrar_reads_it: "RAR 1.5", "unrar";
    zero_byte_under_rar_20_as_rar_reads_it: "RAR 2.0", "rar";
    zero_byte_under_rar_20_as_unrar_reads_it: "RAR 2.0", "unrar";
    zero_byte_under_aes_with_no_salt_as_rar_reads_it: "RAR 3/4 AES, no salt", "rar";
    zero_byte_under_aes_with_no_salt_as_unrar_reads_it: "RAR 3/4 AES, no salt", "unrar";
    zero_byte_under_aes_with_a_salt_as_rar_reads_it: "RAR 3/4 AES", "rar";
    zero_byte_under_aes_with_a_salt_as_unrar_reads_it: "RAR 3/4 AES", "unrar";
    zero_byte_under_rar_5_as_rar_reads_it: "RAR 5", "rar";
    zero_byte_under_rar_5_as_unrar_reads_it: "RAR 5", "unrar";
}

// ---- what a member wipes when it ends, and what its key's owner does ---

/// Bytes of schedule a key holds on this machine: the block cipher's and
/// the wide chain's where there is one.
#[cfg(feature = "test-support")]
fn schedule_bytes<C>(has_wide: bool) -> u64 {
    let wide = if has_wide { WIDE_CHAIN_BYTES } else { 0 };
    (std::mem::size_of::<C>() + wide) as u64
}

#[cfg(all(
    feature = "test-support",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const WIDE_CHAIN_BYTES: usize = std::mem::size_of::<super::wide_dec::Chain>();
#[cfg(all(
    feature = "test-support",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const WIDE_CHAIN_BYTES: usize = 0;

/// Whether this machine gives a key a wide chain, asked of a chain built
/// the way the key cache builds its own.
#[cfg(feature = "test-support")]
fn machine_has_wide() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    return super::wide_dec::Chain::new(&[0u8; 32]).is_some();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    false
}

/// THE COUNT of the bytes a member's chain wipes at its end, on the key
/// cache's schedules (`MemberCipher::aes256_on`, `aes128_on`), by the
/// counted hook `cbc::wiped` and not by reading freed memory.
///
/// A member borrows its key's schedules and wipes only what is its own:
/// the 16 bytes of its chaining value. Until 13 Oct 2026 it held a copy
/// of both schedules and wiped the copy, 1,208 bytes a RAR 5 member and
/// 952 a RAR 4 family one on aarch64, which this test pinned as the red.
/// While members come and go the key's schedules are wiped by no one.
#[cfg(feature = "test-support")]
#[test]
fn a_member_wipes_its_chaining_value_and_no_schedule_when_it_ends() {
    use super::cbc::wiped;
    const MEMBERS: u64 = 1000;
    let pw = Password::from("pw");
    let mut cache = KeyCache::new(None);
    let iv = [0x3Cu8; 16];
    // Chains made above this line on this thread are gone by here.
    let schedules = wiped::schedules();

    let keys = cache.rar5_cipher(&pw, &[5; 16], 0).unwrap();
    let before = wiped::member_bytes();
    for _ in 0..MEMBERS {
        let mut member = MemberDecryptor::new(MemberCipher::aes256_on(keys, &iv));
        let mut buf = [0x5Au8; 64];
        assert_eq!(member.update(&mut buf).body, 64);
    }
    let a_member = (wiped::member_bytes() - before) / MEMBERS;
    eprintln!("a RAR 5 member wipes {a_member} bytes at its end");
    assert_eq!(a_member, 16);

    let key = cache.rar4_cipher(&pw, Some([7; 8])).unwrap();
    let before = wiped::member_bytes();
    for _ in 0..MEMBERS {
        let mut member = MemberDecryptor::new(MemberCipher::aes128_on(key));
        let mut buf = [0x5Au8; 64];
        assert_eq!(member.update(&mut buf).body, 64);
    }
    let a_member = (wiped::member_bytes() - before) / MEMBERS;
    eprintln!("a RAR 4 family member wipes {a_member} bytes at its end");
    assert_eq!(a_member, 16);

    assert_eq!(
        wiped::schedules(),
        schedules,
        "a member's end wiped a schedule the key cache still holds"
    );
    // The member's cipher is no longer a copy of the schedules.
    assert!(std::mem::size_of::<MemberCipher>() <= 128);
}

/// THE OWNER'S WIPE STILL RUNS, once a key, by the counted hook: the
/// schedules are wiped when the key cache's slot goes, at the cache's end
/// and on eviction, and at no other moment while no member is on them.
#[cfg(feature = "test-support")]
#[test]
fn the_key_caches_end_and_eviction_wipe_each_keys_schedules_once() {
    use super::cbc::wiped;
    let pw = Password::from("pw");
    let wide = machine_has_wide();
    let five = schedule_bytes::<aes::Aes256Dec>(wide);
    let four = schedule_bytes::<aes::Aes128Dec>(wide);

    // The cache's end: one RAR 5 key and one RAR 4 family key.
    let (n0, b0) = wiped::schedules();
    {
        let mut cache = KeyCache::new(None);
        let iv = [1u8; 16];
        let keys = cache.rar5_cipher(&pw, &[5; 16], 0).unwrap();
        for _ in 0..10 {
            let mut member = MemberDecryptor::new(MemberCipher::aes256_on(keys, &iv));
            let mut buf = [0u8; 32];
            assert_eq!(member.update(&mut buf).body, 32);
        }
        let key = cache.rar4_cipher(&pw, Some([7; 8])).unwrap();
        drop(MemberDecryptor::new(MemberCipher::aes128_on(key)));
        assert_eq!(
            wiped::schedules(),
            (n0, b0),
            "wiped while the cache holds them"
        );
    }
    assert_eq!(wiped::schedules(), (n0 + 2, b0 + five + four));

    // Eviction: one more key than the cache has slots wipes exactly the
    // evicted key's schedules, and the cache's end the rest.
    let (n0, b0) = wiped::schedules();
    {
        let mut cache = KeyCache::new(None);
        for salt in 0..CACHE_SLOTS as u8 {
            cache.rar5_cipher(&pw, &[salt; 16], 0).unwrap();
        }
        assert_eq!(wiped::schedules(), (n0, b0));
        cache.rar5_cipher(&pw, &[0xEE; 16], 0).unwrap();
        assert_eq!(wiped::schedules(), (n0 + 1, b0 + five));
    }
    let slots = CACHE_SLOTS as u64;
    assert_eq!(
        wiped::schedules(),
        (n0 + 1 + slots, b0 + (1 + slots) * five)
    );
}

/// A member that OUTLIVES its key's slot keeps the schedules it is
/// deciphering on, and they are wiped when it ends: later than the slot,
/// never not at all, and still once.
#[cfg(feature = "test-support")]
#[test]
fn a_member_that_outlives_the_key_cache_wipes_the_schedules_at_its_own_end() {
    use super::cbc::wiped;
    let pw = Password::from("pw");
    let five = schedule_bytes::<aes::Aes256Dec>(machine_has_wide());
    let iv = [9u8; 16];
    let data: Vec<u8> = (0..160u32).map(|i| (i * 31 + 7) as u8).collect();

    let mut cache = KeyCache::new(None);
    let keys = cache.rar5_cipher(&pw, &[5; 16], 0).unwrap();
    let mut want = data.clone();
    MemberDecryptor::new(MemberCipher::aes256_on(keys, &iv)).update(&mut want);
    let mut member = MemberDecryptor::new(MemberCipher::aes256_on(keys, &iv));
    let (n0, b0) = wiped::schedules();
    drop(cache);
    assert_eq!(wiped::schedules(), (n0, b0), "wiped under a live member");
    // It still deciphers, and to the same bytes.
    let mut got = data.clone();
    assert_eq!(member.update(&mut got).body, data.len());
    assert_eq!(got, want);
    let before = wiped::member_bytes();
    drop(member);
    assert_eq!(wiped::schedules(), (n0 + 1, b0 + five));
    assert_eq!(wiped::member_bytes() - before, 16);
}

/// A chain that is not on the key cache's schedules (`MemberCipher::aes256`,
/// the tests' and the seam's form) owns its own, and wipes them, its kept
/// key and its chaining value at its end.
#[cfg(feature = "test-support")]
#[test]
fn a_chain_with_schedules_of_its_own_wipes_them_at_its_end() {
    use super::cbc::wiped;
    let keys = Rar5Keys::derive(b"pw", &[4; 16], 0, None).unwrap();
    let (n0, b0) = wiped::schedules();
    let before = wiped::member_bytes();
    let mut member = MemberDecryptor::new(MemberCipher::aes256(&keys, &[6; 16]));
    let mut buf = [0u8; 64];
    assert_eq!(member.update(&mut buf).body, 64);
    drop(member);
    // No run reached the wide chain's floor, so none was built and the
    // key was still kept.
    assert_eq!(
        wiped::schedules(),
        (n0 + 1, b0 + schedule_bytes::<aes::Aes256Dec>(false))
    );
    let kept_key = if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        32
    } else {
        0
    };
    assert_eq!(wiped::member_bytes() - before, 16 + kept_key);
}
