//! Spec G's writers, from the write path's own side. What is here is what
//! an integration test cannot see: this crate's test-only instrumentation.

/// The width of the pool [`on_own_pool`] builds.
const OWN_POOL: usize = 12;

/// Runs `work` on a rayon pool of this file's own, [`OWN_POOL`] threads
/// wide, and answers what it answers.
///
/// **A test states the pool width it needs and never takes it from the
/// machine.** The writer holds a write to `min(workers, the caller's
/// pool)` helpers, so a test that read the global pool's width, which is
/// the machine's, held one thing on a wide box and another on a hosted
/// runner of two threads (10 Oct 2026: `chains_ahead_stay_inside_the_
/// helper_count` failed there with the engine right). The census, the
/// read-ahead count and the BLAKE2sp allowance these tests read are the
/// CALLING thread's, and `install` runs `work` on one thread of the pool
/// from its first line to its last, so they are read where they were
/// written.
fn on_own_pool<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(OWN_POOL)
            .build()
            .expect("a pool of this file's own")
    })
    .install(|| {
        assert_eq!(rayon::current_num_threads(), OWN_POOL);
        work()
    })
}

/// **The BLAKE2sp leaf team is REACHABLE through the write path**, the
/// other half of the read path's
/// `the_read_path_gives_its_hasher_the_policy_worker_ceiling`. Every
/// shipped write built its member hasher at ONE worker until this was
/// wired, so spec L's "when the caller's `max_workers` allows it" could
/// not be reached by any caller at any policy (API 8.2's table names the
/// leaf team as a stage `max_workers` bounds).
///
/// A ceiling is not a demand, so this asserts where the figure LANDS and
/// nothing about threads: whether a team then engages is the hasher's own
/// batch gate, which `checksum::blake2sp`'s tests hold.
///
/// The figure is also held to what the helper budget
/// leaves (`engine::Run::digest_threads`): with `workers` unset that is
/// the pool's width beside the hashing thread, so on a box whose pool is
/// narrower than the ceiling the team is the pool's and not the ceiling's.
///
/// And this member is STORED, so its digest is the copy's
/// (`engine::Run::copy_digest`), whose stages are paid out of the same
/// helpers before the team is: the digest stage alone on a pool of one,
/// the reader as well from a pool of two. The team has what they leave,
/// which is nothing on a pool of one or two and `pool - 2` beside the
/// hashing thread above that. Until 3 Oct 2026 this test expected
/// `1 + pool`, which holds only where the pool is nine or wider: it was
/// red at 1, 2, 3, 4 and 8 CPUs under `taskset` and on a 2 core hosted
/// runner, and green on every box this project gates on.
#[test]
fn the_write_path_gives_its_hasher_the_policy_worker_ceiling() {
    // On a pool of this file's own, of a stated width: [`on_own_pool`].
    on_own_pool(the_write_path_gives_its_hasher_the_policy_worker_ceiling_there);
}

fn the_write_path_gives_its_hasher_the_policy_worker_ceiling_there() {
    use crate::checksum::blake2sp;
    use crate::write::{ChecksumKind, MemberSpec, Payload, WriteOptions, Writer};

    // Past the hasher's stage, so the member is one a team could want.
    let data = vec![0xA5u8; 3 << 20];
    for workers in [1usize, 2, 8] {
        let options = WriteOptions {
            checksum: ChecksumKind::Blake2sp,
            memory: crate::MemoryPolicy {
                max_workers: workers,
                ..Default::default()
            },
            ..WriteOptions::default()
        };
        blake2sp::forget_allowance();
        let mut writer = Writer::new(options).expect("options");
        writer
            .add(MemberSpec {
                name: b"m.bin",
                payload: Payload::Bytes(&data),
                mtime: None,
                attributes: 0,
                host_os: crate::write::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish");
        let allowance = blake2sp::last_allowance();
        let pool = OWN_POOL;
        // The stored copy's stages take their helpers first.
        let stages = pool.min(2);
        let expected = if workers <= 1 || cfg!(not(feature = "parallel")) {
            1
        } else {
            workers.min(1 + pool - stages)
        };
        assert_eq!(
            allowance, expected,
            "a write at max_workers {workers} hashed its member at {allowance}"
        );
    }
}

/// **The recovery copy is reserved once and never grows**, which is what
/// keeps a create run's peak RSS flat when the run is repeated.
///
/// The measurement behind it, on a laptop, 20 Sep 2026: a `two_arm`
/// process running `g/create/rar5/m0/rr` for 25 rounds instead of 3 went
/// from 215 MiB of peak RSS to 1699, climbing 67.3 MiB a round - one
/// whole archive - and a 60 round run reached 3710 MiB still climbing.
/// The cause is not a structure rarkit holds: on macOS a heap buffer
/// REALLOCATED while it is larger than about four megabytes leaves its
/// whole dirty length resident for the life of the process. One realloc
/// is enough, and the same bytes asked for at their final size in one
/// call are reused round after round. `Out::keep_a_copy` says the rest.
///
/// So this asserts the property the fix rests on and not a peak RSS
/// figure, which no test on a shared box can hold: the copy is asked for
/// at a bound and the writer never has to grow it.
#[test]
fn the_recovery_copy_is_reserved_and_never_grows() {
    use crate::write::{MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

    // Well past the four megabytes the platform's threshold sits at, so
    // the buffer under test is one a growth would actually strand.
    let data = vec![0x5Au8; 9 << 20];
    let shapes: [(WriteFormat, WriteMethod, Option<u64>); 4] = [
        (WriteFormat::Rar5, WriteMethod::Stored, None),
        (
            WriteFormat::Rar5,
            WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            None,
        ),
        (WriteFormat::Rar5, WriteMethod::Stored, Some(4 << 20)),
        (
            WriteFormat::Rar4(crate::write::Rar4Version::V29),
            WriteMethod::Stored,
            None,
        ),
    ];
    for (format, method, volume) in shapes {
        let mut writer = Writer::new(WriteOptions {
            format,
            method,
            filters: crate::write::FilterPolicy::Off,
            recovery_percent: Some(5),
            volume_file_size: volume,
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"payload.bin",
                payload: Payload::Bytes(&data),
                mtime: None,
                attributes: 0o100644,
                host_os: crate::write::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        crate::write::out::forget_tee_growth();
        let mut out = std::io::Cursor::new(Vec::new());
        if volume.is_some() {
            let mut volumes = Collecting(Vec::new());
            writer.finish_volumes(&mut volumes).expect("finish volumes");
        } else {
            writer.finish_seek(&mut out).expect("finish");
        }
        let grew = crate::write::out::tee_grew();
        assert_eq!(
            grew, 0,
            "{format:?} {method:?} volumes {volume:?}: the recovery copy grew {grew} times"
        );
    }
}

/// A volume provider for the test above: it keeps what it is handed and
/// asks for nothing else.
#[cfg(test)]
struct Collecting(Vec<Vec<u8>>);

impl crate::write::VolumeOut for Collecting {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> crate::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> crate::Result<()> {
        self.0.push(volume);
        Ok(())
    }
}

/// **What the withdrawn reserve did to peak RSS**, kept as the
/// instrument that measured it rather than as a claim about it.
///
/// The second half of the 21 Sep 2026 decision was to reserve `Run::packed` once a run
/// to `Run::packed_bound`, so that the compressed create legs stopped
/// retaining about one archive a round through a doubling realloc chain
/// (found in package G's work: on macOS a heap buffer
/// reallocated while larger than about four megabytes leaves its whole
/// dirty length resident for the life of the process).
///
/// It was built and measured and it did NOT land, because it is a trade
/// and not a win. On macOS 27.0, peak RSS growth from 3 rounds to 25 in
/// one process, three repeats each, ranges non-overlapping:
///
/// | leg | with the reserve | without |
/// |---|---|---|
/// | `g/create/rar5/m3/vol+rr` | +8.6, +11.4, +8.0 MiB | +291.4, +286.6, +283.0 |
/// | `g/create/rar5/m3` | +759.7, +760.3, +773.0 | +589.0, +575.5, +597.6 |
///
/// Flat on one leg, 7.8 MiB a round worse on another, and no
/// specification says which to prefer.
/// This also CORRECTS `Out::keep_a_copy`'s sentence
/// about an over-reserve costing address space and not memory.
///
/// What this test pins meanwhile is the counter itself and the shape of
/// the walk: the buffer is grown a BOUNDED number of times per member
/// and nothing compounds across members, so a successor re-measuring the
/// reserve has a working instrument and a baseline to compare against.
#[test]
fn the_packed_buffer_is_grown_a_bounded_number_of_times() {
    use crate::write::{MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

    let data = vec![0x5Au8; 9 << 20];
    let shapes: [(WriteFormat, u8, Option<u64>, bool); 5] = [
        (WriteFormat::Rar5, 3, None, false),
        (WriteFormat::Rar5, 3, Some(2 << 20), false),
        (WriteFormat::Rar5, 5, None, false),
        (
            WriteFormat::Rar4(crate::write::Rar4Version::V29),
            3,
            None,
            false,
        ),
        (WriteFormat::Rar5, 3, None, true),
    ];
    for (format, level, volume, solid) in shapes {
        let mut writer = Writer::new(WriteOptions {
            format,
            method: WriteMethod::Compressed {
                level,
                dictionary: None,
            },
            filters: crate::write::FilterPolicy::Off,
            solid,
            volume_file_size: volume,
            ..WriteOptions::default()
        })
        .expect("options");
        for name in [b"one.bin".as_slice(), b"two.bin".as_slice()] {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(&data),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: crate::write::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        crate::write::engine::forget_packed_growth();
        let report = if volume.is_some() {
            let mut volumes = Collecting(Vec::new());
            writer.finish_volumes(&mut volumes).expect("finish volumes")
        } else {
            let mut out = std::io::Cursor::new(Vec::new());
            writer.finish_seek(&mut out).expect("finish")
        };
        let grew = crate::write::engine::packed_grew();
        let label = format!("{format:?} -m{level} volumes {volume:?} solid {solid}");
        // A 9 MiB member's doubling chain is about a dozen steps, and
        // TWO members of the same size are written: anything that
        // carried over from the first to the second would roughly
        // double this, which is what the bound is here to catch.
        assert!(
            grew <= 30,
            "{label}: the packed buffer changed size {grew} times over two members"
        );
        // The rule that DID land: the figure counts bytes
        // IN USE. This member packs down to a sliver of its length, so a
        // figure counting capacity would report at least the member's
        // size here.
        if solid {
            // A solid run carries the encoder's HISTORY across its
            // members by design (spec G 3.9), so its working memory
            // legitimately passes any one member's size.
            continue;
        }
        // Since 28 Sep 2026 the figure also states the encoder's match
        // finder, which is sized from the dictionary and the member and
        // never from the packed buffer (68 MiB of chains here at level 3),
        // so the bound is the member's length PLUS that term, and still
        // below a figure that counted the buffer's capacity as well.
        // The figure also states the parses in flight (the -m4 and -m5
        // memory work, 28 Sep 2026), bounded by the encoder's own
        // `flight_term` for a flush of the whole member.
        let dictionary = 2 << 20; // the default, fitted to a 9 MiB member
        let finder = match format {
            WriteFormat::Rar5 => {
                let encoder = crate::encode::rar5::Rar5Encoder::new(
                    crate::encode::rar5::EncodeOptions::for_level(level, dictionary),
                );
                encoder.member_held_bytes(data.len(), None) + encoder.flight_term(data.len())
            }
            WriteFormat::Rar4(_) => {
                let encoder = crate::encode::rar29::Rar29Encoder::new(
                    crate::encode::rar29::EncodeOptions::for_level(level, dictionary),
                );
                encoder.member_held_bytes(data.len(), None) + encoder.flight_term(data.len())
            }
        };
        assert!(
            report.peak_working_memory < data.len() as u64 + finder,
            "{label}: a {} byte member that packs down small reported {} bytes of \
             working memory, {finder} of them its finder and parses",
            data.len(),
            report.peak_working_memory
        );
    }
}

/// **The mark is carried ACROSS the run, not read off at the end of it**
/// (decided 21 Sep 2026).
///
/// This is the half of the rule that a `len()` swap alone would have
/// got wrong, and it is built so that it FAILS against the snapshot the
/// field used to be. Two runs are compared:
///
/// - one member of incompressible noise, large, followed by a tiny one;
/// - the tiny member by itself.
///
/// The packed buffer holds the TINY member's bytes when either run
/// finishes, so a figure read off at report time is about the same for
/// both and the large member leaves no trace at all. A high-water mark
/// carried across the run remembers it, and the first run's figure is
/// the larger by most of the large member.
///
/// Incompressible on purpose: a member that packs away to nothing would
/// make this assertion pass for the wrong reason.
///
/// **Checked against the snapshot rather than assumed to bite.** With
/// `Run::report` answering `working_now()` alone, as the field did
/// before 21 Sep 2026, both runs report 1,048,673 bytes - the SAME number
/// to the byte, which is the copy buffer and a header - and the six
/// megabyte member leaves no trace whatsoever.
#[test]
fn the_working_memory_figure_remembers_a_member_the_run_has_finished_with() {
    use crate::write::{MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

    // A cheap linear congruential stream: it does not compress, so the
    // packed output really is about the member's own size.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut big: Vec<u8> = (0..(6usize << 20))
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as u8
        })
        .collect();
    // Since 28 Sep 2026 a member this incompressible is written STORED by
    // spec G 3.8.3's samples, and a stored member has no packed buffer to
    // remember, so this row would measure nothing. A run of 512 zero bytes
    // in the middle of the samples of the first five of its sixteen
    // segments outvotes the rule at every size (two do under 128 MiB; from
    // 128 MiB four may compress since 1 Oct 2026), and
    // the packed output is still about
    // the member's own size (`write::store`; the plain stream is stored,
    // `a_member_the_samples_store_leaves_no_packed_buffer` below).
    for segment in 0..5 {
        let middle = (2 * segment + 1) * big.len() / 32;
        big[middle - 256..middle + 256].fill(0);
    }
    let tiny = vec![b'x'; 512];

    let peak_of = |members: &[(&[u8], &[u8])]| -> u64 {
        let mut writer = Writer::new(WriteOptions {
            format: WriteFormat::Rar5,
            method: WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            filters: crate::write::FilterPolicy::Off,
            ..WriteOptions::default()
        })
        .expect("options");
        for (name, body) in members {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(body),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: crate::write::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out = std::io::Cursor::new(Vec::new());
        writer
            .finish_seek(&mut out)
            .expect("finish")
            .peak_working_memory
    };

    let after_big = peak_of(&[(b"big.bin", &big), (b"tiny.txt", &tiny)]);
    let alone = peak_of(&[(b"tiny.txt", &tiny)]);

    // Most of the large member, allowing for the compressor not quite
    // failing to shrink noise. Against the snapshot this field used to
    // be, the two figures differ by almost nothing and this fails.
    let least = (big.len() as u64) / 2;
    assert!(
        after_big > alone + least,
        "a run that wrote a {} byte member and then a {} byte one reported {} bytes of \
         working memory against {} for the tiny member alone, so the large member left \
         no trace and the figure is not a high-water mark",
        big.len(),
        tiny.len(),
        after_big,
        alone
    );
}

/// The row above moved onto a stream with two planted runs, and this is
/// why, pinned the other way: the PLAIN stream it used is now written
/// STORED by spec G 3.8.3's samples, so the run holds no packed buffer
/// for it at all and its high-water mark does not follow the member.
#[test]
fn a_member_the_samples_store_leaves_no_packed_buffer() {
    use crate::write::{MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let big: Vec<u8> = (0..(6usize << 20))
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 33) as u8
        })
        .collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        filters: crate::write::FilterPolicy::Off,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"big.bin",
            payload: Payload::Bytes(&big),
            mtime: None,
            attributes: 0o100644,
            host_os: crate::write::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = std::io::Cursor::new(Vec::new());
    let report = writer.finish_seek(&mut out).expect("finish");
    let archive = out.into_inner();
    assert!(
        archive.len() < big.len() + 200,
        "{} bytes for a stored {} byte member",
        archive.len(),
        big.len()
    );
    // The run's one judge is stated since 1 Oct 2026
    // (`store::Judges::held_bytes`): 2 MiB of tables that took the member's
    // samples, and none of the member's bytes.
    let judge = crate::write::store::Judge::MOST_BYTES;
    assert!(
        report.peak_working_memory < (big.len() as u64) / 2 + judge,
        "a stored {} byte member left a {} byte high-water mark",
        big.len(),
        report.peak_working_memory
    );
    assert!(report.peak_working_memory >= judge);
}

/// **A span's digest taken BESIDE its copy writes the archive the serial
/// copy writes, byte for byte**, on every shape that path reaches: a
/// single seekable archive, a volume set whose fragments each carry their
/// own digest, CRC32 and BLAKE2sp, encrypted and not, RAR 5 and RAR 4.
///
/// The serial arm is `max_workers: 1`, which `engine::digest_beside`
/// refuses a second thread; the other arm is the default ceiling. Both
/// arms are asserted to have taken the path they name, so neither
/// comparison can pass by both arms running the same code.
// Helper threads exist only with the `parallel` feature: without it a
// write is one thread in all (SPEC-API 7.2).
#[cfg(feature = "parallel")]
#[test]
fn a_digest_beside_the_copy_writes_the_serial_bytes() {
    use crate::write::engine::BESIDE;
    use crate::write::{
        ChecksumKind, Entropy, MemberSpec, Payload, Rar4Version, WriteFormat, WriteMethod,
        WriteOptions, Writer,
    };
    use crate::Password;

    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let data: Vec<u8> = (0..(13 << 20) + 777)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    let small = &data[..100_003];

    struct Shape {
        name: &'static str,
        format: WriteFormat,
        checksum: ChecksumKind,
        password: bool,
        headers: bool,
        volumes: Option<u64>,
    }
    let shapes = [
        Shape {
            name: "rar5 crc32",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Crc32,
            password: false,
            headers: false,
            volumes: None,
        },
        Shape {
            name: "rar5 blake2sp",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Blake2sp,
            password: false,
            headers: false,
            volumes: None,
        },
        Shape {
            name: "rar5 pw",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Crc32,
            password: true,
            headers: false,
            volumes: None,
        },
        Shape {
            name: "rar5 hp",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Crc32,
            password: true,
            headers: true,
            volumes: None,
        },
        Shape {
            name: "rar5 vol",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Crc32,
            password: false,
            headers: false,
            volumes: Some(5 << 20),
        },
        Shape {
            name: "rar5 vol blake2sp",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Blake2sp,
            password: false,
            headers: false,
            volumes: Some(5 << 20),
        },
        Shape {
            name: "rar5 vol pw",
            format: WriteFormat::Rar5,
            checksum: ChecksumKind::Crc32,
            password: true,
            headers: false,
            volumes: Some(5 << 20),
        },
        Shape {
            name: "rar4 crc32",
            format: WriteFormat::Rar4(Rar4Version::V29),
            checksum: ChecksumKind::Crc32,
            password: false,
            headers: false,
            volumes: None,
        },
        Shape {
            name: "rar4 vol pw",
            format: WriteFormat::Rar4(Rar4Version::V29),
            checksum: ChecksumKind::Crc32,
            password: true,
            headers: false,
            volumes: Some(5 << 20),
        },
    ];
    for shape in &shapes {
        let write = |workers: usize| -> (Vec<Vec<u8>>, usize) {
            let options = WriteOptions {
                format: shape.format,
                method: WriteMethod::Stored,
                checksum: shape.checksum,
                password: shape.password.then(|| Password::new(b"beside")),
                encrypt_headers: shape.headers,
                volume_size: shape.volumes,
                entropy: Entropy::Seeded([9; 32]),
                filters: crate::write::FilterPolicy::Off,
                memory: crate::MemoryPolicy {
                    max_workers: workers,
                    ..Default::default()
                },
                ..WriteOptions::default()
            };
            BESIDE.with(|count| count.set(0));
            let mut writer = Writer::new(options).expect("options");
            for (name, body) in [(&b"big.bin"[..], &data[..]), (&b"small.bin"[..], small)] {
                writer
                    .add(MemberSpec {
                        name,
                        payload: Payload::Bytes(body),
                        mtime: None,
                        attributes: 0o100644,
                        host_os: crate::write::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let volumes = if shape.volumes.is_some() {
                let mut volumes: Vec<Vec<u8>> = Vec::new();
                writer.finish_volumes(&mut volumes).expect("finish_volumes");
                volumes
            } else {
                let mut out = std::io::Cursor::new(Vec::new());
                writer.finish_seek(&mut out).expect("finish_seek");
                vec![out.into_inner()]
            };
            (volumes, BESIDE.with(std::cell::Cell::get))
        };
        let (serial, serial_spans) = write(1);
        let (beside, beside_spans) = write(8);
        assert_eq!(
            serial_spans, 0,
            "{}: the serial arm took the thread",
            shape.name
        );
        assert!(
            beside_spans > 0,
            "{}: the default arm never took the thread",
            shape.name
        );
        assert_eq!(
            serial.len(),
            beside.len(),
            "{}: volume counts differ",
            shape.name
        );
        for (i, (a, b)) in serial.iter().zip(&beside).enumerate() {
            assert!(
                a == b,
                "{}: volume {i} differs between the serial and the beside copy",
                shape.name
            );
        }
    }
}

/// **A member's cipher fed through the fused push writes what one
/// in-place encryption of the zero-padded member writes**, whatever the
/// chunk lengths: aligned and unaligned, shorter than a block, a block
/// and one byte, a mebibyte, in both key sizes (RAR 5's AES-256 and the
/// RAR 4 family's AES-128). The reference arm encrypts the whole padded
/// member in place, in one call, under the key and IV the same seeded
/// draws produce, so it shares no code with `MemberCrypt::push`'s
/// splitting and carrying.
#[test]
fn the_fused_member_cipher_is_one_in_place_encryption() {
    use crate::carry::b_writers::write_entropy::Seeded;
    use crate::crypto::{Aes128Enc, Aes256Enc, Rar4Key, Rar5Keys};
    use crate::write::crypt::{ArchiveKey, Draw, MemberCrypt, RAR5_KDF_LOG2};
    use crate::Password;

    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let data: Vec<u8> = (0..(3 << 20) + 4099).map(|_| next() as u8).collect();
    let password = Password::new(b"fused");
    let seed = [4u8; 32];
    let splits: [&[usize]; 5] = [
        &[1, 15, 16, 17, 31, 33, 1 << 20, 3, 4099],
        &[16, 16, 16, 1 << 20],
        &[7],
        &[1 << 20],
        &[5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 65_537],
    ];
    for rar4 in [false, true] {
        for split in splits {
            // The arm under test.
            let mut draw = Draw::Seeded(Seeded { seed, counter: 0 });
            let key = ArchiveKey::derive(Some(&password), rar4, &mut draw).unwrap();
            let mut crypt = MemberCrypt::new(&key, &mut draw)
                .unwrap()
                .expect("a password gives a cipher");
            let mut got = Vec::new();
            let mut out = Vec::new();
            let mut at = 0;
            let mut i = 0;
            while at < data.len() {
                let len = split[i % split.len()].min(data.len() - at);
                crypt.push(&data[at..at + len], &mut out).unwrap();
                got.extend_from_slice(&out);
                at += len;
                i += 1;
            }
            crypt.finish(&mut out).unwrap();
            got.extend_from_slice(&out);

            // The reference: the same draws, one in-place call.
            let mut draw = Seeded { seed, counter: 0 };
            let mut want = data.clone();
            want.resize(data.len().next_multiple_of(16), 0);
            if rar4 {
                let mut salt = [0u8; 8];
                draw.fill(&mut salt);
                let key = Rar4Key::derive(password.as_bytes(), Some(salt)).unwrap();
                Aes128Enc::new(&key).encrypt(&mut want).unwrap();
            } else {
                let (mut salt, mut iv) = ([0u8; 16], [0u8; 16]);
                draw.fill(&mut salt);
                draw.fill(&mut iv);
                let keys =
                    Rar5Keys::derive(password.as_bytes(), &salt, RAR5_KDF_LOG2, None).unwrap();
                Aes256Enc::new(&keys, &iv).encrypt(&mut want).unwrap();
            }
            assert!(
                got == want,
                "rar4 {rar4}, split {split:?}: the fused member cipher differs"
            );
        }
    }
}

/// **One header chain, restarted per block, gives every block the bytes of
/// a fresh chain from its own IV** (spec K 3.6.3 and 3.7.5): the writer's
/// `HeaderKey` expands its key ONCE and restarts the chain for each
/// header, and each wrapped header must be the reference `cbc` crate's
/// ciphertext from that header's IV (RAR 5) or the key's IV (RAR 4),
/// whatever headers came before it.
#[test]
fn a_header_key_restarts_one_chain_per_header() {
    use crate::carry::b_writers::write_entropy::Seeded;
    use crate::write::crypt::{ArchiveKey, Draw, HeaderKey};
    use crate::Password;
    use aes::cipher::{Array, BlockModeEncrypt, KeyIvInit};

    let password = Password::new(b"restart");
    for rar4 in [false, true] {
        let mut draw = Draw::Seeded(Seeded {
            seed: [5; 32],
            counter: 0,
        });
        let (_, header) =
            ArchiveKey::derive_with_headers(Some(&password), rar4, true, &mut draw).unwrap();
        let (mut key, _) = header.expect("a header key");
        for (n, len) in [7usize, 16, 17, 95, 1, 300, 33].into_iter().enumerate() {
            let header: Vec<u8> = (0..len).map(|i| (i * 13 + n) as u8).collect();
            let iv = [n as u8 ^ 0x5A; 16];
            let got = key.wrap(&header, &iv).unwrap();
            let mut want = header.clone();
            want.resize(len.next_multiple_of(16), 0);
            let prefix = match &key {
                HeaderKey::Rar5 { keys, .. } => {
                    ::cbc::Encryptor::<aes::Aes256>::new(&keys.key.into(), &iv.into())
                        .encrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
                    iv.to_vec()
                }
                HeaderKey::Rar4 { key: k, salt, .. } => {
                    ::cbc::Encryptor::<aes::Aes128>::new(&k.key.into(), &k.iv.into())
                        .encrypt_blocks(Array::slice_as_chunks_mut(&mut want).0);
                    salt.to_vec()
                }
            };
            assert_eq!(&got[..prefix.len()], &prefix[..], "rar4 {rar4}, header {n}");
            assert_eq!(&got[prefix.len()..], &want[..], "rar4 {rar4}, header {n}");
        }
    }
}

/// **A header-encrypted write is the same archive at any width**, for a
/// small member and an empty one, in both families, and a RAR 5 one keys
/// its headers from the member salt (spec K 3.7.7): the archive
/// encryption header's salt is the first draw, the one `ArchiveKey`
/// holds. The derivation that once ran on a helper thread beside the
/// member key's is gone with the second salt, so width cannot move a byte
/// of the keying.
#[test]
fn a_header_encrypted_write_is_the_same_archive_at_any_width() {
    use crate::carry::b_writers::write_entropy::Seeded;
    use crate::write::{
        Entropy, FilterPolicy, MemberSpec, Payload, Rar4Version, WriteFormat, WriteMethod,
        WriteOptions, Writer,
    };
    use crate::Password;

    let body = b"one salt keys the headers and the members".repeat(99);
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V29)] {
        let write = |workers: usize| -> Vec<u8> {
            let mut writer = Writer::new(WriteOptions {
                format,
                method: WriteMethod::Stored,
                password: Some(Password::new(b"one salt")),
                encrypt_headers: true,
                entropy: Entropy::Seeded([3; 32]),
                filters: FilterPolicy::Off,
                memory: crate::MemoryPolicy {
                    max_workers: workers,
                    ..Default::default()
                },
                ..WriteOptions::default()
            })
            .expect("options");
            for (name, data) in [(&b"a.txt"[..], &body[..]), (&b"empty"[..], &b""[..])] {
                writer
                    .add(MemberSpec {
                        name,
                        payload: Payload::Bytes(data),
                        mtime: None,
                        attributes: 0o100644,
                        host_os: crate::write::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let mut out = Vec::new();
            writer.finish_into(&mut out).expect("finish");
            out
        };
        let serial = write(1);
        assert!(serial == write(8), "{format:?}: the archives differ");
        if format == WriteFormat::Rar5 {
            // The archive encryption header follows the signature in
            // clear: CRC32 (4), size, type 4, flags, then the record:
            // version, flags, exponent, and the salt.
            let mut first = [0u8; 16];
            Seeded {
                seed: [3; 32],
                counter: 0,
            }
            .fill(&mut first);
            let salt_at = 8 + 4 + 3 + 3;
            assert_eq!(serial[8 + 4 + 1], 4, "the first block is type 4");
            assert_eq!(
                &serial[salt_at..salt_at + 16],
                &first[..],
                "the header salt is the archive's first draw"
            );
        }
    }
}

/// **A RAR 4 archive draws ONE salt and names it everywhere** (spec K
/// 3.6.5: "one 8-byte salt per archive drawn from the API's `Entropy`",
/// and the archive's one salt in front of every encrypted block): a write
/// of many members, with and without header encryption, as one archive
/// and as a volume set with a member split across volumes, draws ONE salt
/// (and, without header encryption, nothing else), and every file header
/// of every volume, read back through its encrypted headers where there
/// are some, carries that salt. Until 30 Sep 2026 the writer drew a salt
/// and ran the key derivation for every member.
#[test]
fn a_rar4_archive_draws_one_salt_and_every_member_names_it() {
    use crate::read::block::Fields;
    use crate::read::reader::{BlockReader, ReadCtx};
    use crate::write::{
        Entropy, EntropySource, FilterPolicy, MemberSpec, Payload, Rar4Version, WriteFormat,
        WriteMethod, WriteOptions, Writer,
    };
    use crate::{Password, ReadOptions};
    use std::sync::{Arc, Mutex};

    struct Counted(Arc<Mutex<Vec<u8>>>, u8);
    impl EntropySource for Counted {
        fn fill(&mut self, buf: &mut [u8]) -> crate::Result<()> {
            for b in buf.iter_mut() {
                self.1 = self.1.wrapping_mul(31).wrapping_add(7);
                *b = self.1;
            }
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(())
        }
    }

    let small = b"one salt for the archive".repeat(3);
    let big = noise(300_000);
    let names: Vec<Vec<u8>> = (0..40)
        .map(|i| format!("m{i:02}.txt").into_bytes())
        .collect();
    for encrypt_headers in [false, true] {
        for volume_size in [None, Some(100_000)] {
            let drawn = Arc::new(Mutex::new(Vec::new()));
            let mut writer = Writer::new(WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V30),
                method: WriteMethod::Stored,
                password: Some(Password::new(b"salted")),
                encrypt_headers,
                entropy: Entropy::Source(Box::new(Counted(Arc::clone(&drawn), 1))),
                filters: FilterPolicy::Off,
                volume_size,
                ..WriteOptions::default()
            })
            .expect("options");
            for (i, name) in names.iter().enumerate() {
                let data = if i == 20 { &big[..] } else { &small[..] };
                writer
                    .add(MemberSpec {
                        name,
                        payload: Payload::Bytes(data),
                        mtime: None,
                        attributes: 0o100644,
                        host_os: crate::write::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            if volume_size.is_some() {
                writer.finish_volumes(&mut volumes).expect("finish");
            } else {
                let mut one = Vec::new();
                writer.finish_into(&mut one).expect("finish");
                volumes.push(one);
            }
            let case = format!("headers {encrypt_headers}, volumes {volume_size:?}");
            if volume_size.is_some() {
                assert!(volumes.len() > 2, "{case}: a set of several volumes");
            }
            // The salt is the first draw. Under header encryption the
            // writer also draws a 16-byte initialisation vector per header
            // group (spec G 3.13), which the RAR 4 family never uses: its
            // IV comes from the key derivation (spec K 3.6.1, 3.6.3).
            let drawn = drawn.lock().unwrap().clone();
            if !encrypt_headers {
                assert_eq!(drawn.len(), 8, "{case}: one 8-byte salt and nothing more");
            } else {
                assert_eq!((drawn.len() - 8) % 16, 0, "{case}: a salt, then IVs");
            }
            let drawn = drawn[..8].to_vec();

            let mut files = 0;
            let mut ctx =
                ReadCtx::new(ReadOptions::default().with_password(Some(Password::new(b"salted"))));
            for volume in &volumes {
                let found = crate::read::archive::require_signature(volume, 0).expect("signature");
                let mut reader = BlockReader::new(volume, &mut ctx, found.format, found.start);
                while let Some(block) = reader.next().expect("a readable block") {
                    if let Fields::File(file) = &block.fields {
                        if file.service.is_none() {
                            assert_eq!(
                                file.rar4_salt.as_ref().map(|s| &s[..]),
                                Some(&drawn[..]),
                                "{case}"
                            );
                            files += 1;
                        }
                    }
                }
            }
            assert!(files >= names.len(), "{case}: every member read, {files}");
        }
    }
}

/// A reader over a slice that notes whether any of its reads ran on a
/// thread other than the one that built it.
struct Watched<'d> {
    data: &'d [u8],
    at: usize,
    home: std::thread::ThreadId,
    away: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl<'d> Watched<'d> {
    fn new(data: &'d [u8]) -> Watched<'d> {
        Watched {
            data,
            at: 0,
            home: std::thread::current().id(),
            away: std::sync::Arc::default(),
        }
    }
}

impl std::io::Read for Watched<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if std::thread::current().id() != self.home {
            self.away.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // Short reads on purpose, so a buffer is filled over several.
        let take = buffer.len().min(self.data.len() - self.at).min(300_007);
        buffer[..take].copy_from_slice(&self.data[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }
}

/// Noise, so nothing about the bytes lines up with a buffer.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 11) as u8
        })
        .collect()
}

/// **A stored member streamed from a READER is read ahead on a second
/// thread**, while the calling thread enciphers and writes, and the
/// archive is the serial copy's byte for byte on every shape that path
/// reaches: a single seekable archive, a volume set (patched and held),
/// CRC32 and BLAKE2sp, encrypted and not, RAR 5 and RAR 4.
///
/// In the code before 28 Sep 2026 every read of a reader payload ran on the
/// calling thread, so a stored create's wall was its read plus its write
/// on one core (6.44 s against rar 7.23's 4.85 s on 8 GiB, Zen 4). The
/// serial arm is `max_workers: 1`, which `engine::reads_ahead` refuses a
/// second thread; both arms are asserted to have taken the path they
/// name.
///
/// **And `-mt N` is at most N helper threads beside the
/// caller's own**, the reading, digest and cipher stages all counted. Each
/// shape is written at `workers` 1, 2, 3 and 8, and the most helpers alive
/// at once (`engine::HELPERS`, an instantaneous high-water) is held to N,
/// with the bytes the serial copy's at every N. In the code of 29 Sep 2026 a
/// volume set at `-mt1` ran two (the reader and the digest stage).
// Helper threads exist only with the `parallel` feature: without it a
// write is one thread in all (SPEC-API 7.2).
#[cfg(feature = "parallel")]
#[test]
fn a_reader_payload_read_ahead_writes_the_serial_bytes() {
    // On a pool of this file's own, of a stated width: [`on_own_pool`].
    on_own_pool(a_reader_payload_read_ahead_writes_the_serial_bytes_there);
}

fn a_reader_payload_read_ahead_writes_the_serial_bytes_there() {
    use crate::write::engine::{AHEAD, HELPERS};
    use crate::write::{
        ChecksumKind, Entropy, MemberSpec, Payload, Rar4Version, VolumeOut, WriteFormat,
        WriteMethod, WriteOptions, Writer,
    };
    use crate::Password;

    /// The volume provider that cannot patch, so every fragment's bytes
    /// are held behind a placeholder: the other walk the copy feeds.
    struct Held(Vec<Vec<u8>>);
    impl VolumeOut for Held {
        type W = Vec<u8>;
        fn volume(&mut self, _index: u32) -> crate::Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn finished(&mut self, _index: u32, volume: Vec<u8>) -> crate::Result<()> {
            self.0.push(volume);
            Ok(())
        }
    }

    let data = noise((13 << 20) + 777);
    let small = &data[..100_003];
    /// Name, format, checksum, password, header encryption, volumes, held.
    type Shape = (
        &'static str,
        WriteFormat,
        ChecksumKind,
        bool,
        bool,
        Option<u64>,
        bool,
    );
    let shapes: [Shape; 9] = [
        (
            "rar5 crc32",
            WriteFormat::Rar5,
            ChecksumKind::Crc32,
            false,
            false,
            None,
            false,
        ),
        (
            "rar5 blake2sp",
            WriteFormat::Rar5,
            ChecksumKind::Blake2sp,
            false,
            false,
            None,
            false,
        ),
        (
            "rar5 pw",
            WriteFormat::Rar5,
            ChecksumKind::Crc32,
            true,
            false,
            None,
            false,
        ),
        (
            "rar5 hp",
            WriteFormat::Rar5,
            ChecksumKind::Crc32,
            true,
            true,
            None,
            false,
        ),
        (
            "rar5 vol",
            WriteFormat::Rar5,
            ChecksumKind::Crc32,
            false,
            false,
            Some(5 << 20),
            false,
        ),
        (
            "rar5 vol held",
            WriteFormat::Rar5,
            ChecksumKind::Crc32,
            false,
            false,
            Some(5 << 20),
            true,
        ),
        (
            "rar5 vol b2 pw",
            WriteFormat::Rar5,
            ChecksumKind::Blake2sp,
            true,
            false,
            Some(5 << 20),
            false,
        ),
        (
            "rar4 crc32",
            WriteFormat::Rar4(Rar4Version::V29),
            ChecksumKind::Crc32,
            false,
            false,
            None,
            false,
        ),
        (
            "rar4 vol pw",
            WriteFormat::Rar4(Rar4Version::V29),
            ChecksumKind::Crc32,
            true,
            false,
            Some(5 << 20),
            true,
        ),
    ];
    for (name, format, checksum, password, headers, volumes, held) in shapes {
        let write = |max_workers: usize, mt: Option<usize>| -> (Vec<Vec<u8>>, usize, bool, usize) {
            let options = WriteOptions {
                format,
                method: WriteMethod::Stored,
                checksum,
                password: password.then(|| Password::new(b"ahead")),
                encrypt_headers: headers,
                volume_size: volumes,
                entropy: Entropy::Seeded([7; 32]),
                filters: crate::write::FilterPolicy::Off,
                memory: crate::MemoryPolicy {
                    max_workers,
                    ..Default::default()
                },
                workers: mt,
                ..WriteOptions::default()
            };
            AHEAD.with(|count| count.set(0));
            HELPERS.with(|census| census.reset());
            let mut big = Watched::new(&data);
            let mut little = Watched::new(small);
            let away = std::sync::Arc::clone(&big.away);
            let mut writer = Writer::new(options).expect("options");
            for (member, reader) in [
                (&b"big.bin"[..], &mut big),
                (&b"small.bin"[..], &mut little),
            ] {
                let size = reader.data.len() as u64;
                writer
                    .add(MemberSpec {
                        name: member,
                        payload: Payload::Reader {
                            reader,
                            size,
                            crc32: None,
                        },
                        mtime: None,
                        attributes: 0o100644,
                        host_os: crate::write::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let out = match (volumes, held) {
                (Some(_), false) => {
                    let mut out: Vec<Vec<u8>> = Vec::new();
                    writer.finish_volumes(&mut out).expect("finish_volumes");
                    out
                }
                (Some(_), true) => {
                    let mut out = Held(Vec::new());
                    writer.finish_volumes(&mut out).expect("finish_volumes");
                    out.0
                }
                (None, _) => {
                    let mut out = std::io::Cursor::new(Vec::new());
                    writer.finish_seek(&mut out).expect("finish_seek");
                    vec![out.into_inner()]
                }
            };
            let away = away.load(std::sync::atomic::Ordering::Relaxed);
            let peak = HELPERS.with(|census| census.peak());
            (out, AHEAD.with(std::cell::Cell::get), away, peak)
        };
        let (serial, serial_spans, serial_away, serial_peak) = write(1, None);
        assert!(
            serial_spans == 0 && !serial_away && serial_peak == 0,
            "{name}: the serial arm started a helper"
        );
        let pool = OWN_POOL;
        for mt in [1usize, 2, 3, 8] {
            crate::checksum::blake2sp::forget_allowance();
            let (ahead, ahead_spans, ahead_away, peak) = write(8, Some(mt));
            let allowed = mt.min(pool);
            // A BLAKE2sp team's pool threads count too: each stream's
            // team is allowed its own thread and what the stages leave
            // (`engine::Run::copy_digest`), and the census counts a
            // team's threads beside its own while it hashes, so `peak`
            // below already holds them; at -mt1 a digest hashes alone.
            if checksum == ChecksumKind::Blake2sp && mt == 1 {
                let team = crate::checksum::blake2sp::last_allowance() - 1;
                assert_eq!(team, 0, "{name} -mt1: a digest was given pool threads");
            }
            assert!(
                (1..=allowed).contains(&peak),
                "{name} -mt{mt}: {peak} helpers alive at once, against at most {allowed}"
            );
            // With ONE helper an encrypted member spends it on the cipher,
            // and a member hashed with BLAKE2sp on its digest, and each
            // reads on the calling thread; every other arrangement has a
            // reading thread (`engine::Stages::plan`).
            let blake = checksum == ChecksumKind::Blake2sp;
            let caller_reads = allowed == 1 && (password || blake);
            if !caller_reads {
                assert!(
                    ahead_away,
                    "{name} -mt{mt}: every read ran on the calling thread, nothing was read ahead"
                );
            }
            assert!(
                ahead_spans > 0,
                "{name} -mt{mt}: the read-ahead was never counted"
            );
            assert_eq!(
                serial.len(),
                ahead.len(),
                "{name} -mt{mt}: volume counts differ"
            );
            for (i, (a, b)) in serial.iter().zip(&ahead).enumerate() {
                assert!(
                    a == b,
                    "{name} -mt{mt}: volume {i} differs between the serial and the read-ahead copy"
                );
            }
        }
    }
}

/// A reader that ends early, or fails, is an error through the read-ahead
/// exactly as through the serial copy, and a sink that fails stops every
/// helper rather than leaving one waiting: in clear and enciphered, at
/// `-mt1` (where an enciphered member's one helper is the cipher stage and
/// the calling thread reads), at `-mt2` and at the pool's width.
// Helper threads exist only with the `parallel` feature: without it a
// write is one thread in all (SPEC-API 7.2).
#[cfg(feature = "parallel")]
#[test]
fn the_read_ahead_passes_every_failure_on() {
    use crate::write::{MemberSpec, Payload, VolumeOut, WriteMethod, WriteOptions, Writer};
    use crate::{ErrorKind, Password};

    let data = noise(12 << 20);
    fn options(mt: Option<usize>, password: bool) -> WriteOptions {
        WriteOptions {
            method: WriteMethod::Stored,
            password: password.then(|| Password::new(b"fails")),
            memory: crate::MemoryPolicy {
                max_workers: 8,
                ..Default::default()
            },
            workers: mt,
            ..WriteOptions::default()
        }
    }
    fn member<'r>(
        reader: &'r mut (dyn std::io::Read + Send),
        size: u64,
        crc32: Option<u32>,
        options: WriteOptions,
    ) -> Writer<'r> {
        let mut writer = Writer::new(options).expect("options");
        writer
            .add(MemberSpec {
                name: b"big.bin",
                payload: Payload::Reader {
                    reader,
                    size,
                    crc32,
                },
                mtime: None,
                attributes: 0,
                host_os: crate::write::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        writer
    }

    // Failing: an I/O error half way.
    struct Failing(usize);
    impl std::io::Read for Failing {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0 > 6 << 20 {
                return Err(std::io::Error::other("the disk went away"));
            }
            let take = buffer.len().min(1 << 20);
            buffer[..take].fill(0x5A);
            self.0 += take;
            Ok(take)
        }
    }
    // A volume that refuses its bytes part way through.
    struct Full;
    struct FullWriter(usize);
    impl std::io::Write for FullWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.0 > 3 << 20 {
                return Err(std::io::Error::other("the volume is full"));
            }
            self.0 += buffer.len();
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl VolumeOut for Full {
        type W = FullWriter;
        fn volume(&mut self, _index: u32) -> crate::Result<FullWriter> {
            Ok(FullWriter(0))
        }
    }

    for mt in [Some(1), Some(2), None] {
        for password in [false, true] {
            let shape = format!("-mt{mt:?} password {password}");

            // Short: the reader has 12 MiB and the member says 13.
            let mut short = Watched::new(&data);
            let err = member(&mut short, 13 << 20, None, options(mt, password))
                .finish_seek(std::io::Cursor::new(Vec::new()))
                .expect_err("a short reader wrote an archive");
            assert!(matches!(err.kind(), ErrorKind::Truncated), "{shape}: {err}");

            let err = member(&mut Failing(0), 12 << 20, None, options(mt, password))
                .finish_seek(std::io::Cursor::new(Vec::new()))
                .expect_err("a failing reader wrote an archive");
            assert!(
                err.to_string().contains("the disk went away"),
                "{shape}: {err}"
            );

            let mut whole = Watched::new(&data);
            let err = member(
                &mut whole,
                data.len() as u64,
                Some(crate::checksum::crc32(&data)),
                WriteOptions {
                    volume_size: Some(64 << 20),
                    ..options(mt, password)
                },
            )
            .finish_volumes(&mut Full)
            .expect_err("a full volume wrote a set");
            assert!(
                err.to_string().contains("the volume is full"),
                "{shape}: {err}"
            );
        }
    }
}

/// A volume provider that patches but cannot read back, which is what
/// every provider was before `VolumeOut::can_read_back`: the writer keeps
/// its copy of each volume for the recovery record.
#[cfg(test)]
struct PatchOnly(Vec<Vec<u8>>);

impl crate::write::VolumeOut for PatchOnly {
    type W = Vec<u8>;

    fn volume(&mut self, index: u32) -> crate::Result<Vec<u8>> {
        self.0.volume(index)
    }

    fn finished(&mut self, index: u32, volume: Vec<u8>) -> crate::Result<()> {
        self.0.finished(index, volume)
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> crate::Result<()> {
        self.0.patch(volume, at, bytes)
    }
}

/// Moves the protected length above which a recovery record is read back
/// (`engine::recovery_copy_limit`, 512 MiB in a shipped build) for as long
/// as it lives, so the read back can be exercised on volumes small enough
/// to test, and puts it back when dropped, a failed assertion included.
#[cfg(test)]
struct CopyLimit;

#[cfg(test)]
impl CopyLimit {
    fn set(limit: u64) -> CopyLimit {
        crate::write::engine::set_recovery_copy_limit(Some(limit));
        CopyLimit
    }
}

#[cfg(test)]
impl Drop for CopyLimit {
    fn drop(&mut self) {
        crate::write::engine::set_recovery_copy_limit(None);
    }
}

/// What a recovery-record run writes, and a `finish` to write it with.
#[cfg(test)]
#[derive(Clone, Copy)]
struct RecoveryShape {
    name: &'static str,
    format: crate::write::WriteFormat,
    /// `None` stores; `Some(level)` compresses.
    level: Option<u8>,
    /// A password and enciphered headers.
    headers: bool,
    /// The reference layout, with its quick-open block and locator.
    reference: bool,
    volume: Option<u64>,
    percent: u32,
}

/// A run's volumes and its report.
#[cfg(test)]
type Written = (Vec<Vec<u8>>, crate::write::WriteReport);

/// One recovery-record run: `len` pseudo-random bytes as a `Bytes` member
/// and a text member streamed from a reader (so its header is a
/// placeholder corrected later), written through `finish`.
#[cfg(test)]
fn recovery_run(
    shape: RecoveryShape,
    len: usize,
    finish: &dyn Fn(crate::write::Writer<'_>) -> Written,
) -> Written {
    use crate::write::{Entropy, Layout, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let noise: Vec<u8> = (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    let text: Vec<u8> = b"the recovery record reads the volume back. "
        .iter()
        .copied()
        .cycle()
        .take(len / 3 + 17)
        .collect();
    let mut writer = Writer::new(WriteOptions {
        format: shape.format,
        method: shape
            .level
            .map_or(WriteMethod::Stored, |level| WriteMethod::Compressed {
                level,
                dictionary: None,
            }),
        password: shape.headers.then(|| crate::types::Password::new(b"rr")),
        encrypt_headers: shape.headers,
        layout: if shape.reference {
            Layout::Reference { quick_open: true }
        } else {
            Layout::Default
        },
        entropy: Entropy::Seeded([7; 32]),
        filters: crate::write::FilterPolicy::Off,
        recovery_percent: Some(shape.percent),
        volume_file_size: shape.volume,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"noise.bin",
            payload: Payload::Bytes(&noise),
            mtime: None,
            attributes: 0o100644,
            host_os: crate::write::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut reader = std::io::Cursor::new(text.clone());
    writer
        .add(MemberSpec {
            name: b"text.txt",
            payload: Payload::Reader {
                reader: &mut reader,
                size: text.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o100644,
            host_os: crate::write::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    finish(writer)
}

/// **A recovery record computed from the volume read back is the one
/// computed from a copy of it, byte for byte**, over every shape the
/// writer reaches the record from: RAR 5 stored and compressed, enciphered
/// headers (whose record header is corrected under the same IV), the
/// reference layout (whose locator points at the record), a volume set
/// (each volume its own record), and the RAR 4 family's XOR record. The
/// copy's path is `finish_seek` and a provider that cannot read back; the
/// read-back path is `finish_seek_read` and one that can.
#[test]
fn a_recovery_record_read_back_is_the_one_from_the_copy() {
    use crate::write::{Rar4Version, WriteFormat};

    let _limit = CopyLimit::set(0);
    let copied = |writer: crate::write::Writer<'_>| {
        if writer.options.volume_set() {
            let mut volumes = PatchOnly(Vec::new());
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            (volumes.0, report)
        } else {
            let mut out = std::io::Cursor::new(Vec::new());
            let report = writer.finish_seek(&mut out).expect("finish_seek");
            (vec![out.into_inner()], report)
        }
    };
    let read_back = |writer: crate::write::Writer<'_>| {
        if writer.options.volume_set() {
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            (volumes, report)
        } else {
            // Starting part way into the output: the archive's own offsets
            // are what the read back is counted from.
            let mut out = std::io::Cursor::new(b"prefix".to_vec());
            out.set_position(6);
            let report = writer.finish_seek_read(&mut out).expect("finish_seek_read");
            (vec![out.into_inner()[6..].to_vec()], report)
        }
    };
    let rar5 = RecoveryShape {
        name: "rar5 stored",
        format: WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume: None,
        percent: 5,
    };
    let rar4 = RecoveryShape {
        name: "rar4 stored",
        format: WriteFormat::Rar4(Rar4Version::V29),
        ..rar5
    };
    let shapes = [
        rar5,
        RecoveryShape {
            name: "rar5 stored 100",
            percent: 100,
            ..rar5
        },
        // More recovery rows than data shards (spec L 3.5.1).
        RecoveryShape {
            name: "rar5 stored 250",
            percent: 250,
            ..rar5
        },
        RecoveryShape {
            name: "rar5 stored 1000",
            percent: 1_000,
            ..rar5
        },
        RecoveryShape {
            name: "rar5 m3",
            level: Some(3),
            percent: 3,
            ..rar5
        },
        RecoveryShape {
            name: "rar5 hp",
            headers: true,
            ..rar5
        },
        RecoveryShape {
            name: "rar5 reference",
            reference: true,
            ..rar5
        },
        RecoveryShape {
            name: "rar5 vol",
            volume: Some(1 << 20),
            percent: 10,
            ..rar5
        },
        RecoveryShape {
            name: "rar5 vol m3",
            level: Some(3),
            volume: Some(1 << 20),
            percent: 1,
            ..rar5
        },
        rar4,
        RecoveryShape {
            name: "rar4 m3",
            level: Some(3),
            percent: 3,
            ..rar4
        },
    ];
    for shape in shapes {
        // Above 100 percent the fold is `percent` times the volume, so
        // those shapes are small ones.
        let len = if shape.percent > 100 {
            150_000
        } else {
            3 << 20
        };
        let (want, _) = recovery_run(shape, len, &copied);
        let (got, _) = recovery_run(shape, len, &read_back);
        let name = shape.name;
        assert_eq!(want.len(), got.len(), "{name}: volume counts");
        for (i, (a, b)) in want.iter().zip(&got).enumerate() {
            assert!(
                a == b,
                "{name}: volume {i} differs ({} and {} bytes)",
                a.len(),
                b.len()
            );
        }
    }
}

/// **Above 100 percent the record decides which way it is computed, and
/// what it holds is counted** (spec L 3.5.1, spec G 3.7.3 rule 2). Under a
/// copy limit of 4 MiB a 150,000 byte member at 100 percent is well inside
/// it and is copied; at 1,000 percent the copy's route would hold the
/// volume and three times its 2 MiB record, past the limit, so an output
/// that reads back is read back, where the record costs its `2k + m`
/// slices of one group and no copy. An output that cannot read back keeps
/// the copy, and its report counts the rows and the data area.
#[test]
fn above_100_percent_the_record_decides_the_route() {
    use crate::write::WriteFormat;

    let _limit = CopyLimit::set(4 << 20);
    let read_back = |writer: crate::write::Writer<'_>| {
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek_read(&mut out).expect("finish_seek_read");
        (vec![out.into_inner()], report)
    };
    let copied = |writer: crate::write::Writer<'_>| {
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek(&mut out).expect("finish_seek");
        (vec![out.into_inner()], report)
    };
    let shape = |percent| RecoveryShape {
        name: "rar5 stored",
        format: WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume: None,
        percent,
    };
    let len = 150_000;

    let (kept, kept_report) = recovery_run(shape(1_000), len, &copied);
    let (read, read_report) = recovery_run(shape(1_000), len, &read_back);
    assert!(kept == read, "the two routes wrote different archives");
    let archive = kept[0].len() as u64;
    let record = archive - 200_100;
    assert!(record > 1_900_000, "a record of {record} bytes");
    // Rows and data area beside the copy: twice the record and the volume.
    assert!(
        kept_report.peak_working_memory > 2 * record,
        "the copy's route reported {} for a record of {record}",
        kept_report.peak_working_memory
    );
    // Read back: 2,401 slices of 1,000 bytes and one record, and no copy.
    assert!(
        read_report.peak_working_memory < 2 * record,
        "the read back reported {} for a record of {record}",
        read_report.peak_working_memory
    );

    // At 100 percent the same member is copied on both outputs, as it
    // was: the volume is held, so the report passes its length.
    let (_, small) = recovery_run(shape(100), len, &read_back);
    assert!(
        small.peak_working_memory > 200_000,
        "{}",
        small.peak_working_memory
    );
}

/// **Working memory does not follow the archive's length once the record
/// is computed from the archive read back.** A RAR 5 stored archive at
/// `-rr1` reports the same working memory at 48 MiB as at 32 MiB (both
/// past the 13 MiB where one group's slices reach their 64 KiB width, so
/// the encode's own stripes are the same size), where the copied path
/// reports the archive's whole length and more; before `finish_seek_read`
/// a single archive with a record held all of it.
#[test]
fn a_read_back_recovery_record_holds_no_archive() {
    use crate::write::WriteFormat;

    let _limit = CopyLimit::set(0);
    let read_back = |writer: crate::write::Writer<'_>| {
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek_read(&mut out).expect("finish_seek_read");
        (vec![out.into_inner()], report)
    };
    let copied = |writer: crate::write::Writer<'_>| {
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek(&mut out).expect("finish_seek");
        (vec![out.into_inner()], report)
    };
    let shape = RecoveryShape {
        name: "rar5 stored rr1",
        format: WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume: None,
        percent: 1,
    };
    let run = |len: usize, finish: &dyn Fn(crate::write::Writer<'_>) -> Written| {
        recovery_run(shape, len, finish).1.peak_working_memory
    };
    let smaller = run(32 << 20, &read_back);
    let larger = run(48 << 20, &read_back);
    let whole = run(48 << 20, &copied);
    assert!(whole > 48 << 20, "the copied path reported {whole}");
    assert!(
        larger <= smaller + (256 << 10),
        "the read-back path grew from {smaller} at 32 MiB to {larger} at 48 MiB"
    );
    assert!(larger < 48 << 20, "the read-back path reported {larger}");
}

/// **rarkit's own repair mends an archive whose record was computed from
/// the archive read back**: a RAR 5 single archive, a RAR 5 volume set's
/// middle volume, and a RAR 4 single archive, each with 40 KiB zeroed in
/// the middle of the protected bytes, come back byte for byte through
/// `recovery::repair_inline`. (Reference `rar r` repairing the same
/// shapes written by `rarfast` was measured on an Apple M3 Mac.)
#[test]
fn a_read_back_recovery_record_repairs_its_archive() {
    use crate::write::{Rar4Version, WriteFormat};

    let _limit = CopyLimit::set(0);
    let read_back = |writer: crate::write::Writer<'_>| {
        if writer.options.volume_set() {
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            (volumes, report)
        } else {
            let mut out = std::io::Cursor::new(Vec::new());
            let report = writer.finish_seek_read(&mut out).expect("finish_seek_read");
            (vec![out.into_inner()], report)
        }
    };
    let rar5 = RecoveryShape {
        name: "rar5 single",
        format: WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume: None,
        percent: 5,
    };
    let shapes = [
        rar5,
        RecoveryShape {
            name: "rar5 vol",
            volume: Some(1 << 20),
            ..rar5
        },
        RecoveryShape {
            name: "rar4 single",
            format: WriteFormat::Rar4(Rar4Version::V29),
            ..rar5
        },
    ];
    for shape in shapes {
        let (volumes, _) = recovery_run(shape, 3 << 20, &read_back);
        let whole = &volumes[volumes.len() / 2];
        let mut damaged = whole.clone();
        let at = whole.len() / 3;
        damaged[at..at + (40 << 10)].fill(0);
        assert!(&damaged != whole, "{}: nothing was damaged", shape.name);
        let mut mended = Vec::new();
        crate::recovery::repair_inline(&damaged, &crate::read::ReadOptions::default(), &mut mended)
            .unwrap_or_else(|err| panic!("{}: {err}", shape.name));
        assert!(
            &mended == whole,
            "{}: the repair is not the archive",
            shape.name
        );
    }
}

/// **Repair finds rarkit's own record through the header chain, and the
/// team that hashes the slices changes nothing**:
/// rarkit's
/// writer writes no recovery locator, so the headers are followed from the
/// main header to the `RR` service header; the records walked there are
/// the records the whole-volume scan finds; and a volume damaged in three
/// places comes back byte for byte at one worker and at eight, stored and
/// compressed, single and a volume set's middle volume.
#[test]
fn repair_walks_the_header_chain_and_its_team_changes_nothing() {
    use crate::recovery::scan;

    let _limit = CopyLimit::set(0);
    let read_back = |writer: crate::write::Writer<'_>| {
        if writer.options.volume_set() {
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            (volumes, report)
        } else {
            let mut out = std::io::Cursor::new(Vec::new());
            let report = writer.finish_seek_read(&mut out).expect("finish_seek_read");
            (vec![out.into_inner()], report)
        }
    };
    let stored = RecoveryShape {
        name: "rar5 stored",
        format: crate::write::WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume: None,
        percent: 5,
    };
    let shapes = [
        stored,
        RecoveryShape {
            name: "rar5 m3",
            level: Some(3),
            ..stored
        },
        RecoveryShape {
            name: "rar5 vol",
            volume: Some(3 << 20),
            ..stored
        },
    ];
    for shape in shapes {
        let (volumes, _) = recovery_run(shape, 12 << 20, &read_back);
        let whole = &volumes[volumes.len() / 2];
        let volume = whole.len() as u64;
        let area = scan::record_area(whole, volume)
            .unwrap_or_else(|| panic!("{}: the headers lead to no record", shape.name));
        let policy = crate::memory::repair_only(u64::MAX);
        let located = scan::scan(whole, &policy).unwrap();
        assert_eq!(
            located.records,
            scan::scan_whole(whole).unwrap().records,
            "{}",
            shape.name
        );
        assert!(
            located.records.iter().all(|r| area.contains(&r.offset)),
            "{}",
            shape.name
        );
        let mut damaged = whole.clone();
        for third in 1..=3 {
            let at = area.start as usize * third / 4;
            damaged[at..at + 3000].iter_mut().for_each(|b| *b ^= 0x5a);
        }
        for workers in [1usize, 8] {
            let mut opts = crate::read::ReadOptions::default();
            opts.memory.max_workers = workers;
            let mut mended = Vec::new();
            crate::recovery::repair_inline(&damaged, &opts, &mut mended)
                .unwrap_or_else(|err| panic!("{} at {workers}: {err}", shape.name));
            assert!(
                &mended == whole,
                "{} at {workers}: the repair is not the archive",
                shape.name
            );
        }
    }
}

/// **The copy is kept up to the limit and the volume is read back above
/// it**, on an output that can do either (the floor set 28 Sep
/// 2026): with the limit moved to 40 MiB, a 32 MiB archive reports the
/// copy's working memory (the archive's length and more) and a 48 MiB one
/// the read back's (flat, well under it), and both archives are the bytes
/// the copy's path writes. A shipped build's limit is 512 MiB, where the
/// same rule keeps every archive below it at the copy's wall.
#[test]
fn the_copy_is_kept_below_the_limit_and_read_back_above_it() {
    use crate::write::WriteFormat;

    let _limit = CopyLimit::set(40 << 20);
    let read_back = |writer: crate::write::Writer<'_>| {
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek_read(&mut out).expect("finish_seek_read");
        (vec![out.into_inner()], report)
    };
    let copied = |writer: crate::write::Writer<'_>| {
        let mut out = std::io::Cursor::new(Vec::new());
        let report = writer.finish_seek(&mut out).expect("finish_seek");
        (vec![out.into_inner()], report)
    };
    let shape = RecoveryShape {
        name: "rar5 stored rr1",
        format: WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume: None,
        percent: 1,
    };
    let (small, small_report) = recovery_run(shape, 24 << 20, &read_back);
    let (small_copy, _) = recovery_run(shape, 24 << 20, &copied);
    assert!(small == small_copy, "below the limit: the archives differ");
    assert!(
        small_report.peak_working_memory > 24 << 20,
        "below the limit the copy was not kept: {}",
        small_report.peak_working_memory
    );
    let (large, large_report) = recovery_run(shape, 48 << 20, &read_back);
    let (large_copy, _) = recovery_run(shape, 48 << 20, &copied);
    assert!(large == large_copy, "above the limit: the archives differ");
    assert!(
        large_report.peak_working_memory < 40 << 20,
        "above the limit the volume was not read back: {}",
        large_report.peak_working_memory
    );
}

/// **A write at `workers = Some(N)` runs at most N helper
/// threads beside the caller's own, on every write path** (SPEC-API 7.2,
/// "The test it owes"). Each shape is written at N of 1, 2 and a width
/// below the pool's, and at `workers: None`; the census
/// (`engine::HELPERS`) holds the instantaneous high-water to N (the pool's
/// width for `None`), and the archive's bytes are the same at every N.
///
/// The shapes are levels 1, 3 and 5, solid and not, slice and reader
/// payloads, CRC32 and BLAKE2sp, unencrypted, `-p` and `-hp`: every
/// combination. Beside them, the paths first named for it: a stored
/// member's one-shot digest ahead of a non-seekable output, the recovery
/// record encoded whole and in place, and a BLAKE2sp volume set.
///
/// **What the census counts.** A thread the write starts outside any pool
/// counts from its first instruction to its last (the copy's stages, the
/// key derivation's second thread). A BLAKE2sp team counts its allowance
/// less the hashing thread for as long as it hashes. A pool the calling
/// thread lends the write (`width::on_pool`, `width::scope_here`, the
/// recovery's in-place team) counts its WHOLE width for as long as it is
/// lent, since what the write spawned into it may fill it; that pool is
/// no wider than N by construction (`width`), so the figure is an upper
/// bound on what runs at any instant. Counted from outside on this
/// repository's library writer before the fix (30 Sep 2026, per-thread
/// run states sampled through `ps -M`), every compressed shape ran 17 to
/// 18 helpers at N of 1, 2 and 4 on an eighteen-wide pool.
// Helper threads exist only with the `parallel` feature: without it a
// write is one thread in all (SPEC-API 7.2).
#[cfg(feature = "parallel")]
#[test]
fn every_write_path_keeps_its_helpers_within_workers() {
    use crate::write::engine::HELPERS;
    use crate::write::{
        ChecksumKind, Entropy, MemberSpec, Payload, WriteMethod, WriteOptions, Writer,
    };
    use crate::Password;

    // Text-like bytes the finders have something to find in, then noise:
    // a member past the BLAKE2sp team's batch and the tree walk's lone
    // group, and a set of small members for the worker team and a solid
    // batch.
    let text: Vec<u8> = (0..(640usize << 10))
        .map(|at| {
            b"the quick brown fox jumps over the lazy dog 0123456789\n"[at % 55]
                ^ ((at / 4099) as u8 & 3)
        })
        .collect();
    let mut big = text;
    big.extend_from_slice(&noise(128 << 10));
    let smalls: Vec<Vec<u8>> = (0..16usize)
        .map(|index| {
            let len = 3_000 + index * 2_111;
            big[index * 7_001..index * 7_001 + len].to_vec()
        })
        .collect();

    // THE MACHINE'S POOL, on purpose, and nothing here needs a width of
    // it: this test is about a write called from a thread OUTSIDE any
    // pool (called from one of a pool's own threads, a write at one
    // worker lends no pool at all and the census has nothing to see),
    // so it cannot run on [`on_own_pool`]. Every figure below is a
    // CEILING (`peak <= n`, `peak <= pool`) or "some helper was
    // counted", which holds on a pool of any width, one included; the
    // widths tried are cut to what the pool has.
    let pool = rayon::current_num_threads();
    let mut widths = vec![1usize, 2, pool.saturating_sub(1).clamp(1, 4)];
    widths.sort_unstable();
    widths.dedup();

    #[derive(Clone, Copy, PartialEq)]
    enum Out {
        Seek,
        Stream,
        SeekRead,
        Volumes,
    }
    struct Shape {
        name: String,
        level: u8,
        solid: bool,
        reader: bool,
        checksum: ChecksumKind,
        password: bool,
        headers: bool,
        recovery: Option<u32>,
        out: Out,
    }
    let mut shapes = Vec::new();
    for level in [1u8, 3, 5] {
        for solid in [false, true] {
            for reader in [false, true] {
                for checksum in [ChecksumKind::Crc32, ChecksumKind::Blake2sp] {
                    for (password, headers) in [(false, false), (true, false), (true, true)] {
                        shapes.push(Shape {
                            name: format!(
                                "-m{level}{} {} {:?}{}",
                                if solid { " -s" } else { "" },
                                if reader { "reader" } else { "slice" },
                                checksum,
                                match (password, headers) {
                                    (false, _) => "",
                                    (true, false) => " -p",
                                    (true, true) => " -hp",
                                }
                            ),
                            level,
                            solid,
                            reader,
                            checksum,
                            password,
                            headers,
                            recovery: None,
                            out: Out::Seek,
                        });
                    }
                }
            }
        }
    }
    let extra = |name: &str, level: u8, checksum, recovery, out| Shape {
        name: name.to_string(),
        level,
        solid: false,
        reader: false,
        checksum,
        password: false,
        headers: false,
        recovery,
        out,
    };
    shapes.push(extra(
        "stored BLAKE2sp to a stream: the one-shot digest",
        0,
        ChecksumKind::Blake2sp,
        None,
        Out::Stream,
    ));
    shapes.push(extra(
        "-m3 BLAKE2sp to a stream",
        3,
        ChecksumKind::Blake2sp,
        None,
        Out::Stream,
    ));
    shapes.push(extra(
        "stored -rr5, the record whole",
        0,
        ChecksumKind::Crc32,
        Some(5),
        Out::Seek,
    ));
    shapes.push(extra(
        "stored -rr5, the record in place",
        0,
        ChecksumKind::Crc32,
        Some(5),
        Out::SeekRead,
    ));
    shapes.push(extra(
        "-m3 -rr5",
        3,
        ChecksumKind::Crc32,
        Some(5),
        Out::Seek,
    ));
    shapes.push(extra(
        "-m3 BLAKE2sp volumes",
        3,
        ChecksumKind::Blake2sp,
        None,
        Out::Volumes,
    ));

    for shape in &shapes {
        let write = |workers: Option<usize>| -> (Vec<Vec<u8>>, usize) {
            let options = WriteOptions {
                method: if shape.level == 0 {
                    WriteMethod::Stored
                } else {
                    WriteMethod::Compressed {
                        level: shape.level,
                        dictionary: None,
                    }
                },
                solid: shape.solid,
                checksum: shape.checksum,
                password: shape.password.then(|| Password::new(b"width")),
                encrypt_headers: shape.headers,
                recovery_percent: shape.recovery,
                volume_size: (shape.out == Out::Volumes).then_some(256 << 10),
                entropy: Entropy::Seeded([124; 32]),
                workers,
                ..WriteOptions::default()
            };
            let mut readers: Vec<std::io::Cursor<&[u8]>> = std::iter::once(&big)
                .chain(&smalls)
                .map(|data| std::io::Cursor::new(&data[..]))
                .collect();
            let names: Vec<Vec<u8>> = (0..readers.len())
                .map(|index| format!("m{index:02}.dat").into_bytes())
                .collect();
            let datas: Vec<&[u8]> = std::iter::once(&big[..])
                .chain(smalls.iter().map(|data| &data[..]))
                .collect();
            HELPERS.with(|census| census.reset());
            if shape.out == Out::SeekRead {
                crate::write::engine::set_recovery_copy_limit(Some(0));
            }
            let mut writer = Writer::new(options).expect("options");
            for ((name, reader), data) in names.iter().zip(&mut readers).zip(&datas) {
                let payload = if shape.reader {
                    Payload::Reader {
                        reader,
                        size: data.len() as u64,
                        crc32: None,
                    }
                } else {
                    Payload::Bytes(data)
                };
                writer
                    .add(MemberSpec {
                        name,
                        payload,
                        mtime: None,
                        attributes: 0o100644,
                        host_os: crate::write::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let out = match shape.out {
                Out::Seek => {
                    let mut out = std::io::Cursor::new(Vec::new());
                    writer.finish_seek(&mut out).expect("finish_seek");
                    vec![out.into_inner()]
                }
                Out::SeekRead => {
                    let mut out = std::io::Cursor::new(Vec::new());
                    writer.finish_seek_read(&mut out).expect("finish_seek_read");
                    vec![out.into_inner()]
                }
                Out::Stream => {
                    let mut out = Vec::new();
                    writer.finish_into(&mut out).expect("finish_into");
                    vec![out]
                }
                Out::Volumes => {
                    let mut out: Vec<Vec<u8>> = Vec::new();
                    writer.finish_volumes(&mut out).expect("finish_volumes");
                    out
                }
            };
            crate::write::engine::set_recovery_copy_limit(None);
            (out, HELPERS.with(|census| census.peak()))
        };
        let (first, _) = write(Some(1));
        for &n in &widths {
            let (bytes, peak) = write(Some(n));
            assert!(
                peak <= n,
                "{} -mt{n}: {peak} helpers alive at once, against at most {n}",
                shape.name
            );
            if shape.level > 0 {
                assert!(
                    peak >= 1,
                    "{} -mt{n}: the census saw no helper, so the path it holds was not taken",
                    shape.name
                );
            }
            assert!(
                bytes == first,
                "{} -mt{n}: not the -mt1 archive",
                shape.name
            );
        }
        let (bytes, peak) = write(None);
        assert!(
            peak <= pool,
            "{} with no workers figure: {peak} helpers against the pool's {pool}",
            shape.name
        );
        assert!(
            bytes == first,
            "{} with no workers figure: not the -mt1 archive",
            shape.name
        );
    }
}

/// **Chains ahead are counted helpers.**
/// Under `WriteOptions::encrypted_read_ahead` a stored encrypted set at
/// `-mt N` never has more than N helper threads working at once, chains,
/// their reading threads and the stored copy's own stages together, at
/// every N; at N of 2 and more chains are begun ahead, and at N of 1 none
/// is; and every archive is the `-mt1` archive, which no chain touches.
/// A chain is counted until its last message: its thread may still be
/// exiting when the next chain starts, with no work left to do.
///
/// **The pool is this test's own, twelve threads wide**, built here and
/// installed for every write: the engine holds a write to
/// `min(workers, the caller's pool)` helpers (`Run::helpers`), so on the
/// machine's pool what this test held changed with the box, and on a
/// narrow one `-mt4` is two helpers by design. **That chains ran is read
/// off the count of chains BEGUN**, which the writing thread decides from
/// the members and the helper count, and not off two helpers having been
/// ALIVE AT ONCE, which is a fact of the schedule: on a hosted runner of
/// few threads a chain ended before the next helper began, the peak read
/// one, and this test failed with the engine right (10 Oct 2026). The
/// peak stays what it is good for, the ceiling. Memory: six members of
/// 5 MiB and their ciphertext, under 100 MiB.
#[cfg(feature = "parallel")]
#[test]
fn chains_ahead_stay_inside_the_helper_count() {
    use crate::write::engine::HELPERS;
    use crate::write::{
        ChecksumKind, Entropy, MemberSpec, Payload, WriteMethod, WriteOptions, Writer,
    };
    use crate::Password;

    const POOL: usize = OWN_POOL;

    let members: Vec<Vec<u8>> = (0..6u32)
        .map(|index| {
            let mut state = 0x9E37_79B9u32.wrapping_mul(index + 1) | 1;
            (0..(5 << 20) + 7 * index as usize)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect()
        })
        .collect();
    for (headers, checksum) in [
        (false, ChecksumKind::Crc32),
        (true, ChecksumKind::Crc32),
        (true, ChecksumKind::Blake2sp),
    ] {
        // Answers the archive, the most helpers alive at once and the
        // chains begun ahead.
        let write_here = |workers: Option<usize>| -> (Vec<u8>, usize, usize) {
            let options = WriteOptions {
                method: WriteMethod::Stored,
                checksum,
                password: Some(Password::new(b"width")),
                encrypt_headers: headers,
                entropy: Entropy::Seeded([124; 32]),
                encrypted_read_ahead: true,
                workers,
                ..WriteOptions::default()
            };
            let mut readers: Vec<std::io::Cursor<&[u8]>> = members
                .iter()
                .map(|data| std::io::Cursor::new(&data[..]))
                .collect();
            let names: Vec<Vec<u8>> = (0..readers.len())
                .map(|index| format!("m{index:02}.dat").into_bytes())
                .collect();
            HELPERS.with(|census| census.reset());
            let mut writer = Writer::new(options).expect("options");
            for ((name, reader), data) in names.iter().zip(&mut readers).zip(&members) {
                writer
                    .add(MemberSpec {
                        name,
                        payload: Payload::Reader {
                            reader,
                            size: data.len() as u64,
                            crc32: None,
                        },
                        mtime: None,
                        attributes: 0o100644,
                        host_os: crate::write::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let mut out = std::io::Cursor::new(Vec::new());
            writer.finish_seek(&mut out).expect("finish_seek");
            let (peak, chains) = HELPERS.with(|census| (census.peak(), census.chains()));
            (out.into_inner(), peak, chains)
        };
        // The census is the calling thread's, so the write runs on ONE
        // thread of the pool, start to finish.
        let write = |workers: Option<usize>| on_own_pool(|| write_here(workers));
        let pool = on_own_pool(crate::write::width::pool_width);
        assert_eq!(
            pool, POOL,
            "the pool this test built is not the writes' pool"
        );

        let what = format!("headers={headers} {checksum:?}");
        let (first, alone, chains) = write(Some(1));
        assert!(alone <= 1, "{what} -mt1: {alone} helpers alive at once");
        assert_eq!(chains, 0, "{what} -mt1: a chain was begun ahead");
        for n in [2usize, 3, 4, 5, 8, 12] {
            let (bytes, peak, chains) = write(Some(n));
            assert!(
                peak <= n,
                "{what} -mt{n}: {peak} helpers alive at once, against at most {n}"
            );
            assert!(
                chains >= 1,
                "{what} -mt{n}: no chain was begun ahead on a pool of {POOL}"
            );
            assert!(bytes == first, "{what} -mt{n}: not the -mt1 archive");
        }
        let (bytes, peak, chains) = write(None);
        assert!(
            peak <= POOL,
            "{what} with no workers figure: {peak} helpers against the pool's {POOL}"
        );
        assert!(
            chains >= 1,
            "{what} with no workers figure: no chain was begun ahead on a pool of {POOL}"
        );
        assert!(
            bytes == first,
            "{what} with no workers figure: not the -mt1 archive"
        );
    }
}

/// **The reference layout's main header is rar 7.23's, with the quick-open
/// index on and with it off** (spec G 3.6.2: with `quick_open: false` the
/// reference writes NEITHER the block NOR the locator). The two vectors
/// are the main headers `rar a -ma5 -m0` and `rar a -ma5 -m0 -qo-` wrote
/// over the same two members, a 3 byte `a.txt` and a 5,000 byte `b.bin`,
/// mode 0644, whole-second times: flags 0x05 with a locator whose
/// quick-open offset is 5,083 at the reserved width of 4, and flags 0x04
/// with no extra area at all.
#[test]
fn the_reference_main_header_is_what_rar_writes_with_the_index_on_and_off() {
    use crate::write::{Layout, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

    const QO_ON: &str = "35398cca0b01050700060101dba78000";
    const QO_OFF: &str = "c1df5f5603010400";

    let small = b"hi\n".to_vec();
    let large = vec![b'x'; 5_000];
    for (quick_open, expected) in [(true, QO_ON), (false, QO_OFF)] {
        let mut writer = Writer::new(WriteOptions {
            method: WriteMethod::Stored,
            layout: Layout::Reference { quick_open },
            ..WriteOptions::default()
        })
        .expect("options");
        for (name, data) in [(&b"a.txt"[..], &small), (&b"b.bin"[..], &large)] {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(data),
                    mtime: Some(crate::Timestamp {
                        unix_seconds: 1_790_726_400,
                        nanos: 0,
                    }),
                    attributes: 0o100644,
                    host_os: crate::write::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out = Vec::new();
        writer.finish_into(&mut out).expect("finish");
        let main: String = out[8..8 + expected.len() / 2]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(main, expected, "quick_open {quick_open}");
    }
}

/// A volume provider that can neither patch nor read back, as a pipe
/// cannot: the trait's defaults.
#[cfg(test)]
struct StreamOnly(Vec<Vec<u8>>);

#[cfg(test)]
impl crate::write::VolumeOut for StreamOnly {
    type W = Vec<u8>;

    fn volume(&mut self, index: u32) -> crate::Result<Vec<u8>> {
        self.0.volume(index)
    }

    fn finished(&mut self, index: u32, volume: Vec<u8>) -> crate::Result<()> {
        self.0.finished(index, volume)
    }
}

/// The main header's locator, and where each `RR` service header starts,
/// in one RAR 5 volume.
#[cfg(test)]
fn locator_and_rr(volume: &[u8]) -> (Option<crate::read::block::Locator>, Vec<u64>) {
    use crate::read::block::{Fields, ServiceName};
    use crate::read::reader::{BlockReader, ReadCtx};
    use crate::read::{Format, ReadOptions};

    let mut ctx = ReadCtx::new(ReadOptions::default());
    let mut reader = BlockReader::new(&volume, &mut ctx, Format::Rar5, 0);
    let mut locator = None;
    let mut rr = Vec::new();
    while let Some(block) = reader.next().expect("block") {
        match &block.fields {
            Fields::Main(main) => locator = main.locator,
            Fields::File(file) if file.service == Some(ServiceName::Recovery) => {
                rr.push(block.header.start);
            }
            _ => {}
        }
    }
    (locator, rr)
}

/// **The DEFAULT layout's recovery locator (spec G 3.5 rule 1 and
/// 3.11).** Wherever the output can patch, every volume's main
/// header is exactly the one 3.11 describes: a locator with flag 0x0002
/// alone whose offset names that volume's own `RR` header, at 3.6.3's
/// width over EVERY member of the archive, the same width in every volume
/// (5 here, where the volume's own bytes would need only 3), from the copy
/// and from the read back alike; the record is then found through the
/// locator with the header chain BROKEN (the first member's header CRC
/// spoiled), which is the path spec L 3.5.5 names first; and every byte
/// from the end of the main header to the `RR` header is the byte an
/// output that cannot patch writes, which carries no locator at all.
#[test]
fn the_default_layout_locator_names_each_volumes_record() {
    use crate::write::WriteFormat;

    let shape = |name, volume| RecoveryShape {
        name,
        format: WriteFormat::Rar5,
        level: None,
        headers: false,
        reference: false,
        volume,
        percent: 5,
    };
    let seek = |writer: crate::write::Writer<'_>| {
        if writer.options.volume_set() {
            let mut volumes = PatchOnly(Vec::new());
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            (volumes.0, report)
        } else {
            let mut out = std::io::Cursor::new(Vec::new());
            let report = writer.finish_seek(&mut out).expect("finish_seek");
            (vec![out.into_inner()], report)
        }
    };
    let stream = |writer: crate::write::Writer<'_>| {
        if writer.options.volume_set() {
            let mut volumes = StreamOnly(Vec::new());
            let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
            (volumes.0, report)
        } else {
            let mut out = Vec::new();
            let report = writer.finish_into(&mut out).expect("finish_into");
            (vec![out], report)
        }
    };
    let len = 200usize << 10;
    for limit in [u64::MAX, 0] {
        let _limit = CopyLimit::set(limit);
        for shape in [shape("single", None), shape("set", Some(96 << 10))] {
            let (located, _) = recovery_run(shape, len, &seek);
            let (plain, _) = recovery_run(shape, len, &stream);
            assert_eq!(located.len(), plain.len(), "{}", shape.name);
            if shape.volume.is_some() {
                assert!(located.len() >= 2, "{}: one volume", shape.name);
            }
            for (index, (with, without)) in located.iter().zip(&plain).enumerate() {
                let what = format!("{} volume {index} at copy limit {limit}", shape.name);
                let (locator, rr) = locator_and_rr(with);
                let locator = locator.unwrap_or_else(|| panic!("{what}: no locator"));
                assert_eq!(locator.flags, 0x0002, "{what}");
                assert_eq!(rr.len(), 1, "{what}");
                assert_eq!(locator.recovery, Some(rr[0]), "{what}");
                let width = crate::write::rar5::locator_reserve_width(
                    [
                        (len as u64, &b"noise.bin"[..]),
                        (len as u64 / 3 + 17, &b"text.txt"[..]),
                    ]
                    .into_iter(),
                );
                assert_eq!(width, 5, "{what}: the estimate's width");
                let main = crate::write::rar5::main_header(&crate::write::rar5::MainPlan {
                    volume_set: shape.volume.is_some(),
                    volume_number: index as u32,
                    solid: false,
                    recovery: true,
                    locked: false,
                    locator: Some(crate::write::rar5::Locator {
                        quick_open: None,
                        recovery: Some((locator.raw_recovery.expect("raw"), width)),
                    }),
                });
                assert_eq!(
                    &with[8..8 + main.len()],
                    &main[..],
                    "{what}: the main header"
                );

                let (none, plain_rr) = locator_and_rr(without);
                assert!(
                    none.is_none(),
                    "{what}: an output that cannot patch wrote one"
                );
                let main_end = |v: &[u8]| {
                    let mut at = 12;
                    let size = crate::read::vint::read(v, &mut at).expect("size");
                    at + size as usize
                };
                // In a capped volume the locator's bytes take room, so a
                // set splits a few bytes earlier; a single archive's members
                // are the same bytes, and a set's volumes keep their cap.
                match shape.volume {
                    None => assert_eq!(
                        &with[main_end(with)..rr[0] as usize],
                        &without[main_end(without)..plain_rr[0] as usize],
                        "{what}: the members' bytes moved"
                    ),
                    Some(cap) => assert!(with.len() as u64 <= cap, "{what}: past the cap"),
                }

                // Spoil the first block after the main header; only the
                // locator can lead to the record now.
                let mut broken = with.clone();
                broken[main_end(with)] ^= 0xFF;
                let area = crate::recovery::scan::record_area(&broken, broken.len() as u64)
                    .unwrap_or_else(|| panic!("{what}: the locator did not lead to the record"));
                let mut plain_broken = without.clone();
                plain_broken[main_end(without)] ^= 0xFF;
                assert!(
                    crate::recovery::scan::record_area(&plain_broken, plain_broken.len() as u64)
                        .is_none(),
                    "{what}: the header chain survived the spoiled header"
                );
                assert!(
                    area.start > rr[0] && area.end <= with.len() as u64,
                    "{what}"
                );
            }
        }
        // Under header encryption no locator is written (spec G 3.11: which
        // byte rar 7.23 counts from there is not measured yet), so an
        // output that can patch writes what one that cannot writes.
        let hp = RecoveryShape {
            headers: true,
            ..shape("hp", None)
        };
        let (located, _) = recovery_run(hp, len, &seek);
        let (plain, _) = recovery_run(hp, len, &stream);
        assert!(
            located == plain,
            "-hp at copy limit {limit}: the outputs differ"
        );
    }
}

/// **The reference layout with a recovery record is rar 7.23's archive,
/// byte for byte, but for one difference** (spec G
/// 3.6.1 and 3.11): each record's set tag (spec L 3.5.2, `0x40 + 8k`) is
/// content-derived here and clock-derived there, and so is each record's
/// CRC-64 over it. Everything else agrees: the locator (flags 0x0003, the
/// quick-open and recovery offsets at 3.6.3's width of 4), the members, the
/// quick-open block, the `RR` header WITHOUT a data CRC32, the parity and
/// the end header. The vector is `rar a -ma5 -m0 -rr3` over a 3 byte
/// `a.txt` and a 4,097 byte `b.bin` of `x`, mode 0644, mtime 1,790,740,800;
/// `b.bin`'s payload is left out of the constants and put back here.
#[test]
fn the_reference_layout_with_a_record_is_what_rar_writes_but_for_the_set_tag() {
    use crate::write::{HostOs, Layout, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

    const HEAD: &str = concat!(
        "526172211a070100382cd4d70f01050b080a0103d8a0800094a180000fc5d8c11b02028300068300a483024089bc6a7a",
        "7a6fed80000105612e74787468690a698519411b02028120068120a483024089bc6ad2f4816080000105622e62696e",
    );
    const TAIL: &str = concat!(
        "6dcc37ab0e0306a90000a9000080000102514fe6ac2e392400a12020698519411b02028120068120a483024089bc6ad2",
        "f4816080000105622e62696ea7b1873412030703c40700c407008000010252520207037b52427dc9e220106d798b97c4",
        "03000070000000010100000000000000004c0300009c100000000000005403000000000000c403000000000000050001",
        "000000a4c3bdfb5fc5e3f20f2c71060b5691790f2c71060b5691790f2c71060b569179fc7b0f445692f6ac7b687a2e28",
        "9a214d6aa8334d7b46d2e788beed7c84e786e5d6152b17e897fe17ad67fe172a7946287917836d2946f8e7a49d835254",
        "6165ff35fb4ecd87e77f0826ac315ccffad2aa51b0c5b07ab752ed2e9d89665647909f0bfabdd605a8fe17d2e6341ecd",
        "fac80fc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8afc8",
        "afc8afc8afc8afc8afc8afc8afc8afc8afc8afdd1b877cbed4b67eb0d719d7b057b0d6b286ff311cf989f3b07690f7d9",
        "52a996abd5b25690d131f71454b297396bda054456d057b0d6b5b59eb5d9b9b0d7b0d7b0d7b0d71d77565103050400",
    );
    let unhex = |text: &str| -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    };
    let large = vec![b'x'; 4_097];
    let mut rar = unhex(HEAD);
    rar.extend_from_slice(&large);
    rar.extend_from_slice(&unhex(TAIL));

    let small = b"hi\n".to_vec();
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        layout: Layout::Reference { quick_open: true },
        recovery_percent: Some(3),
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in [(&b"a.txt"[..], &small), (&b"b.bin"[..], &large)] {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: Some(crate::Timestamp {
                    unix_seconds: 1_790_740_800,
                    nanos: 0,
                }),
                attributes: 0o100644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut ours = Vec::new();
    writer.finish_into(&mut ours).expect("finish");
    assert_eq!(ours.len(), rar.len(), "lengths");

    // Blank the two named fields of every record in both archives, at the
    // places rar's own records say they are.
    let mut records = 0;
    let mut at = 0;
    while let Some(found) = rar[at..].windows(4).position(|w| w == b"{RB}") {
        let start = at + found;
        let k = u16::from_le_bytes([rar[start + 0x3A], rar[start + 0x3B]]) as usize;
        let tag = start + 0x40 + 8 * k;
        for archive in [&mut rar, &mut ours] {
            archive[start + 4..start + 12].fill(0);
            archive[tag..tag + 8].fill(0);
        }
        records += 1;
        at = start + 4;
    }
    assert!(records >= 1, "no record found in the vector");
    let first = ours.iter().zip(&rar).position(|(a, b)| a != b);
    assert_eq!(first, None, "first difference at {first:?}");
}

/// Spec G 3.7.3: at levels 4 and 5 a segment team the memory left holds
/// under four engines is the one engine's walk (two engines were 0.74x of
/// one, four 1.16x, measured 2 Oct 2026); at
/// four it is the team; and levels 1 to 3 keep whatever the bounds give.
#[cfg(feature = "parallel")]
#[test]
fn a_team_under_four_engines_at_levels_4_and_5_is_the_one_engines_walk() {
    use crate::write::engine::segment_team;
    // A pool of 96, a member of 60 stretches, the rule's 24 engines.
    for level in [4u8, 5] {
        for afford in [1usize, 2, 3] {
            assert_eq!(
                segment_team(level, 96, 60, afford, 24),
                1,
                "-m{level}, {afford} afforded"
            );
        }
        assert_eq!(
            segment_team(level, 96, 60, 4, 24),
            4,
            "-m{level}, four afforded"
        );
        assert_eq!(
            segment_team(level, 96, 60, 9, 24),
            9,
            "-m{level}, nine afforded"
        );
        assert_eq!(
            segment_team(level, 96, 60, usize::MAX, 24),
            24,
            "-m{level}, the rule's engines"
        );
        // The floor is on the team, whichever bound made it small.
        assert_eq!(
            segment_team(level, 96, 3, usize::MAX, 24),
            1,
            "-m{level}, three stretches"
        );
        assert_eq!(
            segment_team(level, 3, 60, usize::MAX, 24),
            1,
            "-m{level}, a pool of three"
        );
    }
    for level in [1u8, 2, 3] {
        assert_eq!(
            segment_team(level, 96, 60, 2, 24),
            2,
            "-m{level} keeps a team of two"
        );
        assert_eq!(
            segment_team(level, 96, 60, 3, 24),
            3,
            "-m{level} keeps a team of three"
        );
    }
}

/// Spec G 3.7.3: at levels 2 and 3 a segment team the working limit
/// affords fewer engines than gain at its window is the one engine's
/// walk: three, or two at a window of 8 MiB and more (at 2 MiB windows two
/// engines were 0.82x and 0.77x of one, three 1.06x and level,
/// measured 2 Oct 2026).
#[cfg(feature = "parallel")]
#[test]
fn the_engines_the_memory_must_afford_a_team_at_levels_2_and_3() {
    use crate::write::engine::segment_afforded_least;
    for level in [2u8, 3] {
        // Blocks of 256 KiB: 2 MiB, 4 MiB, 8 MiB and 32 MiB windows.
        assert_eq!(segment_afforded_least(level, 8), 3, "-m{level}, 2 MiB");
        assert_eq!(segment_afforded_least(level, 16), 3, "-m{level}, 4 MiB");
        assert_eq!(segment_afforded_least(level, 32), 2, "-m{level}, 8 MiB");
        assert_eq!(segment_afforded_least(level, 128), 2, "-m{level}, 32 MiB");
        // A window under 2 MiB has no row: three, as at 2 MiB.
        assert_eq!(segment_afforded_least(level, 4), 3, "-m{level}, 1 MiB");
    }
}

/// **Level 3's default dictionary and its far-link budget, on what the
/// options resolve to** (spec G 3.8.1; `options::LEVEL3_DICTIONARY`,
/// `options::LEVEL3_FAR_LINKS`). The integration test
/// `level3_default_dictionary` holds the bytes; this holds the part
/// bytes cannot show, that the budget goes with the DEFAULT dictionary
/// and with nothing else: a named dictionary is searched with no budget,
/// a budget the caller set is kept, and no other non-solid level and
/// nothing of the RAR 4 family is given one.
#[test]
fn level_3s_default_dictionary_alone_brings_its_far_link_budget() {
    use super::options::{
        resolve, DEFAULT_DICTIONARY, LEVEL1_DICTIONARY, LEVEL3_DICTIONARY, SOLID_DICTIONARY,
    };
    use super::{FilterPolicy, Rar4Version, WriteFormat, WriteMethod, WriteOptions};

    let ask = |format, level, solid, dictionary, budget, keep| {
        let resolved = resolve(WriteOptions {
            format,
            method: WriteMethod::Compressed { level, dictionary },
            solid,
            filters: match format {
                WriteFormat::Rar5 => FilterPolicy::Detect,
                WriteFormat::Rar4(_) => FilterPolicy::Off,
            },
            far_link_budget: budget,
            level3_dictionary_2mib: keep,
            ..WriteOptions::default()
        })
        .expect("options");
        (resolved.dictionary, resolved.far_link_budget)
    };
    let rar5 = WriteFormat::Rar5;
    let rar4 = WriteFormat::Rar4(Rar4Version::V29);

    // The default, and the two ways a caller takes part of it back.
    assert_eq!(
        ask(rar5, 3, false, None, None, false),
        (LEVEL3_DICTIONARY, Some(1))
    );
    assert_eq!(
        ask(rar5, 3, false, None, Some(4), false),
        (LEVEL3_DICTIONARY, Some(4))
    );
    assert_eq!(
        ask(rar5, 3, false, None, Some(0), false),
        (LEVEL3_DICTIONARY, Some(0))
    );
    assert_eq!(
        ask(rar5, 3, false, None, None, true),
        (DEFAULT_DICTIONARY, None)
    );
    // A memory ceiling the caller NAMED keeps 2 MiB and no budget; an
    // allowance nobody named, of any size, does not decide it.
    let under = |memory: crate::MemoryPolicy| {
        let resolved = resolve(WriteOptions {
            method: WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            memory,
            ..WriteOptions::default()
        })
        .expect("options");
        (resolved.dictionary, resolved.far_link_budget)
    };
    for named in [512u64 << 20, 8 << 30] {
        assert_eq!(
            under(crate::MemoryPolicy::from_limit(named)),
            (DEFAULT_DICTIONARY, None)
        );
        assert_eq!(
            under(crate::MemoryPolicy::for_process(named, 0)),
            (DEFAULT_DICTIONARY, None)
        );
        let allowance = crate::MemoryPolicy {
            working_limit: named,
            ..crate::MemoryPolicy::default()
        };
        assert!(!allowance.limit_named);
        assert_eq!(under(allowance), (LEVEL3_DICTIONARY, Some(1)));
    }
    // A named dictionary: no budget, at the default's own figure too.
    for named in [2u64 << 20, 16 << 20, 32 << 20] {
        assert_eq!(ask(rar5, 3, false, Some(named), None, false), (named, None));
        assert_eq!(
            ask(rar5, 3, false, Some(named), Some(2), false),
            (named, Some(2))
        );
    }
    // Everything else is as it was, with the option off and on.
    for keep in [false, true] {
        for level in [1u8, 2, 4, 5] {
            let unnamed = if level == 1 {
                LEVEL1_DICTIONARY
            } else {
                DEFAULT_DICTIONARY
            };
            assert_eq!(ask(rar5, level, false, None, None, keep), (unnamed, None));
        }
        for level in 1u8..=5 {
            // A solid RAR 5 archive has its own default, which this
            // option does not reach (the test below holds it).
            assert_eq!(
                ask(rar5, level, true, None, None, keep),
                if level >= 2 {
                    (SOLID_DICTIONARY, Some(1))
                } else {
                    (DEFAULT_DICTIONARY, None)
                }
            );
            for solid in [false, true] {
                assert_eq!(
                    ask(rar4, level, solid, None, None, keep),
                    (DEFAULT_DICTIONARY, None)
                );
            }
        }
    }
}

/// **The solid default dictionary and its far-link budget, on what the
/// options resolve to** (spec G 3.8.1; `options::SOLID_DICTIONARY`,
/// `options::SOLID_FAR_LINKS`). The integration test
/// `solid_default_dictionary` holds the bytes; this holds what bytes
/// cannot show: the budget goes with the DEFAULT dictionary at levels 2
/// to 5 and with nothing else, level 1 keeps 2 MiB, and a named
/// dictionary, the option, a named ceiling, a stored archive and the
/// RAR 4 family take neither.
#[test]
fn the_solid_default_dictionary_alone_brings_its_far_link_budget() {
    use super::options::{resolve, DEFAULT_DICTIONARY, SOLID_DICTIONARY};
    use super::{FilterPolicy, Rar4Version, WriteFormat, WriteMethod, WriteOptions};

    let ask = |format, level, dictionary, budget, keep, memory: Option<crate::MemoryPolicy>| {
        let resolved = resolve(WriteOptions {
            format,
            method: WriteMethod::Compressed { level, dictionary },
            solid: true,
            filters: match format {
                WriteFormat::Rar5 => FilterPolicy::Detect,
                WriteFormat::Rar4(_) => FilterPolicy::Off,
            },
            far_link_budget: budget,
            solid_dictionary_2mib: keep,
            memory: memory.unwrap_or_default(),
            ..WriteOptions::default()
        })
        .expect("options");
        (resolved.dictionary, resolved.far_link_budget)
    };
    let rar5 = WriteFormat::Rar5;
    let rar4 = WriteFormat::Rar4(Rar4Version::V29);

    assert_eq!(SOLID_DICTIONARY, 32 << 20);
    assert_eq!(
        ask(rar5, 1, None, None, false, None),
        (DEFAULT_DICTIONARY, None)
    );
    for level in 2u8..=5 {
        assert_eq!(
            ask(rar5, level, None, None, false, None),
            (SOLID_DICTIONARY, Some(1)),
            "-m{level}"
        );
    }
    for level in 1u8..=5 {
        // Level 1 keeps the general default; levels 2 to 5 their own.
        let default = if level >= 2 {
            SOLID_DICTIONARY
        } else {
            DEFAULT_DICTIONARY
        };
        // A budget the caller set is the caller's.
        for own in [0u32, 4] {
            assert_eq!(
                ask(rar5, level, None, Some(own), false, None),
                (default, Some(own))
            );
        }
        // The option, and a ceiling the caller NAMED, keep 2 MiB and no
        // budget; an allowance nobody named does not decide it.
        assert_eq!(
            ask(rar5, level, None, None, true, None),
            (DEFAULT_DICTIONARY, None)
        );
        for named in [512u64 << 20, 8 << 30] {
            assert_eq!(
                ask(
                    rar5,
                    level,
                    None,
                    None,
                    false,
                    Some(crate::MemoryPolicy::from_limit(named))
                ),
                (DEFAULT_DICTIONARY, None)
            );
            let allowance = crate::MemoryPolicy {
                working_limit: named,
                ..crate::MemoryPolicy::default()
            };
            assert_eq!(
                ask(rar5, level, None, None, false, Some(allowance)).0,
                default
            );
        }
        // A named dictionary: no budget, at the default's own figure too.
        for named in [2u64 << 20, 32 << 20, 64 << 20] {
            assert_eq!(
                ask(rar5, level, Some(named), None, false, None),
                (named, None)
            );
        }
        // The RAR 4 family did not move.
        for keep in [false, true] {
            assert_eq!(
                ask(rar4, level, None, None, keep, None),
                (DEFAULT_DICTIONARY, None)
            );
        }
    }
    // A stored solid archive resolves as it did.
    let stored = resolve(WriteOptions {
        method: WriteMethod::Stored,
        solid: true,
        ..WriteOptions::default()
    })
    .expect("options");
    assert_eq!(
        (stored.dictionary, stored.far_link_budget),
        (DEFAULT_DICTIONARY, None)
    );
}

/// A `Cursor` that counts the writes that land BEHIND its end: the
/// corrections of headers laid down with a placeholder.
#[cfg(test)]
struct Behind {
    inner: std::io::Cursor<Vec<u8>>,
    behind: usize,
}

#[cfg(test)]
impl std::io::Write for Behind {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.inner.position() < self.inner.get_ref().len() as u64 {
            self.behind += 1;
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl std::io::Seek for Behind {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// **A small stored reader member over a seekable output is hashed before
/// its header and never corrected** (`Run::digest_before_header`), and
/// the archive is the one a non-seekable output gets, byte for byte, in
/// RAR 5 and RAR 4. A member past the copy buffer keeps its placeholder,
/// which is what shows the count can see a correction. `workers: 1`: no
/// helper thread is asked for, and the members are far below any
/// read-ahead's floor.
#[test]
fn a_small_stored_reader_is_hashed_before_its_header() {
    use crate::write::{MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};
    let sizes: [usize; 5] = [1, 512, 4096, 70_001, crate::write::options::COPY_CHUNK];
    let bodies: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(n, &len)| (0..len).map(|i| (i * 31 + n * 7) as u8).collect())
        .collect();
    let large: Vec<u8> = (0..crate::write::options::COPY_CHUNK + 1)
        .map(|i| (i % 251) as u8)
        .collect();
    let write = |format: WriteFormat, with_large: bool, seek: bool| -> (Vec<u8>, usize) {
        let mut writer = Writer::new(WriteOptions {
            format,
            method: WriteMethod::Stored,
            filters: crate::write::FilterPolicy::Off,
            workers: Some(1),
            ..WriteOptions::default()
        })
        .expect("options");
        let mut readers: Vec<std::io::Cursor<&[u8]>> = bodies
            .iter()
            .map(|body| std::io::Cursor::new(&body[..]))
            .collect();
        let mut big = std::io::Cursor::new(&large[..]);
        let names: Vec<Vec<u8>> = (0..sizes.len())
            .map(|n| format!("m{n}.bin").into_bytes())
            .collect();
        for ((name, reader), body) in names.iter().zip(readers.iter_mut()).zip(&bodies) {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Reader {
                        reader,
                        size: body.len() as u64,
                        crc32: None,
                    },
                    mtime: None,
                    attributes: 0o100644,
                    host_os: crate::write::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        if with_large {
            writer
                .add(MemberSpec {
                    name: b"large.bin",
                    payload: Payload::Reader {
                        reader: &mut big,
                        size: large.len() as u64,
                        crc32: None,
                    },
                    mtime: None,
                    attributes: 0o100644,
                    host_os: crate::write::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        if seek {
            let mut out = Behind {
                inner: std::io::Cursor::new(Vec::new()),
                behind: 0,
            };
            writer.finish_seek(&mut out).expect("finish_seek");
            (out.inner.into_inner(), out.behind)
        } else {
            let mut out = Vec::new();
            writer.finish_into(&mut out).expect("finish_into");
            (out, 0)
        }
    };
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(crate::write::Rar4Version::V29),
    ] {
        let (seeked, behind) = write(format, false, true);
        let (held, _) = write(format, false, false);
        assert_eq!(
            behind, 0,
            "{format:?}: a small reader's header was corrected"
        );
        assert!(seeked == held, "{format:?}: the seekable archive differs");
        let (seeked, behind) = write(format, true, true);
        let (held, _) = write(format, true, false);
        assert!(behind > 0, "{format:?}: the large member was not corrected");
        assert!(seeked == held, "{format:?}: the seekable archive differs");
    }
}
