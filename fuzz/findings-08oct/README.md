# Fuzz campaign, 8 October 2026: findings

A campaign over every fuzz target of both trees, asked for because the
week's lands had rewritten or touched several decoders and the targets
had had ten minute runs only since. **No panic of the engine, no hang, no
out of memory, no timeout and no memory fault in 7.4 billion executions
and 299 fuzzer hours.** Six items were filed, all of them a target's own
assertion: none is a release blocker by the campaign's four classes (an
archive that makes `rarfast t` or `x` panic, hang, write outside the
output directory, or take memory past the stated limit). **Six of the 52
targets stop on one of those items and could not be fuzzed as they
stand**, which is the campaign's larger result: the RAR 5 member and solid
chain targets since this week's rewrites, and both writer targets, by
inference, since 27 September.

The items are in the project's sweep item files as FUZZ-08OCT-1 to -6, in
the form those files use: the defect and the scenario, no fix. Their
minimised inputs are pinned under `fuzz/seeds/` with a README section
each, and two have an ignored test under `crates/rarkit/tests/`.

## What ran

| | M1 Ultra Mac | x86-64 box |
|---|---|---|
| box | Mac Studio M1 Ultra, 20 cores, aarch64 macOS | AWS c7i.metal-24xl, 96 threads, x86-64 Linux |
| toolchain | nightly 2026-09-26, cargo-fuzz 0.13.2 | nightly 2026-10-06, cargo-fuzz 0.13.2 |
| build | cargo-fuzz default: release, debug assertions and overflow checks ON, AddressSanitizer, every target | the same (LeakSanitizer is live on Linux) |
| width | 18 fuzzers, one a target, no `-jobs`/`-workers` | up to 51, nice 19, pinned to 64 threads |
| rarkit | 46a1d5bd5 from 22:37Z 7 Oct to 02:38Z 8 Oct, then 85cbb5ade (chain 4) to 12:39Z | 85cbb5ade throughout, 07:53Z to 10:59Z between other lanes' holds |
| fuzzer time | 214.0 hours | 85.4 hours |
| executions | 2,231,368,735 | 5,197,101,421 |
| limits | `-timeout=60 -rss_limit_mb=2048 -max_len=65536` | the same |

A second Mac of the same shape was not used: a timed measurement needed
it, and the rented x86-64 box took its place. The 85cbb5ade tree on a box is the 46a1d5bd5 bundle
with the chain's diff of `crates/rarkit/src`, `tests` and `benches`
applied; its one changed source file, `write/filters.rs`, was checked by
sha256. The budget was four hours for each target over the decoders the
week touched and one hour for each other target; on the M1 Ultra Mac the first
group was then raised to six. The x86-64 box was stopped early, with about
two of its four hours done, when the campaign was closed: it spent 2.7
hours waiting on other lanes' holds, each of which stopped its fuzzers by
pid.

The repository's fuzz campaign driver ran every job. A box-side loop (not committed)
ran it in one hour segments over one shared corpus, read the rig lock and
the coordination file every ten seconds, and kept each target's time
across segments, so a target stopped by a hold or by a finding was owed
the rest.

## The items

| item | targets it stops | what | at the command line |
|---|---|---|---|
| FUZZ-08OCT-1 | `fuzz:rar5_member`, `fuzz:rar5_solid_chain`, inside one second | one short RAR 5 member: the serial decode says `Truncated`, the parallel decode `Corrupt(Rar5(IncompleteMember))` | not visible: the same checksum error and exit 3 at every width |
| FUZZ-08OCT-2 | `fuzz:rar5_oracle_stream`, at execution 71 | the defect SWEEP2-08OCT-18 already describes: a member declaring 0 bytes with a filter record | `rarfast t` exit 3; unrar 7.23 `All OK` |
| FUZZ-08OCT-3 | `fuzz:rar5_member` (met through its box-only copy after 4.3 million executions) | both arms fail with `Corrupt(Rar5(InvalidCode))`, the serial after delivering all 262,144 declared bytes, the parallel after none | `rarfast t` and `x` exit 3 at every width, no file left; unrar 7.23 extracts the member whole |
| FUZZ-08OCT-4 | `fuzz:write_members`, `fuzz:write_volumes` (on its committed seeds, execution 102) | a plain member whose Unix attributes carry the symbolic link type is written Ok and then refused by `rarkit::extract` | no route found |
| FUZZ-08OCT-5 | both writer targets | X: a SOLID archive's member order is the writer's and not the caller's, both formats, read `All OK` by unrar. Y: a compressed RAR 4 member cut at a volume payload budget of 1, 3 or 4 bytes is a set rarkit passes and unrar 7.23 fails with a checksum error | no route found: `rarfast` cannot write RAR 4; RAR 5 sets at `-v64b`, `-v200b`, `-v1k` test `All OK` in unrar |
| FUZZ-08OCT-6 | `fuzz:rar5_oracle_reframe`, after about 300,000 executions | a RAR 5 member declaring 0 bytes and method 6 or 7: the old engine passes it, rarkit refuses the method, unrar 7.23 says "No files to extract" | `rarfast t` exit 2 |

Y of FUZZ-08OCT-5 was not found by a target: no target has the genuine
tool in it. It was seen by testing, with unrar, the volume set the writer
returned for the input that showed X.

Two things that are NOT items. A LeakSanitizer report on the x86-64 box
from `crates/rarkit/fuzz:f_extract_parallel` (144 bytes in 4 allocations):
the allocation is the standard library's own per-thread channel context in
a worker thread, and the input did not reproduce it in 20 single replays
or in 2,000 runs in one process; it reads as the sanitizer looking before
a finished thread's own storage was released. And eleven slow units from the
writer copies, 17 to 25 seconds, the same construction cost the 20
September campaign described.

## Every target

Coverage is libFuzzer's `cov:` figure, the first one printed after the
seeds were read and the last of the last segment. A rate on the M1 Ultra Mac is
under 18-way load; on the x86-64 box under up to 51 jobs on 64 threads at
nice 19. `c:` is `crates/rarkit/fuzz:`.

| target | what it reaches | seeds | M1 Ultra Mac: hours, executions, rate, coverage first to last | x86-64 box: the same | finding |
|---|---|---|---|---|---|
| `fuzz:blake2sp_chunking` | BLAKE2sp, cut points and worker allowance | 0 | 1.00 h, 22,093,318, 6134/s, 141 to 348 | 1.01 h, 17,677,590, 4874/s, 144 to 190 | none |
| `fuzz:edit_roundtrip` | every edit entry point over a seeded archive | 164 | 1.00 h, 23,581,044, 6547/s, 3349 to 5241 | 1.01 h, 10,151,283, 2798/s, 3388 to 5198 | none |
| `fuzz:member_decryptor` | member decryptor, any cipher and chunking | 0 | 6.00 h, 61,526,622, 2847/s, 19 to 1102 | 2.09 h, 11,466,376, 1522/s, 19 to 1368 | none |
| `fuzz:rar20_audio_lane` | RAR 2.0 audio predictor, narrow lane against wide | 24 | 1.00 h, 3,479,966, 966/s, 107 to 116 | 1.01 h, 1,922,359, 529/s, 105 to 111 | none |
| `fuzz:rar20_member` | one RAR 2.0 member | 1 | 1.00 h, 12,979,825, 3604/s, 67 to 799 | 1.01 h, 10,508,145, 2898/s, 69 to 808 | none |
| `fuzz:rar20_tables` | RAR 2.0 block header and tables | 0 | 1.00 h, 16,306,450, 4527/s, 103 to 780 | 1.01 h, 35,949,249, 9909/s, 105 to 791 | none |
| `fuzz:rar29_encode_roundtrip` | RAR 2.9 encoder, decoded back | 0 | 1.00 h, 642,910, 178/s, 19 to 3272 | 1.01 h, 239,261, 65/s, 19 to 3409 | none |
| `fuzz:rar15_window_edge` | RAR 1.x member lapping its ring three times | 0 | 6.00 h, 787,186, 36/s, 710 to 1013 | 2.09 h, 148,546, 19/s, 649 to 948 | none |
| `fuzz:rar1x_member` | one RAR 1.x member, declared size and solid flag | 10 | 6.00 h, 14,496,353, 670/s, 754 to 977 | 2.09 h, 3,120,914, 414/s, 743 to 924 | none |
| `fuzz:rar3_filter_record` | RAR 3 filter record stream | 17 | 1.00 h, 18,750,025, 5206/s, 427 to 2285 | 1.01 h, 17,471,215, 4820/s, 417 to 2077 | none |
| `fuzz:rar3_filter_transforms` | RAR 3 filter transforms, both directions | 11 | 1.00 h, 26,441,388, 7341/s, 553 to 3593 | 1.01 h, 30,482,560, 8404/s, 508 to 3364 | none |
| `fuzz:rar3_lz_window_edge` | RAR 3 match distances at the window edge | 0 | 6.00 h, 615,345, 28/s, 20 to 2879 | 2.09 h, 107,740, 14/s, 20 to 2859 | none |
| `fuzz:rar4_encrypted_header_walk` | RAR 4 encrypted header walk | 0 | 6.00 h, 161,237,161, 7462/s, 98 to 425 | 2.09 h, 76,680,099, 10188/s, 99 to 599 | none |
| `fuzz:rar5_block_chain` | RAR 5 block chain walk only | 0 | 6.00 h, 264,101,803, 12222/s, 33 to 55 | 2.09 h, 2,040,048,444, 271055/s, 38 to 65 | none |
| `fuzz:rar5_encode_roundtrip` | RAR 5 encoder, decoded back | 0 | 1.00 h, 779,484, 216/s, 19 to 5363 | 1.01 h, 244,192, 67/s, 19 to 5445 | none |
| `fuzz:rar5_encrypted_header_walk` | RAR 5 encrypted header walk | 0 | 6.00 h, 60,815,527, 2814/s, 122 to 237 | 2.09 h, 14,143,131, 1879/s, 204 to 368 | none |
| `fuzz:rar5_encryption_record` | RAR 5 encryption record | 0 | 6.00 h, 283,823,129, 13135/s, 34 to 444 | 2.09 h, 1,839,026,435, 244372/s, 34 to 451 | none |
| `fuzz:rar5_drain_lap` | RAR 5 drain against the ring, filtered member | 0 | 6.00 h, 492,959, 22/s, 321 to 1564 | 2.09 h, 74,830, 9/s, 337 to 1533 | none |
| `fuzz:rar5_filter_offload` | RAR 5 filters off the drain's thread | 0 | 6.00 h, 91,489, 4/s, 742 to 1493 | 2.09 h, 14,632, 1/s, 812 to 1508 | none |
| `fuzz:rar5_member` | one RAR 5 member, serial against parallel | 2 | 0.00 h, 2,553, 1063/s, 384 to 454 | - | FUZZ-08OCT-1, at once |
| `fuzz:rar5_oracle_reframe` | RAR 5 archive reframed, against the old engine | 0 | 6.00 h, 82,309,329, 3809/s, 96 to 104 | 0.45 h, 847,609, 524/s, 72 to 9458 | FUZZ-08OCT-6 (rental only) |
| `fuzz:rar5_oracle_small` | many small RAR 5 members, three readers | 5 | 6.00 h, 99,058, 4/s, 18835 to 27893 | 2.09 h, 24,177, 3/s, 18279 to 25077 | none |
| `fuzz:rar5_oracle_stream` | scripted RAR 5 streams, against the old engine | 10 | 0.00 h, 71, 22/s, 9693 to 10288 | - | FUZZ-08OCT-2, at once |
| `fuzz:rar5_solid_chain` | RAR 5 solid chain, serial against parallel | 1 | 0.04 h, 167,259, 1177/s, 105 to 2021 | - | FUZZ-08OCT-1, at once |
| `fuzz:rar5_tables` | one RAR 5 block's tables | 0 | 6.00 h, 265,455,429, 12285/s, 32 to 806 | 2.09 h, 342,688,506, 45552/s, 41 to 642 | none |
| `fuzz:rar5_window_edge` | RAR 5 match distances at the window edge | 0 | 6.00 h, 550,025, 25/s, 19 to 4863 | 2.09 h, 104,340, 13/s, 19 to 4687 | none |
| `fuzz:read_seam` | one member's overlapped read, decrypt, decode, checksum | 4 | 6.00 h, 198,109, 9/s, 9008 to 15183 | 2.09 h, 31,860, 4/s, 8879 to 14094 | none |
| `fuzz:rr5_encode_paths` | recovery record encode, stream against team | 0 | 1.00 h, 13,698, 3/s, 19 to 1090 | 1.17 h, 4,720, 1/s, 19 to 1068 | none |
| `fuzz:write_members` | writer: member list written and read back | 1 | 0.00 h, 7,960, 1693/s, 17 to 8774 | - | FUZZ-08OCT-4 |
| `fuzz:write_reader_payload` | writer: a scripted payload reader | 0 | 1.00 h, 245,191, 68/s, 19 to 6732 | 1.01 h, 113,688, 31/s, 19 to 6780 | none |
| `fuzz:store_sample_length` | writer: the store rule's counted sample | 0 | 1.00 h, 224,711, 62/s, 1472 to 2033 | 1.01 h, 104,001, 28/s, 1518 to 2159 | none |
| `fuzz:write_volumes` | writer: member list as a volume set | 287 | 0.00 h, 102, 27/s, None to None | - | FUZZ-08OCT-4, on its seeds |
| `c:blake2sp_chunking` | BLAKE2sp, cut points and arrangements | 0 | 1.00 h, 21,672,549, 6017/s, 140 to 345 | 1.01 h, 17,563,105, 4850/s, 143 to 187 | none |
| `c:f_extract_any` | extract over mutated vectors with a refusing sink | 84 | 6.00 h, 7,582,999, 350/s, 7436 to 14617 | 2.09 h, 904,279, 120/s, 7661 to 13532 | none |
| `c:f_extract_batches` | extract with small member batches | 24 | 6.00 h, 350,568, 16/s, 10806 to 13926 | 2.09 h, 45,190, 6/s, 8872 to 13177 | none |
| `c:f_extract_parallel` | extract_parallel against extract | 14 | 6.00 h, 2,791,546, 129/s, 6554 to 16741 | 1.91 h, 597,137, 86/s, 6658 to 15568 | none |
| `c:f_headers_encrypted` | header encrypted vectors, random passwords | 0 | 6.00 h, 109,533,291, 5069/s, 16 to 1299 | 2.09 h, 22,994,024, 3057/s, 16 to 1518 | none |
| `c:f_open_any` | Archive::open, short reads | 0 | 6.00 h, 190,920,807, 8835/s, 16 to 1474 | 2.09 h, 88,046,520, 11709/s, 16 to 1481 | none |
| `c:f_volumes_any` | volume sets shuffled, cut, duplicated | 0 | 6.00 h, 88,814,960, 4110/s, 16 to 3778 | 2.09 h, 19,646,523, 2613/s, 16 to 3846 | none |
| `c:k_two_lane_cbc` | CBC decrypt on two lanes against one | 0 | 6.00 h, 6,006,427, 277/s, 19 to 501 | 2.09 h, 1,491,070, 198/s, 19 to 840 | none |
| `c:legacy_rr_scan` | RAR 4 inline recovery record | 0 | 1.00 h, 24,146,973, 6704/s, 67 to 680 | 1.01 h, 13,290,491, 3671/s, 67 to 686 | none |
| `c:ppm_block` | one PPM block | 0 | 6.00 h, 11,871,625, 549/s, 24 to 895 | 2.09 h, 2,912,365, 387/s, 24 to 902 | none |
| `c:ppm_member` | solid run of PPM members, carrying on past a fault | 1 | 6.00 h, 13,286,390, 614/s, 649 to 1029 | 2.09 h, 1,947,634, 259/s, 651 to 1018 | none |
| `c:rar15_decode` | RAR 1.5 decoder, one to four chunks | 1 | 6.00 h, 44,444,990, 2056/s, 497 to 1000 | 2.09 h, 17,018,722, 2265/s, 439 to 935 | none |
| `c:rar3_filter_record` | RAR 3 filter record stream | 0 | 1.00 h, 23,814,946, 6612/s, 19 to 274 | 1.01 h, 20,542,141, 5675/s, 19 to 295 | none |
| `c:rar3_filter_transforms` | RAR 3 filter transforms | 0 | 1.00 h, 23,303,795, 6470/s, 19 to 3591 | 1.01 h, 48,532,941, 13398/s, 19 to 3362 | none |
| `c:rar3_lz_member` | one RAR 2.9 member | 0 | 6.00 h, 13,693,514, 633/s, 211 to 2398 | 2.09 h, 2,307,524, 307/s, 226 to 2235 | none |
| `c:rar3_lz_solid_chain` | four RAR 2.9 members of a solid chain | 0 | 6.00 h, 17,367,452, 803/s, 201 to 2293 | 2.09 h, 2,792,338, 371/s, 214 to 2258 | none |
| `c:rar3_lz_literal_burst` | RAR 2.9 literal runs at table boundaries | 111 | 6.00 h, 2,932,871, 135/s, 879 to 896 | 2.09 h, 499,223, 66/s, 885 to 902 | none |
| `c:rar3_lz_tables` | RAR 2.9 block header and tables | 0 | 6.00 h, 184,999,439, 8561/s, 149 to 413 | 2.09 h, 83,330,453, 11091/s, 152 to 412 | none |
| `c:rev_parse` | RAR 5 .rev header | 0 | 1.00 h, 38,521,666, 10696/s, 46 to 137 | 1.01 h, 372,925,535, 102989/s, 46 to 177 | none |
| `c:rr5_scan` | RAR 5 inline recovery record | 0 | 1.00 h, 23,327,868, 6477/s, 81 to 1111 | 1.01 h, 16,450,880, 4544/s, 81 to 1113 | none |

Forty-six of the 52 targets found nothing, in 262.7 fuzzer hours between
them. The other six stopped on an item as the table says; one of them,
`fuzz:rar5_oracle_reframe`, ran its full six hours clean on the M1 Ultra Mac and
stopped five times on the x86-64 box only.

## The box-only copies

Because a target that fails in its first second fuzzes nothing, it was
decided, target by target, that a COPY of it, on the box only and never
committed, could leave out the one comparison an item already
describes. Every figure below is from such a copy and is a WEAKER ORACLE
than the target it stands in for. The copies were removed from the boxes
when the campaign ended.

| box-only copy | what it leaves out | M1 Ultra Mac: hours, executions, rate, coverage | x86-64 box: the same | plans passed over, last count printed | finding |
|---|---|---|---|---|---|
| `rar5_member_weak` | error kind not compared between arms | 6.01 h, 34,629,648, 1601/s, 451 to 4118 | 2.09 h, 4,984,180, 663/s, 436 to 3430 | m1: -. rental: - | FUZZ-08OCT-3, five times |
| `rar5_solid_chain_weak` | error kind not compared between arms | 6.00 h, 23,165,710, 1072/s, 60 to 5616 | 2.09 h, 4,492,098, 598/s, 21 to 3983 | m1: -. rental: - | none |
| `write_members_weak` | plans with a symbolic link typed member passed over | 0.39 h, 171,468, 123/s, 17 to 13901 | - | m1: passed_over=555 of plans=80000. rental: - | FUZZ-08OCT-5 X |
| `write_volumes_weak` | the same | 0.01 h, 6,253, 188/s, 9226 to 10604 | - | m1: -. rental: - | FUZZ-08OCT-5 |
| `write_members_weak2` | also solid plans holding a zero byte file | 0.64 h, 163,664, 71/s, 11003 to 14435 | - | m1: symlink=596 solid_empty=5418 of plans=100000. rental: - | FUZZ-08OCT-5 X |
| `write_volumes_weak2` | the same | 0.15 h, 69,457, 126/s, 9094 to 11458 | - | m1: symlink=89 solid_empty=989 of plans=20000. rental: - | FUZZ-08OCT-5 X (RAR 5) |
| `write_members_weak3` | also solid plans holding a directory | 0.35 h, 78,151, 61/s, 12322 to 14669 | 0.21 h, 51,471, 67/s, 17 to 13643 | m1: symlink=178 solid_empty=2632 of plans=40000. rental: - | FUZZ-08OCT-5 X |
| `write_volumes_weak3` | the same | 1.00 h, 366,698, 101/s, 10158 to 12814 | 0.21 h, 28,857, 38/s, 9336 to 11475 | m1: symlink=854 solid_empty=17862 of plans=260000. rental: - | none |
| `write_members_weak4` | solid plans compared as a set (THIS FORM HAD A FAULT OF ITS OWN, see below) | 1.62 h, 217,183, 37/s, 10943 to 16901 | 0.73 h, 65,834, 24/s, 11811 to 14431 | m1: passed_over=120 of plans=40000; as a set: 90000. rental: passed_over=30 of plans=20000; as a set: 15000 | false alarm, the copy's own |
| `write_volumes_weak4` | the same | 1.69 h, 272,648, 44/s, 10175 to 15112 | 0.73 h, 61,588, 23/s, 10573 to 12416 | m1: passed_over=224 of plans=60000; as a set: 110000. rental: passed_over=64 of plans=20000; as a set: 15000 | false alarm, the copy's own |
| `write_members_weak5` | solid plans compared as a set, mended | 2.00 h, 228,976, 31/s, 10854 to 17285 | 1.14 h, 91,059, 22/s, 11813 to 14968 | m1: passed_over=201 of plans=60000; as a set: 95000. rental: passed_over=123 of plans=60000; as a set: 35000 | none |
| `write_volumes_weak5` | the same | 2.00 h, 298,724, 41/s, 10269 to 15560 | 1.14 h, 92,337, 22/s, 8835 to 12977 | m1: passed_over=298 of plans=100000; as a set: 120000. rental: passed_over=229 of plans=60000; as a set: 30000 | none |

The fourth form of the writer copies had a fault of its own: comparing a
solid plan as a set, it blanked the bytes of a FILE that shared its name
with a directory, and reported a set change that was not one (the bytes
had come back whole, by length and hash). Its three stops are that, not
findings, and the fifth form mended it. With the fifth form the writer
ran four hours on the M1 Ultra Mac and 2.3 on the x86-64 box at 85cbb5ade, which
carries the week's one writer change, and found nothing; about 0.3
percent of plans were passed over for the symbolic link type, and solid
plans were compared as a set.

The targets choose the archive format from the fuzz bytes and have no
switch for it, so RAR 5 plans could not be weighted ahead of RAR 4 ones.

## What no target reaches

Read from the targets' own descriptions, NOT measured: no coverage report
was drawn, and one (`cargo fuzz coverage` over the kept corpora) is owed
before this list is trusted.

1. **The command line.** No target drives `rarkit-cli`: switch parsing,
   name masks, the output path a member is written to, overwrite rules,
   listing. Three of the four release blocker classes are about that
   layer, and "writes outside the output directory" is reached by no
   target at all. A target would need the extract path's name handling
   behind a seam that takes a member name and an output root and answers
   the path it would write, or a harness that runs the binary's own entry
   point on a temporary directory.
2. **The genuine tools as an oracle for the WRITER.** Item 5's Y stood in
   the tree unseen because the writer targets read back with rarkit only.
   That cannot be a libFuzzer target on a fleet box without the reference
   binary beside it; it is a differential job over the writer corpus.
3. **Whole archives of the old formats.** RAR 1.x, RAR 2.0 and PPM are
   fuzzed at the decoder (member and block targets). Whether the `f_*`
   reader targets' vectors carry those formats through `extract` was not
   established.
4. **An encrypted solid chain through `extract`.** The encrypted targets
   are the two header walks, the record, the member decryptor and the two
   lane decrypt; `f_headers_encrypted` drives two header encrypted vectors.
   No target names the encrypted solid skip the week changed.
5. **The x86-64 arms for hours.** The x86-64 box gave them about two hours
   a target; before this campaign they had none in a campaign of this
   size.

## Owed

- The three RAR 5 targets and the two writer targets their hours on a tip
  that has FUZZ-08OCT-1, -2 (SWEEP2-08OCT-18), -3, -4 and -5 settled. They
  have had none as themselves.
- `fuzz:rar5_oracle_reframe` again once the method rule of FUZZ-08OCT-6
  (SWEEP2-08OCT-50's shape) is built.
- A coverage report over the kept corpora (726 MB from the M1 Ultra Mac, 509 MB
  from the x86-64 box; they are kept outside this repository, with the
  item inputs).
- The box-side segment loop, if the next campaign wants holds honoured
  and time kept across them: it is a tools lane's to adopt, not a fuzz
  lane's to commit.
