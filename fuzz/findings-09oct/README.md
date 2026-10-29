# Fuzz hours for six targets that had none, 9 October 2026

The tree's own fuzz campaign driver was run and what came back was
read. **Nothing
here is a fix, and nothing is triaged beyond the input and its one
line.**

The six: `fuzz:rar5_member`, `fuzz:rar5_solid_chain`,
`fuzz:rar5_oracle_stream`, `fuzz:write_members`, `fuzz:write_volumes`,
`fuzz:rar5_oracle_reframe`. The campaign of 8 October found all six
stopping on a target's own assertion inside seconds, so none had hours.

## What ran

| | |
|---|---|
| box | Mac Studio M1 Ultra, 20 cores, aarch64 macOS; not timed work, no rig lock held |
| tree | main 3db18e7c5f3d7a272a4739f85cac89cbddde02f4 |
| toolchain | the box's nightly, cargo-fuzz 0.13.2 |
| build | cargo-fuzz default: release, debug assertions and overflow checks ON, AddressSanitizer; both fuzz trees, all 52 targets, 232 s and 218 s |
| limits | the driver's defaults: `-timeout=60 -rss_limit_mb=2048 -max_len=65536` |
| width | ONE process a target (the driver never uses `-jobs` or `-workers`), six side by side |
| seeds | the tree's committed seeds: 5, 2, 12, 2, 288 and 1 inputs |

## Round one: 90 minutes asked of each, 17:07:51Z to 18:37:52Z

| target | ran | executions | a second | coverage at the end | how it ended |
|---|---:|---:|---:|---:|---|
| `fuzz:rar5_member` | 5,402 s | 8,228,074 | 1,523 | 3,871 (ft 11,134) | its whole budget, CLEAN: no crash, no timeout; peak RSS 200 MB and level; 7,341 new units, the last new block 1.4 percent before the end |
| `fuzz:rar5_solid_chain` | 2,457 s | 6,047,247 | 2,462 | 4,741 (ft 14,982) | libFuzzer out-of-memory: 2,050 MB against the 2,048 MB limit, the resident set rising 0.32 KB an execution to the end |
| `fuzz:rar5_oracle_reframe` | 2,421 s | 3,505,840 | 1,448 | 10,359 (ft 40,428) | libFuzzer out-of-memory: 2,070 MB, the resident set rising 0.65 KB an execution at the end |
| `fuzz:rar5_oracle_stream` | 3 s | 254 | - | 12,511 | the target's own assertion, at execution 254 |
| `fuzz:write_members` | 1 s | 2 | - | - | the target's own assertion, on its committed seeds |
| `fuzz:write_volumes` | 2 s | 90 | - | - | the same assertion, on its committed seeds |

No panic inside the engine, no hang, no timeout, no memory fault found
by AddressSanitizer in 17.8 million executions and 2.9 fuzzer hours.
Three targets still cannot be fuzzed as they stand; two more stop
themselves at the memory limit after about 40 minutes.

## The stops, one line each (inputs under `round1/inputs/`, as hex)

| target | artifact, sha256 | bytes | the line |
|---|---|---:|---|
| `fuzz:write_members` | `crash-9cb4cf9b...`, f53020466c9c97efb4197d15ee0b168849d7c0fef73d8e1ea963c8a76da40168 | 7 | `plan.rs:239:9`: "an archive this writer returned Ok for did not read back: Some("outside this engine's scope: Redirection(PosixSymlink) (member "@")")" |
| `fuzz:write_volumes` | `crash-4c8f407a...`, 40cd20ebb23bd8fb4f076f3414ce18befd68ce8b0c022c64e41196dff6115247 | 9 | the same line of `plan.rs:239:9`, another member name |
| `fuzz:rar5_oracle_stream` | `crash-ddf121b8...`, 17727e4e583f2d2f080f219c2c9998586174504294d5000d7d85994f8492be5f | 33 | `oracle_support.rs:683:27`: "stream: rarkit and the oracle disagree on the verdict": rarkit OK, 1 member of 18 bytes, CRC32 9f928eda; the old engine FAILED, "RAR 5 filter type is unsupported" |
| `fuzz:rar5_oracle_reframe` | `oom-00f9b925...`, 3757af6a169d05e025424166b9f48556044c5991413a5651badd16027138105f | 3,590 | `ERROR: libFuzzer: out-of-memory (used: 2070Mb; limit: 2048Mb)` |
| `fuzz:rar5_solid_chain` | `oom-da39a3ee...`, e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | 0 | `ERROR: libFuzzer: out-of-memory (used: 2050Mb; limit: 2048Mb)` |

Each input is kept as `xxd -p` text, named `<target>--<the fuzzer's own
artifact name>.hex` (`xxd -r -p` gives the bytes back; the sha256 above
is of the bytes). The tree's own rule keeps a fuzzer's `artifacts`
directory out of the repository, and a raw input is not valid text.

What can be said of them without triage:

- The two writer stops read like FUZZ-08OCT-4 of the last campaign (a
  member whose attributes carry the symbolic link type is written Ok and
  then refused by the reader): the same assertion, still met on the
  committed seeds, so neither writer target has yet run an hour.
- The two out-of-memory stops are NOT one input each. The solid chain's
  artifact is the EMPTY input: the process's resident set climbed for 40
  minutes (789 MB at 2.06 million executions, 2,050 MB at 6.05 million)
  and whichever input was running at the limit was written out. The
  driver's own report marks both as a resident set SLOPE that reaches
  the limit inside the run. `fuzz:rar5_member` beside them levels at
  200 MB. Whether the growth is the engine's, the target's or the
  fuzzer's own corpus is not looked into here.
- `round1/`: the three short logs whole, the head and tail of the three
  long ones (the whole log's sha256 is in each excerpt), the driver's
  `state.json`. Home paths and the host name are taken out, and in the
  two oracle targets' logs seven lines that named the vendored
  comparison crate are taken out UNREAD.

## Round two: the three reader targets in 30 minute segments, read at 22:57Z

A small loop round the driver: `rar5_member`,
`rar5_solid_chain`, `rar5_oracle_reframe` on main 3db18e7c5, three side
by side, each segment a fresh process seeded from the corpus before it.
Segments of 18:52Z and 19:22Z ran whole; at 19:59:47Z every process was
stopped by pid, seven seconds after a timed measurement took the
machine; they were taken up again at 21:20Z when it was free. Four whole
segments and a fifth running at this reading:

| target | executions in the whole segments | a second | coverage, first to last | resident set at each segment's end, MB | how the segments ended |
|---|---:|---:|---|---|---|
| `fuzz:rar5_member` | 9,738,269 in 4 | 1,351 | 3,881 to 3,931 | 198, 201, 224, 236 | clean, every one |
| `fuzz:rar5_solid_chain` | 12,919,284 in 4 | 1,793 | 5,134 to 5,569 | 977, 909, 934, 979 | clean, every one: a fresh process each 30 minutes stays under the limit |
| `fuzz:rar5_oracle_reframe` | 3,019,402 in 2, then 2,451,464 in 3 that stopped | 797 | 11,467 to 12,901 | 1,783 and 1,682 at 30 minutes; 1,121, 858, 1,558 where it stopped | two clean, then THREE STOPS on the target's own assertion, after 981 s, 587 s and 1,692 s |

**A NEW stop, `fuzz:rar5_oracle_reframe`, three inputs**, the same line
each time, `oracle_support.rs:683:27`: "reframe: rarkit and the oracle
disagree on the verdict": rarkit FAILED,
`Corrupt(Rar5(IncompleteMember))`; the old engine OK, 1 member of 2
bytes.

| input, sha256 | bytes | the old engine's member CRC32 |
|---|---:|---|
| 428d5a3919c692381b62d92d676c2a0670831bffe66f1d2b4f8079b943092d1d | 84 | e9321ed6 |
| 38261e2b0c0b51dd58f953724d9b72fa2961875fea173b25c6d341ab92bff0d0 | 204 | 90cd7f15 |
| cbd89b34147339ce1db79b1853eac4b20dc6c6c98f33e7c8989ba0aec7f86bde | 100 | bd609a83 |

Not triaged: which engine is right is not looked into. The target also
sits at 1.7 to 1.8 GB after 30 minutes, close to its 2,048 MB limit.

## The two writer targets on the writer's mend, read at 22:57Z

`fuzz:write_members` and `fuzz:write_volumes` on
fix/write-refuses-contradicting-file-type-09oct
3b12cb51dde1dd9715e0ff5bb69683c541f8aad1 exactly (a second tree on the
box, the same driver and limits). 19:39:45Z to the stop for the rig lock
at 19:59:48Z (20 minutes), then 30 minute segments from 21:27Z: 80
minutes whole at this reading and a third segment running.

| target | executions in 80 minutes | a second | coverage at 20, 50, 80 minutes | resident set at each end, MB | how it ended |
|---|---:|---:|---|---|---|
| `fuzz:write_members` | 296,348 | 62 | 16,051; 16,811; 17,166 | 1,004; 1,231; 1,236 | NO panic, no crash, no timeout. libFuzzer wrote two SLOW UNITS: 18 seconds for one input of 30 bytes and one of 15 bytes |
| `fuzz:write_volumes` | 401,516 | 84 | 12,328; 12,878; 14,034 | 927; 1,128; 1,263 | NO panic, no crash, no timeout, no slow unit |

Both targets ran past the 2 and 90 executions where they stopped on
main: the mend lets them be fuzzed. Coverage is still rising on both.

- **The slow units** (`fuzz:write_members`): sha256
  576c8c72037fb3e6a278e932f1e707964fb5139fb68595dca4fa28428d9042c8 (30
  bytes) and
  08c8698178588533af0ffd9965f16c5f25767ff27cf360c2b67d4a09b76d9b15 (15
  bytes, met again in the next segment), "Slowest unit: 18 s" each,
  under the 60 second limit, in a build with AddressSanitizer and debug
  assertions. Its rate fell with them: 103 a second in the first 20
  minutes, 60 in the next 30, 35 in the next.
- **The resident set** of both is 0.9 to 1.0 GB after 20 minutes and 1.1
  to 1.3 GB after 30: one long process would reach the 2,048 MB limit
  inside its 90 minutes, which is why they run in segments.

`round2/inputs/`: the three reframe inputs and the two slow units, as
hex.

## The last stretch: 02:01Z to 05:46Z on 10 October, and the totals

Both campaigns were stopped by pid a second time at 23:39:02Z, eight
seconds after a timed measurement took the machine, and stood idle until
02:01Z (the measurement had ended at 00:18Z; the stop was not seen in
time). Then seven 30 minute segments each, to their own end, with no
stop. A loop fault of this campaign's own, not the driver's or the
engine's, also cost the reader targets 22:58Z to 23:25Z: seeding each
segment from the one before grew every corpus file's name until the
eighth generation could not be written, and the loop now copies a
corpus flat under the sha1 of its bytes first.

No panic inside the engine, no hang, no timeout and no AddressSanitizer
fault on any target in the whole campaign.

| target | tree | fuzzer time counted | executions counted | coverage at the end | resident set at the 30 minute ends, MB | what it met |
|---|---|---:|---:|---:|---|---|
| `fuzz:rar5_member` | main 3db18e7c5 | 7.0 hours | 34,680,310 | 4,014 | 198 to 271 | nothing: clean throughout |
| `fuzz:rar5_solid_chain` | main | 6.2 hours | 40,988,435 | 5,725 | 855 to 1,010 | the memory limit once, in round one's single 41 minute process; clean in every 30 minute segment after |
| `fuzz:rar5_oracle_reframe` | main | 2.9 hours | 9,663,469 | 12,898 to 12,932 | 1,682 and 1,783 where a segment ran whole | the memory limit once; then the verdict disagreement below, ELEVEN times, 24 to 1,692 seconds into a segment |
| `fuzz:rar5_oracle_stream` | main | 3 seconds | 254 | - | - | its verdict disagreement of round one, at execution 254; not run again |
| `fuzz:write_members` | the writer's mend 3b12cb51d | 5.3 hours | 684,407 | 17,777 | 1,004 to 1,642 | no panic; SLOW UNITS of 16 to 18 seconds in every stretch; 21 to 103 executions a second, falling |
| `fuzz:write_volumes` | the writer's mend | 5.3 hours | 1,252,793 | 15,815 | 927 to 1,287 | nothing: clean throughout; 56 to 110 executions a second |

(A stretch a stop cut short is not counted: about 7 minutes of the
reader targets at 19:52Z and 13 at 23:26Z, and 32 minutes of the writer
targets from 23:07Z. On main the two writer targets stop inside 2 and
90 executions, as round one found.)

**`fuzz:rar5_oracle_reframe`, the one finding that could be the
engine's.** The same line every time, `oracle_support.rs:683:27`,
"reframe: rarkit and the oracle disagree on the verdict": rarkit FAILED,
`Corrupt(Rar5(IncompleteMember))`; the old engine OK, 1 member of 2
bytes. Eleven inputs of 80 to 204 bytes: three under `round2/inputs/`
and eight under `round3/inputs/` (sha256 beginning 96438e849b8c,
6b8c91593a3d, 64059ed4e48f, ab8362cfe340, 9797db38642c, d54742b45afc,
71fbc22afec4, 42772a22086e). The target cannot now be fuzzed for more
than a few minutes at a time: it meets one of these again inside each
fresh process. Not triaged.

**`fuzz:write_members`, slow units.** Five distinct inputs of 14 to 60
bytes that take 16 to 18 seconds each in this build (AddressSanitizer,
debug assertions), under the 60 second limit: the two under
`round2/inputs/` and three under `round3/inputs/` (sha256 beginning
a085cd8869fd, 60 bytes; 4602445ccc5d and 7988b22139d7, 14 bytes each).
Its resident set stands at 1.4 to 1.6 GB after 30 minutes, the highest
of the six. Not triaged.

`round3/segments.txt`: the driver's own result line for each of the last
seven segments of both campaigns.

## The eleven reframe inputs replayed at a later main: all clean

The reframe stop was explained while the campaign ran: the inputs are
one class, a RAR 5 block whose bit count ends inside its own tables, which
this engine refuses as an incomplete member where the reference reads
on; the target's support file was taught to count that class (commit
0469aced0). The campaign ran on 3db18e7c5, before it.

On 10 October the `fuzz:rar5_oracle_reframe` target was built at main
38c6bdf0792a74698c8dbb2359077afeb9f7d5b9 exactly (cargo-fuzz default
build, AddressSanitizer, an Apple silicon Mac, untimed) and each of the
eleven inputs was run through it ONCE, no fuzzing:

| input, sha256 begins | bytes | at 38c6bdf07 |
|---|---:|---|
| 428d5a3919c6 | 84 | clean, exit 0 |
| 38261e2b0c0b | 204 | clean, exit 0 |
| cbd89b341473 | 100 | clean, exit 0 |
| 96438e849b8c | 84 | clean, exit 0 |
| 6b8c91593a3d | 98 | clean, exit 0 |
| 64059ed4e48f | 84 | clean, exit 0 |
| ab8362cfe340 | 96 | clean, exit 0 |
| 9797db38642c | 85 | clean, exit 0 |
| d54742b45afc | 80 | clean, exit 0 |
| 71fbc22afec4 | 112 | clean, exit 0 |
| 42772a22086e | 100 | clean, exit 0 |

None stops. The eight inputs found later are that same class, and the
target can be fuzzed again on that main.
