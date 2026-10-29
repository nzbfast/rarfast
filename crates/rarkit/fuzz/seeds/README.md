# Pinned fuzz seeds

`corpus/` and `artifacts/` are gitignored, so an input that cost a campaign
to find is lost the moment the box is cleaned. Anything worth keeping goes
here instead, named for what it is, and `cargo fuzz run <target> seeds/<target>`
replays the lot.

## `f_extract_parallel/rar15-declared-size-*`

The three inputs the 19 Sep 2026 concurrent-member-decode campaign found, on
which the RAR 1.5 decoder ran for 514 seconds and past libFuzzer's 1200 second
timeout. Each is `D140_M5.RAR` with 22 bytes exclusive-ored over it from offset
117, which lands on `DATA.BIN`'s declared UNPACKED SIZE field at offset 132.

They were NOT a decoder defect under the contract of the day, and what they
were instead is measured out in `crates/rarkit/tests/rar15_declared_size.rs`.
The short of it: the member's packed extent
(12,309 bytes) is intact and the decode is a normal one at full speed, but the
corrupted header asks for 671 MB, 45.9 MB or 4.27 GB of output, and spec A
sections 2, 4.11 and 6 put the decoder in contract to produce it.

**That contract changed on 20 Sep 2026 (spec A 6.1), and
this note is corrected rather than deleted.** A step that BEGINS with the
packed input already exhausted now ends the member, so these three declare
what they like and are decoded to about `DATA.BIN`'s true 20,192 bytes in
milliseconds. The shortfall is reported as a member checksum failure and not
as an error. `rar15_declared_size.rs` was INVERTED to pin that, and its
three-seed test no longer needs to be `#[ignore]`d.

A fourth reproducer was noted as existing and was never
written down. It is not recoverable and is not here.

## `f_extract_parallel/par-sink-refusal-ignored-*`

Found 20 Sep 2026 by the first campaign to run this target with the legacy
containers back in, and a DIFFERENT defect from the three above: libFuzzer
timed the first one out after 1229 seconds.

A caller's writer refusing does not stop a decode on a WORKER. On
`par-sink-refusal-ignored-2.6gb`, whose `DATA.BIN` declares 2,634,043,104
bytes, the sequential arm's wall tracks the sink's ceiling exactly (0.2 ms,
3.3 ms, 12 ms, 48.6 ms at ceilings of 0, 1, 4 and 16 MiB) while
`extract_parallel` at width 4 takes about 8 seconds at every one of them,
including a ceiling of ZERO. Not done yet (package F).

The target survives it by gating the wide arm on the sequential one, which
takes all nine seeds here to under 2.2 s in the ASan build.

## `f_extract_any/*`

The SEQUENTIAL extract arm's pinned seeds, added 20 Sep 2026. Campaign 2
found `f_extract_parallel` the best covered target in the roster and
still gaining, while `f_extract_any` - the arm the concurrent one is
compared AGAINST, and so the arm that decides what an answer should be -
had no pinned seeds at all.

A seed is this target's own eleven byte prefix and nothing else: chunk,
vector, memory budget, then eight bytes of refusal mask, and a body that
is exclusive-ored over the chosen vector from offset `seed * 13 % len`
when the vector byte is EVEN. So a name says what a seed does:

    <vector>-s<seed>-chop<n>-mem<limit>-<refusal>-<damage>

- **`<vector>`** is the spec F archive `pick` lands on: `f01` stored,
  `f02` directory entries, `f03` compressed, `f04` solid, `f05` BLAKE2sp,
  `f06` comment, `f07` password, `f09` recovery record, `f10` quick open,
  `d140` RAR 1.5, `d155` RAR 2.0, `d250` RAR 2.50 and `r420` RAR 4.20
  `-m5`, whose stream carries spec I's PPM blocks and spec J's filters
  beside the LZ ones. `d155` and `d250` are the RAR 2.0 window shapes
  that `fixtures/rar20-dictionary` is about, reached here by damage
  rather than by a fixture file, because this target's archives are
  compiled in and it reads none.
- **`chop<n>`** is the short read length the `Choppy` source answers:
  one byte at a time, seven, and 255.
- **`mem<limit>`** is the working limit, 1 MiB, 32 MiB and 512 MiB. The
  first two are below the engine's 128 MiB per worker rule, so they are
  also the policies under which a member decodes one at a time.
- **`<refusal>`** is the sink's mask: `keep` refuses nothing, `refuse0`
  the first member, `refuse1` the SECOND alone (a refusal with a member
  closed either side of it), `refuse01` the first two, `refuseall` every
  member. This is the sequential half of the shape that found the
  20 Sep 2026 defect in the parallel arm, where a caller's refusal did
  not reach a worker's decode; the sequential answer is what that arm is
  judged against, so it is pinned here.
- **`<damage>`** is what the body exclusive-ors in: `clean` nothing (the
  only way this target sees an undamaged archive, and it needs an ODD
  vector byte), `ff4` and `ff22` runs of set bits over a header field,
  `top8` the high bit of eight bytes, `walk16` sixteen increasing bytes.

9,360 candidates from that grid through `-merge=1` kept the 82 here, so
every seed buys a basic block no other one does: `cov: 3667 ft: 7254` on
the committed set. The RAR 1.5 DECLARED SIZE family, from
`fixtures/rar15-packed-bound/`, belongs to the packed input tests
and is deliberately not
duplicated here.

## `rar3_lz_literal_burst/*`

The seeds of the target added 20 Sep 2026 for SPEC-H1's TABLE
BOUNDARIES. A seed is five to nine bytes: the first sizes the stream
(the floor on table reads), and the rest is cycled over its blocks, four
bytes each, as `<alphabet and keep bit> <run high> <run low> <end>`. The
names say which arm a seed names:

- **`f2`, `f3`, `f7`, `f17`**: the floor on table reads the first byte
  asks for, two to seventeen.
- **`a0` to `a8`**: the main alphabet's size, `1 << n` literal values, so
  a literal's code is 1 to 9 bits wide and the run crosses the byte
  boundary at a different rate. **`a0k` to `a8k`** are the same with the
  KEEP BIT set, where the next block's 404 code lengths are read as
  deltas modulo 16 on what the last block left (SPEC-H1 3.3) - the arm
  that cannot be reached at all by a stream with one table read.
- **`run4`, `run256`, `run2048`, `run8192`**: the literals a block holds
  before its boundary. The stream's LAST block always takes whatever is
  left of two laps of the 64 KiB dictionary, so even `run4` ends in a
  burst of tens of thousands.
- **`endnew`, `endkeep`, `endsame`**: the end of block field of SPEC-H1
  3.7 - a new member at a header, a new member resuming INSIDE the block
  under these tables, and a new block in the same member.
- **`-long`**: a nine byte seed, so the blocks of one stream differ from
  each other rather than repeating one four byte step.

2,304 candidates through `-merge=1` kept the 111 here: `cov: 731
ft: 2260`, at about 6.6 ms an execution.
## `f_extract_any/rar15-packed-bound-*` and `f_extract_parallel/rar15-packed-bound-*`

The two inputs the second whole-roster campaign found on 20 Sep 2026, copied
into `fixtures/rar15-packed-bound/` so that the tests
can use them without another repository. They are the
same bytes in both places, which `tests/rar15_packed_bound.rs` asserts.

Each drives `D140_M5.RAR`'s `DATA.BIN` to a declared size of about 4 GiB over
a few kilobytes of packed data. Before spec A 6.1's bound the minimised one
took 13.045 s through the sequential `Archive::extract` and delivered
4,287,955,464 bytes (aarch64 release, 18-core laptop); the campaign measured
121.9 s and 4.32 GB peak RSS through `f_extract_any`, whose sink collects each
member into a `Vec`. After the bound it is 106 microseconds and 520 bytes.

They are seeds for BOTH targets because the bound had to be carried to the
concurrent driver as well as the sequential one.

## `rar15_decode/empty-chunk-target256`

The four bytes `00 01 00 0a`, which is a target of 256 and one chunk whose
packed bytes are EMPTY. Found in passing on 21 Sep 2026 by the par-src4k
work's campaign, on which `rar15_decode` died at 0 s after 26 executions,
`crates/rarkit/src/internals_a.rs`'s "Ok must deliver exactly the target".

It was never a decode defect. The decoder is right and the TARGET was
stale: the specification (spec A 4.11 and 6.1) ends a member at the step that
BEGINS with the packed input already exhausted, and an empty chunk is the
limiting case, so the member produces nothing though it declared 256. That
is `Ok`, and the shortfall is the caller's member CHECKSUM to report
(`MemberOutcome::checksum_ok == Some(false)`, SPEC-F 2.5). The target now
asserts the bound spec A section 6 does promise, that no member delivers
MORE than its target, and the case is pinned as a unit test at
`rar1x::tests::spec_a_4_11_the_member_ends_short_at_the_first_step_with_no_packed_bit_left`.

It is kept here because the assertion it tripped was the fuzz target's own
expectation rather than the decoder's behaviour, and that is the class of
staleness a later contract change can reintroduce.

## `f_extract_parallel/*-outputs2`

Every seed above, again, with bit 2 of its third byte set, which since 22
Sep 2026 sets the outputs bound to twice the breadth for that run
(`RARKIT_OUTPUTS_OVER_BREADTH`, the default; a clear bit
sets it to one, the pool that held a worker until its member closed):
a worker whose answer has arrived is freed while earlier members wait to
close, and the target's own check, that the answer is the sequential
walk's member for member, is what must still hold. The width reads only
the low two bits of that byte, so each copy runs its original at the same
width with the knob on. Written in the small compressed members work
(22 Sep 2026).

## `f_extract_batches/*`

Starting points, not findings (26 Sep 2026). Each is the four control bytes
alone and no damage: which input, which batch shape and member team, which
width, and which memory policy, per the target's own header. Three per
input: the shipped pair at width 4, one member at a time at width 8 on a
team of one, and batches of up to 64 at width 8 under a 1 GiB policy.
