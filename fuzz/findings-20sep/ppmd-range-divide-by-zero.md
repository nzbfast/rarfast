# Two PPMd faults that panicked, 20 September 2026

The fix is written from `specs/SPEC-I-rarkit-ppmd.md` alone.

A damaged RAR 3.93 PPMd archive PANICKED the engine with "attempt to
divide by zero" at `crates/rarkit/src/ppmd/range.rs:60`. A library must
answer untrusted input with an error: one bad download would have taken a
caller's process down.

**There were TWO defects, and they are the same defect.** The reported one
is the range decoder's; the second is the model's, and the fuzz target
widened to confirm the first fix found it in three seconds. Both are:

> a FAULT leaves state that a later operation assumes cannot exist, and
> the caller carries on into it.

Spec F reports a failed member and opens the next one. That is the
premise both defects were written without.

This file is the whole account - both defects, the sweep for their class,
what the reference does on the same bytes, what fuzzing did and did not
see, and what is left open.

## The one byte

    python3 - <<'PY'
    b = bytearray(open('fixtures/legacy/archives/r393_md.rar', 'rb').read())
    b[29567] ^= 0xA5
    open('/tmp/r393_md_damaged.rar', 'wb').write(bytes(b))
    PY
    rarfast t /tmp/r393_md_damaged.rar

Offset 29,567 lies inside the packed data of the archive's second member,
`BIG.TXT` (extent 21,506 to 35,884; 90,000 bytes declared, method `-m5`),
so this is damage to compressed data and not to a header. The archive is
NOT solid: every member of it carries its own flags word `0x8000`.

## What actually happened, traced rather than guessed

Spec I 3.6's binary decision `bit(p)` is `range = range >> 14`, then
`v = (code - low) / range`, then `RangeOutOfBounds` when `v >= 16,384`.
The old code did the shift IN PLACE, on `self.range`. On this file the
decision read `v = 16,396` with `range` shifted down to 932 and returned
the fault - leaving the decoder holding 932.

Normalisation is what keeps that division safe: it only ever returns with
`range >= BOT` (2^15), so the shift leaves at least 2. The degenerate
range was therefore created by the FAULT PATH ITSELF and nowhere else,
and the next binary decision on that decoder computed `932 >> 14 = 0` and
divided by it. That next decision was a later member's: the driver
reports a member's fault and goes on to the next one.

So the defect is not "a check is missing at line 60". It is "a fault
leaves the decoder in a state no successful operation can produce, and
something reads it". Both halves are fixed:

- `bit` and `count` narrow into a LOCAL and assign to `self` only once
  the decision is known to be sound, so a fault leaves the decoder
  exactly as it was;
- `bit` answers `range >> 14 == 0` with `RangeOutOfBounds` before
  anything divides, the way `count` already answered `range / total == 0`.

The guard sits on a branch a stream that has not already faulted never
takes, and it is not in the shift-and-divide's dependency chain.

## Defect 2: a successor read as a context, in a model that had faulted

`crates/rarkit/fuzz/seeds/ppm_member/re-entry-after-fault-successor`,
1,387 bytes, kept because it cost a campaign to find:

    range start index 2,407,334,982 out of range for slice of length
    3,145,744, at Arena::unit_pair, by way of Model::successors

Spec I 3.10's invariants hold because the model is driven ONLY by the
sequence of decoded symbols and every rule is total over them. A fault
breaks that premise from underneath: it can land half way through
3.9.2's update - between a context's `count` and the state that count
promises, say - and what it leaves is a model no symbol sequence could
have built. Decode from it again and 3.9.3 step 2 reads a successor as a
context position.

The input does exactly that: `RangeOutOfBounds` in one member, and the
next member's first decode walks the broken link.

A model that has faulted is therefore not decoded from again: the fault
is kept and re-raised, and a START block header clears it, because 3.5
rebuilds the model wholesale and that is what a non solid member sends.
Only this package's own faults poison - `Truncated` and the memory limit
say nothing about the model's state. Beside it, and because the panic
earned it, a successor read as a context is now tested with spec I
3.9.1's own test (above the text region) and against the buffer, in
3.9.1 and 3.9.3 alike; a link that is neither a text position nor a
context is `Inconsistent`.

Spec I does not rule on whether a faulted decoder may be re-entered. This
is the conservative reading, not an invented behaviour, and the question
is in "Left open" below.

## The sweep: every divide, shift, index and overflow in `ppmd/`

Spec I 3.10's invariant is the backbone of the reading below: the model is
driven ONLY by the sequence of decoded symbols, and every rule is total
over all of them, so a hostile stream cannot put the model in a state that
ordinary input could not. What the stream does control directly is the
block header (3.2) and the counts the range decoder returns (3.6).

| site | what could go wrong | verdict |
|---|---|---|
| `range.rs` `bit`: `range >> 14` then `/` | THE DEFECT | fixed: guarded, and the state survives a fault |
| `range.rs` `count`: `range / total`, `(code - low) / range` | divide by zero | guarded already; now also state-preserving |
| `range.rs` `take`: `range * size` | wrap, or a zero range | `size >= 1` and `lo + size <= total` at all four call sites, each picked from a count already checked against a running sum; so no wrap and no zero. A zero would make `normalise` read to the end of the member and raise `Truncated`: slow, never a panic, never a byte |
| `range.rs` `normalise`: `range <<= 8` | wrap to zero | `range >= 2^24` always satisfies the stop test, so the value shifted is below 2^24 |
| `range.rs` `bit`: `p * range`, `(16,384 - p) * range` | wrap, or a zero range | `range < 2^18` after the shift and both multipliers are at most 16,384; `p` is 1 to 16,383 by induction on the table (seeded at 16,384 - `init_bin[k]`/(i+2) >= 3,303, raised by `p + 128 - floor((p + 32) / 128)` which sticks below 16,384, lowered by `p - floor((p + 32) / 128)` which sticks at 95) |
| `model.rs` `path_binary`: `bin[(freq - 1) * 64 + column]` | index | `freq` checked 1 to 128, `column` at most 63 from checked parts (`parent_count` checked 1 to 256) |
| `model.rs` `path_binary`: `ESC_AFTER_BINARY[updated >> 10]` | index | 16 entries, and `updated <= 16,383` by the same induction |
| `model.rs` `escape`: `esc[ESC_CLASS[open - 1] * 16 + j]` | index | `open` checked 1 to 256, `j` at most 15, `ESC_CLASS` at most 24: 399 of 400 |
| `model.rs` `escape`: `sum >> shift`, `3 << shift` | shift overflow | `shift` starts 3 and rises only while below 7; `3 << shift` is read before the rise, so at most `3 << 6` in a `u8` |
| `model.rs` `update`: `grow(array, k / 2)` -> `CLASS_OF[units + 1]` | index 129 of 129 | the `k >= 256` check above it bounds `k / 2` at 127 |
| `model.rs` `update`: `set_total(c, t + added)` | `u16` truncation | checked against 65,535 explicitly |
| `model.rs` `update`, `path_multi`: `total + 4`, `freq + 4`, `t + 2` | `u16`/`u8` truncation | each increment is matched by a frequency increment, and rescale (3.8) halves at 124, so the sum of a context's 256 frequencies is bounded well below 65,536 |
| `model.rs` `successors`: `(2cf + 3s0 - 1) / (2s0)` | divide by zero | `s0 > 0` checked; the result is then checked 1 to 128 |
| `model.rs` `rescale`: `f -= f / 2` loop | non-termination | the loop ends on `escapes`, which halves every pass and is checked non-negative |
| `model.rs` `rescale`: `CLASS_OF[was_units]`, `shrink` | index | `count` checked 2 to 256, so units are at most 128 |
| `model.rs` `restart`: `16,384 - INIT_BIN[k] / (i + 2)` | divide by zero | constant divisor of at least 2 |
| `arena.rs` every `mem[p]`, `mem[p..p + n]` | slice bounds | **this row was WRONG when first written, and defect 2 is what it missed.** Positions come from this allocator or from links this model wrote, which holds only while 3.10's premise does - and a fault breaks it. With re-entry after a fault refused, and with the two places that read a successor AS a context checking it, the argument holds again: `reserve` gives `BASE + size + UNIT` bytes and the sentinel sits at `BASE + size` |
| `arena.rs` `split`, `glue` step 4: `j -= 1` | underflow | reached only when `UNITS_OF[j] != rest`, which cannot hold at `j == 0` (`UNITS_OF[0] == 1` and `rest >= 1`) |
| `arena.rs` `rare`: `glue_countdown -= 1` | underflow | `glue` sets it to 255, and the branch above runs `glue` when it is 0 |
| `mod.rs` `begin_block`: `(memory + 1) << 20`, `16 + 3 * (code - 16)` | overflow | 8-bit and 5-bit inputs: at most 256 MiB and order 64 |
| `mod.rs` `step`: `(d2 << 16 \| d1 << 8 \| d0) + 2`, `len + 32` | overflow | `u32` from `u8` symbols |
| `mod.rs` `filter_record`: `body` | unbounded growth | length capped at 65,535 by construction (3.3) |

There is no `unwrap` or `expect` on stream-derived data anywhere in the
package: the three in `arena.rs` are `try_into` on slices of a constant
length, which the compiler's own bound already proves.

### Where a debug build and a release build differ

Rust's slice bounds checks are in BOTH builds, so every index above
panics in both if it is ever wrong; none of them can be reached with a
wrapped value that decodes garbage instead. Arithmetic overflow is the
half that differs - `+`, `-` and `*` panic in a debug build and wrap in a
release build - and the range decoder's own `wrapping_*` operations are
the spec's "mod 2^32" ones, deliberate in both. The sites that could
differ are the `u16` and `u8` truncations in the table above; each is
either checked explicitly or bounded by the rescale limit, and a
truncation there would decode garbage silently rather than panic, which
is why they are argued and not merely asserted.

Empirically, in a DEBUG build (overflow checks on):
`a_mutation_sweep_of_the_legacy_fixtures_never_panics` runs 3,888 mutants
over all 81 legacy archives and ends clean; against the unfixed decoder
the same sweep dies on the divide by zero. `make ci`'s own mutation
differential (spec I section 6 test 3) adds about 1,100 more over the
vectors.

## What reference `unrar` does with the same bytes

`unrar` 7.23 on `/tmp/r393_md_damaged.rar`:

    unrar x -y -p- /tmp/r393_md_damaged.rar ./        exit 3
    BIG.TXT              - checksum error
    Total errors: 1

Every other member extracted, byte for byte what the undamaged archive
holds, including a zero-byte `EMPTY.DAT`. rarkit after the fix:

    rarfast x -y /tmp/r393_md_damaged.rar ./          exit 3
    BIG.TXT              - checksum error
    EMPTY.DAT            - checksum error
    malformed archive: Ppmd(RangeOutOfBounds) (member "BIG.TXT")
    Total errors: 2

Same exit code, same verdict on the archive, and every member that both
engines produced is byte-identical (`diff -r`: only `EMPTY.DAT` differs,
and only by being absent). The DIFFERENCE worth recording is the extra
failed member, and it is NOT this package's: damage inside the first
member (`AUDIO.RAW`, byte 15,000) is reported by both engines as exactly
one error and does not touch the member after it, so the spill is
specific to the zero-byte member that follows a failed one. Not done yet,
and it belongs to spec F or spec H; see "Left open" below.

## Fuzzing

**Why the 20 Sep whole-roster campaign missed both of these.** That
campaign ran **1,735,681,117 executions across all 38 targets** and came
back clean (`README.md` beside this file), `ppm_block` and `ppm_member`
among them. Neither could reach either defect, for one reason: both
defects need a SECOND decode after a fault, and `fuzz_ppm_member` drove
ONE member and stopped at the first error. The seam, not the fuzzer, was
the limit. `ppm_block` has the same shape and stops at its first error
too. `f_extract_any` mutates whole archives through `extract`, which is
the right shape, but it would have to build a damaged PPM member that
faults and is followed by another member, from a corpus that is not PPM
heavy; a billion and a half executions did not.

`ppm_member` now drives a SOLID RUN of three members - a START header,
then two CONTINUE headers over cuts of the same bytes - and carries on
past a member's fault. It found defect 2 in **three seconds**.

**This campaign.** An M3 Mac, 32 cores, aarch64 macOS, UNTIMED,
4 build jobs, 2 slots, the fuzz campaign driver, 1,800
seconds per target. Seeded as spec I section 6 asks:
one corpus file per PPM member of `specs/vectors-I/archives/*.rar`, the
RAR 3.93 and RAR 4.20 legacy fixtures and the one-byte-damaged
derivative (73 inputs), plus the pinned crash input for `ppm_member`.

| target | wall | executions | exec/s | cov | features | new units | peak RSS | findings |
|---|---|---|---|---|---|---|---|---|
| `ppm_block` | 1,801 s | 516,761 | 286 | 982 | 5,656 | 1,762 | 156 MB | none |
| `ppm_member` | 1,801 s | 1,159,462 | 643 | 979 | 5,651 | 2,077 | 145 MB | none |

An earlier unseeded pass of the same length, also with both fixes in, was
also clean: 1,710,966 and 1,180,625 executions. So **about 4.6 million
executions after the fixes, no crash, no timeout, no out of memory.**

The run BEFORE the second fix is the one that matters most: `ppm_member`
died at 3 s, rc=77, with the panic above, and its artifact is the pinned
seed.

**A campaign lost, and the bug that ate it.** The first attempt reported
both targets as `SILENT: coverage never left its first input` in 86
seconds. Neither target was silent: a fuzzer runs from its TREE's
directory, the fuzz campaign driver passed `--out` through unchanged, and
a RELATIVE `--out` therefore handed `crates/rarkit/fuzz`'s targets a
corpus path that does not resolve there. libFuzzer answered "the required
directory does not exist" and exited 1, which the report renders exactly
like a dead target. `--out` is absolutised now, with the reason beside
it. Anybody reading a SILENT row in an older report should check this
first.

## Left open

1. **A zero-byte member after a failed member is reported failed** (spec
   F or spec H). Reproduction above. Reference `unrar` reports one error
   where rarkit reports two, and the difference is a member that declares
   no bytes at all. Nothing in spec I decides it: the package's own
   contract ends at `finish_member`.
2. **Whether a faulted decoder may be re-entered at all** (an open
   question). Spec I 3.6 says what `bit` and `count` do with a
   degenerate range; it does not say whether a caller may keep decoding
   through a decoder that has raised `RangeOutOfBounds`. The fix
   takes the conservative reading - the decoder survives a fault
   unchanged and faults again rather than panicking - and did not invent
   a poisoned state the specification does not name. If the specification wants
   the decoder to refuse outright after its first fault, that is a
   cheap flag and a spec sentence.
