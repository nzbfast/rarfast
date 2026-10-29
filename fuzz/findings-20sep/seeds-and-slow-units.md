# Seeds, a new H1 target, and the slow units: 20 September 2026

Campaign 2's open
list, worked through. Every figure here was taken on **an M3 Mac** (32
cores, aarch64 macOS), UNTIMED, with 8 build jobs
and the fuzz campaign driver, at most four fuzzers at a time, in two
runs between 17:30 and 18:15 local. Nothing here is a bench figure
and nothing here travels to another box.

The cargo-fuzz default build is used throughout: release WITH
AddressSanitizer. Per-execution costs below are that build's, and the
20 Sep write-up of `write_members` measured the same work about four
times cheaper with `-s none`.

## 1. The finding: a rename on an archive that stores one name twice

`fuzz:edit_roundtrip`, 84 seconds into its first seeded sweep, at
execution 814,282 of 9,810 a second: the rename arm's assertion failed
on a mutated RAR 4 archive whose two members are BOTH stored as
`hello.txt`.

The engine was right and the TARGET was wrong. `edit::rename` and
`edit::remove` take a NAME, and the rewrite acts on the first member
carrying it (`edit/rewrite.rs`, `names.iter().position`); the target
built its expectation from the argument's INDEX, which is the same
member only while names are unique. Both arms now expect the first
match.

What the API does not state is WHICH of two same-named members a rename
or a removal should take, or whether the call should be refused
instead. SPEC-G 3.15 covers the comment and the lock alone; SPEC-API 7.5
says nothing about duplicates. **An open question for the specification.**
Two tests in `crates/rarkit/tests/edit_members.rs` pin the part that
holds however it is decided - exactly one member touched, order kept,
every other member's bytes unchanged - and the reproducer is
`fuzz/seeds/edit_roundtrip/rename-picks-the-first-of-two-same-names`.

That is the only artifact either run produced. No timeout, no
out-of-memory, no other crash.

## 2. Coverage, before and after seeding

| target | unseeded, 600 s | seeded, 600 s | seeds alone, replayed |
|---|---:|---:|---:|
| `fuzz:edit_roundtrip` | **104** (17,639,676 execs) | **3,991** (5,806,723 execs) | 2,628 |
| `crates/rarkit/fuzz:f_extract_any` | **5,331** (336,710 execs) | **5,266** (281,769 execs) | 3,667 |
| `crates/rarkit/fuzz:rar3_lz_literal_burst` | n/a, new | **751** (58,869 execs) | 731 |
| `fuzz:write_volumes` | **5,710** (17,628 execs), before the floor | **6,094** (54,931 execs), after it | 5,686 |

`write_volumes`'s two columns are before and after the volume budget
floor of section 3, not seeded and unseeded: its seeds are the corpus
that second run grew, and both runs started cold.

Three things in that table are worth saying out loud.

**`edit_roundtrip` was blind and is not any more.** 17.6 million
unseeded executions reach 104 basic blocks - twice over, once with the
target as it was (15,842,408 executions) and once with the rename
expectation fixed (17,639,676), the same 104 either way - which is what campaign 2
measured and what the committed corpus was written for. Seeded, the
same 600 seconds reach 3,991 - thirty eight times the coverage for a
third of the executions, because an execution that gets past
`Archive::open` is worth having and one that does not is not. The seeds
alone replay to 2,628, so two thirds of that is the corpus and a third
is what the fuzzer then built on it.

**The `write_volumes` figure is the budget floor paying for itself.**
Before it: 17,628 executions, cov 5,710. After it: 54,931 executions,
cov 6,094. Three times the executions and more coverage, from a change
that only stops the target asking for hundreds of thousands of volume
files (section 3).

**Seeding did NOT help `f_extract_any`, and that is a real result.**
5,266 seeded against 5,331 unseeded, a 1.2 per cent spread the wrong
way, and the seeded arm ran 16 per cent fewer executions because its
corpus is larger. The reason is structural: this target does not take an
archive from its input at all - it picks one of thirteen compiled-in
vectors and exclusive-ors the input over it - so mutation reaches the
whole vector space on its own within seconds. The value of the pinned
seeds here is as a REGRESSION corpus that can be replayed, which is what
was asked for, and not as a coverage boost. One pair of runs cannot
separate a 1.2 per cent difference from run-to-run variation, and no
claim is made that it can.

**The new H1 target is close to saturated by its own seeds.** 731 from
111 hand-built seeds, 751 after 600 seconds of fuzzing. Merging that
whole sweep's corpus back over the seeds adds 243 files for TWENTY more
edges, so those files are not committed: the grid that names every
alphabet width, keep bit, run length and end of block kind is doing the
work, and the fuzzer is not finding a shape the grid missed.

## 3. `write_volumes`'s five slow units

Campaign 2 reported five for this target and committed none of them;
their write-up was not available here. They were
re-derived instead: a 600 s sweep (17,628 executions, 29 exec/s, no
crash, `slowest_unit_time_sec: 0` on a box carrying four fuzzers rather
than sixteen), then the 379 input corpus it grew replayed one input per
process. Twelve inputs of eight to fourteen bytes cost 2.5 to 3.4
seconds against a 65 ms median, which under a sixteen-way load is the 15
to 20 seconds that flagged them.

They are two shapes, and NEITHER is an engine fault.

**a. 409,600 volume files from ten bytes.** `bulk` repeats the first
member to about 400 KiB (`plan.rs`), and this target's own fallback
budget `data[0] * 64 + 1` is ONE BYTE whenever `data[0]` is zero - which
is RAR 5, stored, non solid, the commonest shape in the corpus. Measured
across budgets, one input per process:

| payload budget | volumes | wall |
|---|---:|---:|
| 1 B | 409,600 | 3.571 s |
| 17 B | 24,094 | 0.247 s |
| 49 B | 8,359 | 0.129 s |
| 113 B | 3,624 | 0.094 s |
| 241 B | 1,699 | 0.079 s |
| 4,081 B | 100 | 0.069 s |

Linear, at about 8.6 microseconds a volume. An expected large write:
every one of those volumes is legal and spec G section 4 admits a budget
that fits one payload byte. FIXED AT THE SITE, in the target: both
budgets are floored so a plan cannot ask for more than 4,096 volumes,
and a plan of small members keeps its one byte budget. The same 379
inputs then run at a 1.695 s worst against 3.571.

**b. The depth-1 control encode.** Solid, level 3, `bulk`, small
dictionary: 1.2 to 1.7 s. That is the same class as the two slow units
`fuzz:write_members` produced on 20 Sep 2026, and the same open
question: whether that control has to run on every execution or on a
sampled fraction. Left alone deliberately - removing it removes the
property the target exists to check, and sampling it is a decision for
spec G section 6.4.

## 4. What is left open after this

- **A decision on duplicate names** for `edit::rename` and `edit::remove`
  (section 1). Until it comes the tests and the fuzz
  target assert only what holds either way.
- **The depth-1 control encode's cost** in `write_members` and
  `write_volumes` (section 3b): a question for spec G section 6.4.
- **`fuzz:rar5_window_edge`'s thin lap**, still 1.03x at the seeds that
  occur, unchanged here and recorded in
  the fuzz target inventory.
- **A nightly-only deprecation warning** in `crates/rarkit/src/memory.rs`
  line 187: `Atomic::<u64>::fetch_update` is renamed `try_update` on
  nightly. It is not a gate failure - the gates build the pinned 1.98.0 -
  and it was seen only because a fuzz build uses nightly.
- **An x86-64 reading of none of this**, because none of it is a timing
  gate: the costs above are aarch64 and are quoted only to tell a
  target's own construction apart from an engine cost.
