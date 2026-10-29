# Fuzz campaign, 20 September 2026: findings

The first whole-roster fuzz campaign over both fuzz trees. **No crash, no
timeout and no out-of-memory, in 1,735,681,117 executions across all 38
targets.** The only artifacts kept are two SLOW UNITS from
`fuzz:write_members`, in `write_members/`, and they are the target's own
construction cost rather than an engine fault. The full write-up is in
the project's research notes (the fuzz campaign of 20 Sep 2026).

Neither fuzz tree had a committed artifacts or corpus-regression location
before this, so this directory is the new one.

## What ran

| | main campaign | top-up |
|---|---|---|
| rarkit | the tip when it started | the tip when it finished |
| box | an M3 Mac, 32 cores, aarch64 macOS | same |
| mode | UNTIMED, 16 build jobs | same |
| width | 16 concurrent fuzzers, no libFuzzer `-jobs`/`-workers` | same |
| wall | 03:57:40Z to 08:14:01Z, 4 h 16 min | 08:18:07Z to 08:49:34Z, 31 min |
| fuzzer time | 187,122 slot-seconds, 52.0 fuzzer-hours | 27,028 slot-seconds |
| targets | 38 of 38, all built, none skipped | 15 of 39, over the code that moved |
| executions | **1,735,681,117** | 173,268,558 |
| findings | 0 crashes, 0 timeouts, 0 OOMs | 2 slow units, below |

`main` moved about fifty commits during the campaign, including a new
`read/concurrent.rs`, a substantially rewritten `read/extract.rs`, reworked
`lz20`, and a 39th target `crates/rarkit/fuzz:f_extract_parallel` the main
campaign never saw. The top-up covers exactly that changed code. It came
back clean, and `f_extract_parallel` reached cov 6282 in 1801 s, the
highest first-run coverage of any target in the roster.

## The two slow units

`write_members/slow-unit-{a,b}-original` as libFuzzer wrote them, and
`-minimised` after `cargo fuzz tmin -- -timeout=5`. Nine bytes each:

    a   0c 9d 00 09 60 00 25 b4 00
    b   0c 9d 00 09 00 a0 ff 0b b4

Both reproduce at the campaign's end revision on an M3 Mac, timed with `/usr/bin/time -l`:

| build | a | b |
|---|---|---|
| cargo-fuzz default, release + AddressSanitizer | 11.8 s, 586 MB | 11.8 s, 578 MB |
| same target, `-s none`, release, no sanitizer | 3.0 s, 129 MB | 2.9 s, 129 MB |

libFuzzer first flagged them at 18 s and 20 s, which is the same work under
the campaign's 16-way load. They did not trip `-timeout=60`; at
`-timeout=5` they are ordinary timeouts, which is how `tmin` minimised them.

**This is the target's own cost, not an engine fault, and the engine was
not opened to decide it.** `plan.rs` line 156 repeats the first member's
data to about 400 KiB, and `write_members.rs` encodes the plan three times
whenever it is solid with level above 0: a depth-1 control, a seed-chosen
depth, then `plan.run()`. Nine bytes therefore buy roughly 1.2 MiB of solid
compressed encoding per execution.

OPEN, for spec G section 6.4: decide whether that depth-1
control encode has to run on every execution or only on a sampled
fraction. `write_members` is the slowest structural target in the roster
at about 120 exec/s and its length limit never rose above 29 bytes in
600 s, so it is barely exploring, and the triple encode is the reason.

**Both of the "two more things" below were worked through on 20 Sep 2026
in the seeds-and-slow-units work; its run, its
findings and its figures are in `seeds-and-slow-units.md` beside this
file, and `fuzz:edit_roundtrip` now reaches cov 3,991 in the same 600
seconds that reached 104 here.**

## Two more things a later campaign should know

1. **`fuzz:edit_roundtrip` is blind.** Its last new basic block came at
   execution **779** of 20,704,032. It is the only target in either tree
   that expects a real archive to arrive from a SEED CORPUS, and neither
   tree commits one, so `Archive::open` refuses nearly every input and the
   body never runs. Seeded from `fixtures/legacy/archives`, 60 seconds
   reach cov 4362 where 601 unseeded seconds reach cov 104. NOT DONE YET
   (spec G section 6.4).

2. **Ten minutes already saturates most of the roster's basic blocks.**
   Nine of the 19 targets given hours more gained not one new block over
   their 600 s sweep. The six that did are
   `crates/rarkit/fuzz:f_extract_any` (+516),
   `crates/rarkit/fuzz:rar3_lz_member` (+139), `fuzz:rar5_member` (+110),
   `fuzz:rar5_window_edge` (+97), `crates/rarkit/fuzz:f_open_any` (+96)
   and `fuzz:rar5_solid_chain` (+87). Spend the budget there and give the
   rest the floor.

The 149 MB / 36,474 file corpus the campaign grew was NOT kept: it lived in
the box's scratch and went with it. Keeping a minimised corpus is worth
doing in the next campaign.

The campaign is run by one driver script, so the next campaign is one
command rather than a re-derivation.
