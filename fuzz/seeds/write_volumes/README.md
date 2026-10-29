# Pinned seeds for `fuzz:write_volumes`

The coverage-minimised corpus of the 600 s sweep of 20 Sep 2026 on
an M3 Mac: **285 inputs, 2,782 bytes in all, the largest of them 14
bytes**, replaying to `cov: 5693` of the 5,710 that sweep reached, and to
`cov: 5686` under the budget floor that landed with them. The
corpus that grew them was 1.5 MB and went with the box's scratch, which
is what happened to every corpus of the two campaigns before this one:
`corpus/` is gitignored and a campaign that keeps nothing starts colder
than the last one finished.

This target is the roster's slowest at 29 executions a second, so what
it starts from matters more here than anywhere: 600 seconds buys it
17,628 executions against `edit_roundtrip`'s 15.8 million.

## The names

Each seed is named for the PLAN its bytes decode to (`plan.rs`), so a
shape that vanishes from the corpus is visible as a missing name rather
than as a coverage number:

- **`rar5`, `r4v29`, `r4v30`, `r4v40`** - the container and, for RAR 4,
  the version the writer targets.
- **`l0` to `l3`** - stored, or the compression level. Levels 4 and 5
  are not reachable from this target's shape byte.
- **`vol`** - the plan named a volume budget itself; **`volfallback`** -
  it did not and the target supplied one.
- **`filebudget`** - the budget counts the whole volume FILE rather than
  its payload (the two are mutually exclusive).
- **`solid`**, **`bulk`** (the first member repeated to about 400 KiB),
  **`smalldict`** (a 256 KiB window, which is what takes the streamed
  walk), **`seek`** (`finish_seek` rather than `finish_into`),
  **`cmt`**, **`lock`**.

91 distinct shapes are here. The commonest are `r4v40-l3-vol-solid` and
`r4v40-l3-vol-filebudget`, which is where the depth-1 control encode of
spec G 3.9 is driven.

## Two of these were slow units

`r4v40-l3-vol-solid-*-bulk` and `rar5-l0-volfallback-*-bulk` are the two
shapes behind the five slow units campaign 2 reported for this target.
Neither is an engine fault: the first is the depth-1 control encode of a
400 KiB solid member, and the second was 409,600 one-byte volumes, which
this target no longer asks for - `MOST_VOLUMES` in `write_volumes.rs`
floors the budget and says what was measured.
