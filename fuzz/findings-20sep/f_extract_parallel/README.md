# `f_extract_parallel`: two slow units, 25 bytes each (20 Sep 2026)

Found by a 600 s campaign run during the breadth-times-width work over its own branch. **No
crash, no timeout, no out-of-memory in 80,609 runs.** libFuzzer reported
two slow units, 16 s and 21 s as it measured them, and they are kept here
as it wrote them.

The two differ in ONE BYTE (offset 0x14: `0x00` against `0xb0`), so they
are one finding rather than two.

## What is left open

**The underlying cost is NOT from this change and is left to the fuzz
roster.** Both units are pathological on the PRE-CHANGE division too.
Timed on one laptop under load, so the walls are indicative and the CPU
figures are the solid ones:

| unit | floored share (the code before this change) | after this change's fix |
|---|---|---|
| `c29d...` | 10.3 s wall, **8.9 s CPU** | 16.2 s wall, 10.0 s CPU |
| `e2cf...` | 12.4 s wall, **9.4 s CPU** | 10.5 s wall, 9.6 s CPU |

**Nine CPU seconds for twenty five bytes** is the finding. A whole-roster
campaign should reproduce it at scale and somebody should profile where
it goes; that was out of scope here and was not done.

## STATUS: the fix is DIAGNOSED AND DRAFTED BUT NOT LANDED

Read this before repeating the work. A first attempt landed and was
REVERTED the same evening, and the reason is worth more than the patch.

The fix sizes the lane request from the CHUNK's block count instead of
the member's declared unpacked size. Two ways of doing that were tried:

1. cap `want` itself. This also shrinks `in_flight`, which is
   `want * 2`, and so the pipeline depth, which is THROUGHPUT and not
   budget.
2. cap only what is asked of the `LaneBudget`, leaving `want` to size
   the wave. `lanes` is then arithmetically unchanged in every case and
   the only difference is how much of the ceiling a member RESERVES from
   its neighbours. This is the right shape.

It was reverted anyway, because **neither variant could be measured**
on the evening of 20 Sep 2026. Variant 1 on `f/extract-dial-8x16-m1` at
width 6 read 28 percent WORSE than no cap on an M3 Mac and 35 percent
BETTER than variant 2 on a laptop, in the same hour. Those two
readings cannot both be right, so both are noise: the box had five cores
of Spotlight on it and the laptop was at load 37 with eight other builds
running. By the project's rule a performance change is whichever setting
MEASURES the lowest wall, and neither of these was measured.

**So this needs a quiet box.** What the next attempt inherits:
the diagnosis, the two variants, the reason variant 2 is the right shape,
and the two units below to check the answer against. What it must not do
is land either variant on the strength of one run, because a
difference of this size is inside the band that needs
two agreeing runs.

## What WAS this change's, and is NOT fixed

Spending the remainder of the read's width made the WALL on these units
much worse while the CPU stayed nearly flat, 10.3 s to 29.6 s on the
first: the signature of spawning and joining lanes that decode nothing.
The cause is that `member_planned` sizes its lane request from the
member's DECLARED unpacked size, which a header can put at anything over
a handful of packed bytes, and caps the lanes to the chunk's actual
block count only AFTER the budget has handed them out. Capping the ask
closes it and brings the units back to the base figures above, but see
the status section: the cap is not landed, so **the wall cost on these
two units is in the shipped engine** and is declared here
rather than hidden.
