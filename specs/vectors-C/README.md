# Vectors and probe records for specification C

Everything here was made on 6 Oct 2026 from black-box runs of the reference
`rar` 7.23 and `unrar` 7.23 for x86-64 Linux. No reader's or writer's source
was opened to write any file in this directory.

## What is here

| File | What it is |
|---|---|
| `rar5build.py` | writes a one member RAR 5 archive by hand: literals, runs of zeros, filter records |
| `rar3build.py` | the same for a RAR 3 archive, the record carrying a program's bytes |
| `harness.py` | builds one archive per arm, runs the reference on it, and scores the stated reading and every variant |
| `c1-x86-probe.py` | Parts 1 and 2: RAR 5 record types 1 and 2 |
| `c3-rar3-x86-probe.py` | Part 3: the RAR 3 x86 programs |
| `c4-arm-probe.py` | Part 4: RAR 5 record type 3 |
| `c5-ia64-probe.py` | Part 5: the RAR 3 IA-64 program |
| `c6-delta-probe.py` | Part 6: RAR 5 record type 0 |
| `c7-genuine-census.py` | Part 7: what genuine rar writes, each record checked against Parts 1, 2 and 6 |
| `c8-hand-vectors-probe.py` | the rows of sections 1.3 to 6.3, each put to the reference in both directions |
| `c1-x86/`, `c3-rar3-x86/`, `c4-arm/`, `c5-ia64/`, `c6-delta/` | each probe's record: `arms.tsv`, `variants.tsv` and the line it printed |
| `c7-census.tsv` | the census as printed |
| `c8-drawn-inputs-probe.py` | rows X9, T2 and A1: their span starts and bytes DRAWN from the system's random source inside classes fixed before the draw, and each column delivered by the reference. It holds no filter. `--draw` makes a new table (and the three rows of the specification change with it); `--check` puts the table's rows to the reference again |
| `c8-hand-vectors/` | `hand-vectors.tsv` (the rows), `drawn.tsv` (the drawn rows and what the reference delivered), `drawn-check-unrar-7.23-linux-x86-64.txt` (the same five rows put to unrar 7.23 for x86-64 Linux by `c8-drawn-inputs-probe.py --check`: all as in the table), `arms.tsv`, and each row's archives where they are 8 KiB or less |

## How a probe works

Each probe holds the specification's statements as one function, the STATED
reading, and a table of VARIANTS: the same function with one rule read
another way. An ARM is one archive: a member of `F` zero bytes, a span of
chosen bytes under one filter record, and a few bytes after it. The
archive's header carries the CRC32 of what the stated reading says the
member is. The reference is the judge: `unrar p` gives the bytes it decodes
and `unrar t` its verdict on the CRC32. An arm SETTLES a variant when the
reference's bytes are the stated reading's and are not the variant's.

`arms.tsv` has one line per arm: the span as stored, the stated reading's
bytes, the reference's bytes, the exit code of `unrar t`, the verdict, the
archive's size and the start of its sha256, and the variants that give
other bytes on that arm. `variants.tsv` has one line per variant: how many
arms settle it. A probe exits 0 when every arm is AS STATED and every
variant is settled by at least one arm.

The arms are fixed and nothing is random, so a run rebuilds the same
archives. Spans far into a member (up to `2^33 + 17`) cost a few hundred
bytes of archive under RAR 5 and up to about 3 MB under RAR 3; the
reference then decodes that many zeros, which takes each of the two x86
probes some minutes.

## Running them again

With the reference programs at `$RAR` and `$UNRAR`:

    cd specs/vectors-C
    for p in c1-x86 c3-rar3-x86 c4-arm c5-ia64 c6-delta c8-hand-vectors; do
        python3 $p-probe.py /tmp/$p --unrar $UNRAR || echo "$p DIFFERS"
    done
    python3 c7-genuine-census.py /tmp/c7-work --rar $RAR --unrar $UNRAR > /tmp/c7-census.tsv

and compare each `/tmp/<probe>/arms.tsv` and `variants.tsv` with the copy
here. The census reads archives with a RAR 5 reader written from SPEC-H2's
text (not kept at the tip) and packs
the two reference programs themselves as its x86 inputs, so its counts for
those two members belong to these builds of them (sha256 beginning
`56c3c4fd46faa7a9` for `rar`, `926d3a00775ed96a` for `unrar`).

Python 3.9 or later; nothing outside the standard library.

`c7-census.tsv` was made at the private commit be5c09422 by a tool not kept at the tip (that RAR 5 reader, which the census script loads). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
