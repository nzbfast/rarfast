# A RAR 5 filter record of type 4 to 7 (9 Oct 2026)

The archives and answers behind SPEC-H2 3.6, "a type of 4 or above"
(bug sweep item READER-08OCT-1).

`../h2-unknown-type-record-probe.py --keep DIR` writes the 378 archives
kept here and `cases.tsv` (each SHA-256). Its docstring says what each
archive is and what each column of an answers file means. The container
is a genuine rar 7.23 header rewritten; the blocks are written from
SPEC-H2. A second run gives the same answers line for line; the archives
of a second run differ from these in the file times the genuine writer
stamps into the base container and in the checksums that cover them, and
in nothing else.

| File | Program | SHA-256 of the program, first 16 |
|---|---|---|
| `outcomes-unrar-7.23-macos-arm64.tsv` | unrar 7.23 for macOS | `99720d63484b8db7` |
| `outcomes-rar-7.23-macos-arm64.tsv` | rar 7.23 for macOS | `fd6c7db73c659a28` |

The two agree in every column of every archive. Nothing a program printed
is kept: a verdict is derived from whether a member's name stands on a
line that ends in OK or on one that says error. A member with no checksum
field has no such line, so its column reads `unjudged` and the exit code
carries the verdict.

The item's own input (`1-stream-framed.rar`, 14,320 bytes, SHA-256
`4f2ce9781e6c7f045c9fc635de18af4022da16ee36fc9edde3e3112ccfdae7fb`) is not
kept here. Its first member declares 13,918 bytes and no checksum; walked
block by block with the reading of a RAR 5 reader written from SPEC-H2's
text (not kept at the tip; private commit be5c09422) and no bound on the size,
its second block holds one filter record, read when exactly 13,918 bytes
are out: offset 0, length 0xfdffffff, type 4. unrar 7.23 for macOS tests
the archive All OK, exit 0, nothing on its error stream, and writes all
13,918 bytes, the same bytes that reader gives. The arm
`type4-50-long-nothing-after.declares-50` is that shape built here.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
