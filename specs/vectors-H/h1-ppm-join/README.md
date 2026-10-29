# A PPM block header where an LZ member, or no member, owes nothing

Evidence for SPEC-H1 3.8 (B4, B5) and SPEC-I 3.1 and 3.3 (E2, E7). Read
those first.

| Path | What |
|---|---|
| `join-probe.py` | builds the archives and puts them to the reference. Its LZ blocks are written by `../h1-evidence/h1probe.py`, its PPM blocks by a PPMd model written from SPEC-I's text, which is not kept at the tip |
| `archives/*.rar` | 105 archives, 271 to 773 bytes each: `<case>.<reading>.rar` |
| `archives/cases.tsv` | per archive and member: the size, CRC32 and SHA-256 of the bytes the archive's reading expects, and the question |
| `unrar-7.23-linux-x86-64.txt` | what reference unrar 7.23 for x86-64 Linux answered |
| `unrar-7.23-macos-arm64.txt` | what reference unrar 7.23 for macOS answered: the same, line for line after the first |
| `zero-byte-census.py`, `zero-byte-census.txt` | what genuine writers put in a compressed member that declares zero bytes: the script and its output (below) |
| `cut-probe.py` | packed data that runs out at the end of a PPM member, and inside a PPM block header where nothing is owed (below) |
| `cut/*.rar`, `cut/cases.tsv`, `cut/model.tsv` | its 128 archives, 208 to 3,334 bytes each, the bytes each expects, and where a decoder written from SPEC-I's text first asks for a byte the data does not hold |
| `cut/unrar-7.23-linux-x86-64.txt`, `cut/unrar-7.23-macos-arm64.txt` | what the reference answered: the same, line for line after the first |

## The cases

A PPM block is decoded right only by a reader whose model is the
writer's. So one question is coded as several archives, one per reading
of what the reference's model holds at the judged member, and the
reference prints the judged member right for the reading it follows.

- `c1`, `c2`: controls. An LZ block and a PPM block inside one member's
  declared bytes; a member that begins with a START block.
- `z-<before>-<what>`: a member declaring ZERO bytes at a header expected
  point (after an LZ member ended with bits 0, 1, or after a PPM member
  ended with its end pair), whose packed data begins with a PPM block
  header.
- `t-<before>-<what>`: an LZ member declaring 5 bytes whose packed data
  goes on, after its five literals, with an end of block of first bit 1
  and, at the next byte boundary, a PPM block header.
- `p-<what>`: a PPM member declaring 700 bytes whose packed data goes
  on, after them, with the end of block (escape, 0) and another block.

`<what>` is what follows the point in question: `pair` a START header and
the end pair; `symbols` a START header, 40 symbols and the end pair;
`open` a START header and 40 symbols with no end pair; `header` a START
header and nothing more; `continue` a CONTINUE header, 40 symbols and the
end pair; `lz` (family `p` only) an LZ block header, tables and an end of
block that ends the member.

The readings: `read-then-continue` the header and symbols in question
were taken into the model and the judged member begins with a CONTINUE
header; `header-read-symbols-not-then-continue` the header was read and
the symbols were not; `not-read-then-continue` nothing of it was read and
the model is the one the member before left; `read-then-no-header` the
judged member begins with symbols and no header; `then-start` the judged
member begins with a START header; `read-then-run-of-a-symbol-in-question`
and `read-then-run-of-the-last-declared-byte` the judged member begins
with a run at distance 1 and the archive expects it to copy the last of
the 40 symbols, or the last byte any member declared.

## What the reference answered

57 archives printed as coded and 48 not, the same on both systems.

| What | Printed as coded | Not |
|---|---|---|
| `pair`, `header` (families `z`, `t`, `p`) | `read-then-continue`, `read-then-run-of-the-last-declared-byte`, `then-start` | `not-read-then-continue` (where a PPM member came before), `read-then-no-header` (`header`) |
| `symbols`, `continue` | `read-then-continue`, `read-then-run-of-a-symbol-in-question`, `then-start` | `header-read-symbols-not-then-continue`, `not-read-then-continue`, `read-then-run-of-the-last-declared-byte` |
| `open` | `then-start` only | every reading that continues the model, and `read-then-no-header` |
| `p-lz` | `read-then-kept-tables`, `then-new-tables` | |

So the header is read in all three places; the symbols after it are
decoded, enter the model and enter the window, and are no member's
output; the member after it begins at a block header; and where the
symbols stop with no end pair, the model is of no use to a CONTINUE
header.

## What genuine writers put in a member of zero bytes

Evidence for SPEC-F 3.6.3 item 4, which owns the verdict on such a
member. `zero-byte-census.py` walks the headers of every genuine archive
of the older container kept here and prints each compressed member of
unpack version 29 or later that declares zero bytes, with its packed
bytes. It reads bytes and runs no program. The run recorded in
`zero-byte-census.txt` was over `fixtures/legacy/archives/`,
`../legacy/`, `../../vectors-I/archives/`, `../../vectors-J/archives/`
and the 60 files of `fixtures/legacy/evidence/archives/` as they stand
on the branch `fixtures/legacy-evidence-writes-06oct` (not on the main
branch when this was written; read from that branch): 116 archive files
written by rar 3.9.3, 4.2.0 and 5.5.0, and three more whose headers are
encrypted and were not walked.

| | Count |
|---|---|
| file members, directories left out | 460 |
| compressed members | 420 |
| members declaring zero bytes, stored (no packed byte) | 5 |
| members declaring zero bytes, compressed | 25 |
| of those, encrypted, 16 packed bytes, not readable | 3 |
| of those, 8 packed bytes `00 bf 88 67 f6 a9 ff d4` | 19 |
| of those, 2 packed bytes | 3 |

- **The 19 of 8 bytes** are each the first compressed member of their
  stream: the member's solid bit is clear in all 19 (one of them,
  in `i13_empty_and_one.rar`, heads a solid archive). The bytes are the same in all
  19 and are one whole LZ block: a header with its top bit 0, tables, and
  an end of block (SPEC-H1 3.8, B5; `../h1-evidence/census.txt` decodes
  them). Seven of the 19 stand in archives whose other members begin
  with PPM blocks, written at `-m5` over text: the writer gave the empty
  member an LZ block there too.
- **The 3 of 2 bytes** (`EMPTY.DAT` of `r393_solid.rar`,
  `r420_solid.rar`, `r550_solid.rar`) each follow, in a solid chain, an
  LZ member that ended inside its block; their bytes are symbols of that
  block (an end of block), which `../h1-evidence/census.txt` decodes.
  Their first byte has its top bit set, which means nothing inside a
  block.
- **Never seen:** a member of zero bytes whose packed data holds a PPM
  block header; a member of zero bytes with no packed byte at all in
  these versions; a member of zero bytes that follows a PPM member in a
  solid chain, or that follows an LZ member that ended at a header
  expected point. What a genuine writer puts in those two last places is
  NOT ESTABLISHED: no kept archive has the shape, and the reference
  `rar` 7.23 does not write the older container (`rar a -ma4` answers
  `Unknown option: ma4`). One archive written by rar 3.9.3, 4.2.0 or
  5.5.0 at `-m5 -s` over a text file, an empty file and a text file, in
  that order in the archive, would show it. (Every genuine PPM member
  kept here ends with the same 8 bytes as the 19 above, after its end
  pair.)

    python3 zero-byte-census.py <directories of genuine archives>

## Packed data that runs out (`cut-probe.py`)

Evidence for SPEC-I 3.2 and 3.3 and SPEC-H1 3.8.

**Part G: genuine PPM members, cut.** Four archives of
`../../vectors-I/archives/` written by genuine rar 4.2.0, the last
member of each a PPM member (in `i06_solid3` the third of a solid
chain). `<archive>.file-cut-<k>` is the file ended `k` bytes before the
end of that member's packed data, as an incomplete download is.
`<archive>.data-cut-<k>` has the container whole (the packed size
rewritten, the header checksum made right, the end block kept) and the
member's packed data `k` bytes shorter. `cut/model.tsv` says what a
decoder written from SPEC-I's text meets on each.

| What the decoder meets | Archives | The reference, `file-cut` | The reference, `data-cut` |
|---|---|---|---|
| the end pair, read whole (`k` up to 8: only bytes after the PPM data's end are gone) | 16 and 12 | the member OK; `Unexpected end of archive` and exit 1 for every `k` above 0 | the member OK, exit 0 |
| the data runs out inside the two symbols after the declared size (`k` from 9 up to 10, 11 or 12, by archive) | 13 and 13 | the member OK, its bytes whole; `Unexpected end of archive`, exit 1 | the member OK, its bytes whole, exit 0 |
| the data runs out before the declared size | 27 and 27 | the member short, with as many bytes as the decoder gives or a few more (it reads on past the data), `checksum error` and `Unexpected end of archive`, exit 3 | the same without the second message |

So the reference never says anything of an end pair: where the file is
short it says `Unexpected end of archive`, and a member is judged by its
checksum alone.

**Part H: a PPM START header cut short where nothing is owed.** A START
header of three bytes (order, memory, escape byte) cut to its first one
or two, after a PPM member: behind an LZ member's declared size and an
end of block of first bit 1 (`t-ppm-cut-header-<n>`), and as the whole
packed data of a member declaring zero bytes (`z-ppm-cut-header-<n>`).
The member after it is coded once per reading of the model the reference
then holds.

| Reading | `t`, 1 and 2 bytes | `z`, 1 and 2 bytes |
|---|---|---|
| `not-read-then-continue`: the model of the PPM member before | not printed as coded | not printed as coded |
| `zeros-read-then-continue`: a model started by the header, zero for each missing byte | not | not |
| `started-escape-kept-then-continue`: a model started, the escape byte as it was | not | printed as coded |
| `started-escape-2-then-continue`: a model started, the escape byte 2 | not | not |
| `then-start` (control) | printed as coded | printed as coded |

In every archive the member holding the cut header is reported OK. In
the three `t` readings that start a model the judged member comes out
whole but for its first three bytes, which are the escape byte and the
run's two operands printed as literals: the model is the one the cut
header's first byte starts, and the escape byte is none of the three
tried. So the reference starts a model from a header its data does not
hold whole, and takes the missing bytes from somewhere outside the
member's packed data. Where from is NOT ESTABLISHED. (The `z` answer is
also what bytes left over from the member before would give: that
member's packed data begins with a header whose second and third bytes
are the memory byte 0 and the same escape byte.)

    python3 cut-probe.py --build /some/dir        # byte for byte the archives of cut/
    python3 cut-probe.py --judge /some/dir --unrar /path/to/unrar

## Making the observations again

    python3 join-probe.py --build /some/dir       # byte for byte the archives here
    python3 join-probe.py --judge /some/dir --unrar /path/to/unrar

One process, one thread, under 200 MiB. No engine of this repository is
run.

The archives and answers here were made at the private commit be5c09422 by a tool not kept at the tip (the PPMd model the three probes wrote their PPM blocks with). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
