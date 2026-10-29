# The escape byte after a refused PPM block header (8 Oct 2026)

The observation SPEC-I 3.10.1 asked for: what escape byte do the genuine
programs hold after a PPM block header they refuse?

## The archives

`escape-probe.py --build DIR` writes 23 solid archives of two members
each, and `cases.tsv`; they are kept here beside it. It is seeded and
rebuilds them byte for byte (`cases.tsv` holds each SHA-256). The PPM
blocks were written by a PPMd model written from SPEC-I's text, which is
not kept at the tip; the container is the one that file builds from the public
technote. No reader of the RAR format was opened.

Member `m1.bin` is the same 1,962 bytes in every archive, holding every
byte value. It is one PPM block: a START header with order code 8 and
memory byte 0. The archive's name says how it is coded:

- `nobit-coded-N`: the header does NOT have its 0x40 bit, so it sends no
  escape byte, and the block is coded as if the escape byte were `N`. It
  decodes to the 1,962 bytes only under a reader whose escape byte at
  that point is `N`.
- `control-bit-sent-5`: the header has the bit and sends 5. It decodes
  under any reader that reaches member `m1.bin` at a block header at all.

Member `m0.bin` is the family:

| Family | `m0.bin` |
|---|---|
| `z` | nothing refused: one whole PPM member whose START header sets the escape byte to 77 |
| `a` | the three bytes `e0 00 4d` and 24 more: a START header with ORDER CODE 1, its 0x40 bit set, memory byte 0, escape byte 77. `owes300` declares 300 bytes, `owes0` declares none |
| `b` | the two bytes `c7 4d` and 24 more: a CONTINUE header where the stream has NO MODEL, its 0x40 bit set, escape byte 77. `owes300` and `owes0` as above |
| `c` | a START header that sets the escape byte to 33, 856 bytes, the end of block (code 0), and then the same three bytes `e0 00 4d` and 24 more. `whole` declares the 856 bytes; `short` declares 100 more |

## The judges, and how to run them again

    python3 escape-probe.py --judge . --program <a label of your own> /path/to/unrar

Each archive is put to the program three times with `-inul` and
`LC_ALL=C`: `t`; `p` of `m1.bin` alone; `p` of the whole archive. The
line printed holds the three exit codes, the count of bytes printed, and
whether the bytes printed for `m1.bin` are the 1,962. Nothing a program
printed is kept.

| File | Program | SHA-256 of the program, first 16 |
|---|---|---|
| `outcomes-unrar-7.23-linux-x86_64.tsv` | the reference unrar 7.23, x86-64 Linux | `926d3a00775ed96a` |
| `outcomes-rar-7.23-linux-x86_64.tsv` | the reference rar of the same release, x86-64 Linux | `56c3c4fd46faa7a9` |
| `outcomes-rar-4.2.0-linux.tsv` | genuine rar 4.2.0 for Linux, the static build of its package | `aba2d13423d4e48f` |
| `outcomes-unrar-4.2.0-linux.tsv` | the unrar of the same 4.2.0 package | `b58f87ff10af64ed` |
| `outcomes-unrar-7.23-macos-arm64.tsv` | unrar 7.23 for macOS | `99720d63484b8db7` |

The four Linux files were made on 7 Oct 2026 at 19:24 UTC on one x86-64
Linux machine, the macOS file the same evening. The five files agree in
every column of every archive.

## How to read them

In family `z` the answer is known (SPEC-I 3.2: a START block without the
bit keeps the value before): `nobit-coded-77` is printed and
`nobit-coded-2` is not. It shows the instrument tells the two apart.

In the other families the control says whether the program reads member
`m1.bin` from a block header at all after what `m0.bin` held; where it
does, the one `nobit-coded-N` that is printed names the escape byte the
program held when it reached that header. SPEC-I 3.10.1 states the
result.

## What they show

| Family | Control | `nobit-coded-2` | `nobit-coded-33` | `nobit-coded-77` | The escape byte held |
|---|---|---|---|---|---|
| `z` (nothing refused) | printed | no | | printed | 77, as SPEC-I 3.2 says |
| `a` (START, order code 1, bit, 77), both sizes | printed | no | | printed | 77: the refused header's own |
| `b` (CONTINUE, no model, bit, 77), both sizes | printed | printed | | no | 2: the refused header's is NOT taken |
| `c` (33 set, then START, order code 1, bit, 77), both sizes | printed | no | no | printed | 77: the refused header's own, not the 33 before it |

The exit codes are the members' verdicts and are recorded as they came:
where `m0.bin` declares 300 bytes it fails and the test exits 3 whatever
`m1.bin` does, so read the `m1 as coded` column, which is of `m1.bin`
alone.

The archives and tables here were made at the private commit be5c09422 by a tool not kept at the tip (that PPMd model). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
