# A RAR 2.0 symbol whose bits run past the end of the packed data (9 Oct 2026)

The 790 archives behind SPEC-H3 3.5, "A symbol that begins inside the
packed data and needs bits past its end", and behind the sentence of
SPEC-D 2.1 that points there. `../h3-last-symbol-past-input-probe.py`
builds every one (`--build`, deterministic) and puts the kept ones to a
program (`--judge`); its first comment says what each arm is and what
the MODEL is that the bytes are compared with.

- `cases.tsv`: each archive, its SHA-256 and what it is.
- `outcomes-<program>-7.23-<system>.tsv`: for each archive the exit of
  `t`, marks derived from what `t` printed (nothing a program printed
  is kept), the exit of `x -kb`, the size of `ONE.BIN`, its declared
  size, the size of the uncut stream's bytes, which reading its bytes
  are, the STOP values that give them, the other supplies that give
  them, and the member behind it.

Three groups: 756 arms named by the last symbol, the bits cut and how
the cut is put; 14 arms `own.*`, the cut member first and alone with
long packed data; 20 arms `stale.*`, the cut member behind a first
member of one bits.

To run it again from `specs/vectors-H`:

    ./h3-last-symbol-past-input-probe.py --judge h3-last-symbol-past-input /path/to/unrar LABEL

The four answers files are the same byte for byte: rar and unrar 7.23
for macOS (arm64) and for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16; run on the x86-64 Linux box,
00:03:41Z to 00:16:33Z on 9 Oct 2026).

The older genuine readers are owed: none is deployed.
