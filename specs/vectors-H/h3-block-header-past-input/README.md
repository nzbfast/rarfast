# A RAR 2.0 block header that the end of the packed data cuts (9 Oct 2026)

The 1,695 archives behind SPEC-H3 3.5, "A block header that the end of
the packed data cuts". `../h3-block-header-past-input-probe.py` builds
every one (`--build`, deterministic) and puts the kept ones to a
program (`--judge`); its first comment says what each arm is and what
the MODEL is that the bytes are compared with.

- `cases.tsv`: each archive, its SHA-256 and what it is.
- `outcomes-<program>-7.23-<system>.tsv`: for each archive the exit of
  `t`, marks derived from what `t` printed (nothing a program printed
  is kept), the exit of `x -kb`, the size of `ONE.BIN`, its declared
  size, which reading its bytes are, which reading `TWO.BIN` is, and
  the TAKE values that give both.

Four groups: 1,040 arms `ladder.*` (two headers cut at every bit, put
four ways), 552 arms `edge.*` (the read ending 1 to 37 bits past the
end, put four ways), 7 arms `stale.*` (behind an earlier, longer
member) and 96 arms `over.*` (zeros in the missing bits make the
length alphabet's list oversubscribed, put four ways).

The four answers files are the same byte for byte: rar and unrar 7.23
for macOS (arm64) and for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16).

To run it again from `specs/vectors-H`:

    ./h3-block-header-past-input-probe.py --judge h3-block-header-past-input /path/to/unrar LABEL

The older genuine readers are owed: none is deployed.
