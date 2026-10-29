# The members behind a damaged member of a solid RAR 5 chain (9 Oct 2026)

Three sets of volumes the genuine rar 7.23 wrote, behind SPEC-F 3.6.2
D13, 3.6.3 item 6 and the sentence of the API specification's section
4.4 on one open and one close a member.
`../solid-behind-fault-probe.py` says in its first comment what the
sets and the arms are, makes the sets again (`--build`, which needs the
genuine `rar`) and judges them (`--judge`, which builds nothing and
inverts 4,096 bytes of one volume itself).

- `R.part*.rar`, `L.part*.rar`, `N.part*.rar`: the kept sets.
- `cases.tsv`: each kept volume and its SHA-256. `cases-scale.tsv`: the
  same for the set RX, 21 MiB, which `--build-scale` makes again and
  which is not kept.
- `outcomes-<program>-7.23-<system>.tsv`: for each set and arm the
  exits of `t`, `x` and `x -kb`, the figure after "Total errors", and
  for each member the count of lines of `t` that name it with an
  error, whether `t` says OK for it, and what `x` and `x -kb` left.
  Nothing a program printed is kept.

To run it again from `specs/vectors-F`:

    ./solid-behind-fault-probe.py --judge solid-behind-fault /path/to/unrar LABEL

(RX's rows come only when its volumes stand in the directory too.)

The four answers files are the same byte for byte: rar and unrar 7.23
for macOS (arm64) and for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16), the set RX included.

The older genuine readers are owed: none is deployed.
