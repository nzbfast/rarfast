# A split member whose two headers name different kinds of checksum (10 Oct 2026)

The bases and answers behind SPEC-F 3.5.6 C6.
`../split-checksum-kind-probe.py --build DIR` has genuine rar 7.23 write
the two sets of two volumes kept here (a second run gives other bytes,
so these ARE the vectors) and lists each arm's SHA-256 in `cases.tsv`;
`--judge` makes each of the 28 arms from its base in memory. The probe's
docstring names the arms and the answers' columns. It loads its header
helpers from `../file-header-faults-probe.py`. Nothing a program printed
is kept.

The programs: rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`c98354aec9b71a5c` and `4c6a1df6f447c19e`, first 16), the two the same
on every arm. No older genuine version was run.

10 Oct 2026: the `*-7.23-linux-x86-64.tsv` files here are rar 7.23 and
unrar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16) on the same kept vectors. They agree with
the macOS answers in every column of all 28 arms.
