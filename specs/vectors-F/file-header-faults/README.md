# Faults inside a RAR 5 file header whose checksum is right (9 Oct 2026)

The bases and answers behind SPEC-F 3.2.6 ("A fault inside a file header
whose checksum is right", X1 to X5), 3.2.6.4 (V8) and 3.2.10 U3.
`../file-header-faults-probe.py --build DIR` has genuine rar 7.23 write
the two bases kept here (`crc.rar`, `blake.rar`; a second run gives other
bytes, so these ARE the vectors) and lists every arm's SHA-256 in
`cases.tsv`; `--judge` makes each arm from its base in memory. The
probe's docstring names the groups, the arms and the answers' columns.

One answers file per group, program and system:
`outcomes-<group>-<program>-7.23-<system>.tsv`. The groups are `extra`
(66 arms), `name` (24), `version` (20) and `hash` (22). Nothing a
program printed is kept.

The programs: rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`c98354aec9b71a5c` and `4c6a1df6f447c19e`, first 16), the two the same
on every arm. No older genuine version was run: 5.50, an unrar 6.x and
a 7.0x are owed, and the Windows build.

9 Oct 2026: the `*-7.23-linux-x86-64.tsv` files here are rar 7.23 and
unrar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16) on the same kept vectors. They agree
with the macOS answers in every column of every arm.
