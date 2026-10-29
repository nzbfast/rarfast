# How `rn` builds the new name (10 Oct 2026)

`rn-new-name-probe.py` and the two tables here are the probe and the
answers behind SPEC-CLI 11.1. The probe keeps no archive: it has the
genuine rar write two small archives under TMPDIR, and for each row
runs `rn` on a fresh copy and reads the names back with `lb`. Its
docstring says what the two tables hold. Run it as

    rn-new-name-probe.py /path/to/rar 7.23-macos-arm64 DIR

The answers kept are rar 7.23 for macOS on arm64 (SHA-256
`fd6c7db73c659a28`, first 16): `rn-one-7.23-macos-arm64.tsv`, 95
new-name arguments by 8 members, 760 cells, and
`rn-tree-7.23-macos-arm64.tsv`, 162 argument lines over a tree of 16
members, and `rn-wild-7.23-macos-arm64.tsv`, 28 new-name arguments by
7 members whose own names hold `*` and `?`, 196 cells. Two runs of the probe on 10 Oct gave the same bytes in both
tables. Nothing the program printed is kept but the listed names.

The three `*-7.23-linux-x86-64.tsv` tables are the same probe on 11 Oct
2026 with rar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9`, first
16; an AMD EPYC 4345P, as root): rn-one and rn-wild the same in every
cell, rn-tree the same renames with the members in another order.

Owed: Windows, the older genuine programs, names outside ASCII.
