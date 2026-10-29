# A write past the file size limit (9 Oct 2026)

The archive and answers behind SPEC-F section 8, requirement 8.
`../file-size-limit-probe.py --build DIR` has genuine rar 7.23 store
two members in `limit.rar` (big.bin, 65,536 bytes; small.txt, 120);
`--judge` extracts it under a file size limit of 32,768 bytes, five
ways, which the probe's docstring names with the answers' columns.
Nothing a program printed is kept.

The programs: rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`c98354aec9b71a5c` and `4c6a1df6f447c19e`, first 16), the two the same
in all five ways. No older genuine version was run.

9 Oct 2026: the `*-7.23-linux-x86-64.tsv` files here are rar 7.23 and
unrar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16) on the same kept vectors. They agree
with the macOS answers in every column of every arm.
