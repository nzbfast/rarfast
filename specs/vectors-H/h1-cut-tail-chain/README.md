# A cut member of a solid chain and the members after it (9 Oct 2026)

The answers behind SPEC-H1 3.8, "A cut member and the members after
it". `../h1-cut-tail-chain-probe.py` makes each arm again from a tracked
genuine archive (`fixtures/legacy/archives/r420_f_mixed.rar`,
`r420_solid.rar`, `r393_solid.rar`, `r420_f_ia64.rar`): one compressed
member loses the last n bytes of its packed data, its packed size is
lowered and its header's checksum redone. 249 arms; `cases.tsv` holds
each one's SHA-256, and the archives themselves are not kept. The
probe's docstring names the answers' columns. Nothing a program printed
is kept.

The programs: rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`c98354aec9b71a5c` and `4c6a1df6f447c19e`, first 16), the two the same
on every arm. No older genuine version was run.

9 Oct 2026: the `*-7.23-linux-x86-64.tsv` files here are rar 7.23 and
unrar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16) on the same vectors. They agree with the
macOS answers in every column.
