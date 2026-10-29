# A RAR 5 file encryption record that cannot be used (9 Oct 2026)

The bases and answers behind SPEC-K 3.7.3, "A file encryption record
that cannot be used". `../file-encryption-record-probe.py --build DIR`
has genuine rar 7.23 write the bases kept here (`one.rar` and the three
volumes `set.part1.rar` to `set.part3.rar`; a second run gives other
bytes, so these ARE the vectors) and lists every arm's SHA-256 in
`cases.tsv`; `--judge` makes each arm from its base in memory. The
password is in the probe (`walk-five`). The probe's docstring names the
53 arms and the answers' columns. It loads its header helpers from
`../../vectors-F/file-header-faults-probe.py`. Nothing a program
printed is kept.

The programs: rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`c98354aec9b71a5c` and `4c6a1df6f447c19e`, first 16), the two the same
on every arm. No older genuine version was run.

9 Oct 2026: the `*-7.23-linux-x86-64.tsv` files here are rar 7.23 and
unrar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16) on the same kept vectors. They agree
with the macOS answers in every column of every arm.
