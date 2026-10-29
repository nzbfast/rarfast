# Recovery volume names, above all on a renamed set (10 Oct 2026)

`../rev-names-probe.py` and the table here are the probe and the
answers behind the lines of SPEC-L 3.6.4 that begin "The names follow
the FIRST volume's name". The probe keeps no archive: it has the
genuine rar write each set under TMPDIR, renames the volumes, runs
`rar rv` and lists the `.rev` names. Its docstring says what a row
holds. Run it as

    rev-names-probe.py --rar /path/rar --label 7.23-macos-arm64 --out DIR \
        --old-style fixtures/legacy/archives/r393_voln.rar

`rev-names-7.23-macos-arm64.tsv`: 112 rows (the last 30 added 11 Oct
for which digits are a set's number), rar 7.23 for macOS on arm64
(SHA-256 `fd6c7db73c659a28`, first 16), on a file system that does not
tell names apart by case. Nothing the program printed is kept.

`rev-names-7.23-linux-x86-64.tsv`: the same probe on 11 Oct 2026 with
rar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9`, first 16; an
AMD EPYC 4345P). 80 rows the same; the two rows where the first
volume differs from the rest in case alone get no recovery volume
there.

Owed: Windows, the older genuine programs.
