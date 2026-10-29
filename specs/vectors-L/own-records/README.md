# Whose recovery records they are (10 Oct 2026)

The bases and answers behind SPEC-L 3.5.5, "Whose records they are" (O1
to O5). `../own-records-probe.py --build DIR` has genuine rar 7.23 write
the eight bases kept here (a second run gives other bytes, so these ARE
the vectors) and lists every arm's SHA-256 in `cases.tsv`; `--judge`
makes each of the 178 arms from its base in memory and runs the
program's repair command on it. The probe's docstring names the bases,
the arms and the answers' columns. Nothing the program printed is kept.

`fit.tsv` is `--fit`'s output: it runs no program and says, for every
set of records in every arm, whether a service header stands at the
set's P, whether shard 0's table entry fits the named file's first
bytes, and how many shards fit counted from byte 0. It is what O1b's
choice of shard 0 over a count rests on.

The program: rar 7.23 for macOS on arm64 (SHA-256 `c98354aec9b71a5c`,
first 16) and rar 7.23 for x86-64 Linux (`56c3c4fd46faa7a9`), the two
the same on every arm. `unrar` has no repair command. No older genuine
version was run.
