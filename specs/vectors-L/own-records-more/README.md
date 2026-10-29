# More on whose recovery records they are, and a rebuild with no record (10 Oct 2026)

The bases and answers behind SPEC-L 3.5.5 O6 and O7 and 3.8's "A rebuild
from the headers, with no record". `../own-records-more-probe.py --build
DIR` has genuine rar 7.23 write the seven bases kept here (a second run
gives other bytes, so these ARE the vectors); group `bare` takes its
bases from `../own-records/`. `cases.tsv` lists every arm's SHA-256;
`--judge` makes each arm in memory and runs the program's repair
command on it (288 runs: 6 of group `bare`, 275 of group `hp`, each arm
with the right password, with `-p-`, with a wrong password, with no
password switch, and with neither that nor `-y`; and 7 of group
`rebuild`); `--fit` runs
no program and wrote `fit.tsv`. The probe's docstring names the groups,
the arms and the columns. The password of the -hp bases is in the
probe. Nothing the program printed is kept.

The program: rar 7.23 for macOS on arm64 (SHA-256 `c98354aec9b71a5c`,
first 16) and rar 7.23 for x86-64 Linux (`56c3c4fd46faa7a9`), the two
the same on every run. `unrar` has no repair command. No older genuine
version was run.
