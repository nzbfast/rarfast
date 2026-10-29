# The file a repair writes (10 Oct 2026)

`../repair-output-probe.py` and the table here are the probe and the
answers behind SPEC-L 3.9. The probe keeps no archive: it has the
genuine rar write its inputs under TMPDIR, damages one of them, and for
each arm runs `rar r` or `rar rc` on fresh copies while it lists the
directories, then removes everything. Its docstring says what an arm
is and what a row's columns hold. Run it as

    repair-output-probe.py --rar /path/rar --label 7.23-macos-arm64 \
        --out DIR --runs 5 --rar4 fixtures/legacy/archives/r420_rr.rar

It makes one small disk image of its own for the two arms on a full
volume (hdiutil on macOS; a tmpfs on Linux, where it must be root) and
detaches it.

`repair-output-7.23-macos-arm64.tsv`: 138 arms, 5 runs each, rar 7.23
for macOS on arm64 (SHA-256 `fd6c7db73c659a28`, first 16), run as an
ordinary user. rar is called and nothing else: it is not traced. Of
what it printed only the keys of the probe's marker phrases are kept.

`repair-output-7.23-linux-x86-64.tsv`: the same probe on 11 Oct 2026
with rar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9`, first 16;
an AMD EPYC 4345P), run AS ROOT: the nine arms that rest on a
permission succeed there and say nothing of an ordinary user on
Linux; every other arm answers as on macOS.

Owed: Windows, the older genuine programs, Linux as an ordinary user.
