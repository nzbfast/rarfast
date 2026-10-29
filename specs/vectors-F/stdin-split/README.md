# A member added from standard input and split across volumes (10 Oct 2026)

The sets and tables behind SPEC-F 3.5.4 J5. `../stdin-split-probe.py`
says in its first comment how each set was written and what a row of
each table holds.

- `in/a.bin` (60,000 bytes) and `in/b.txt`: the bytes fed to rar.
- `si-*.partN.rar`: 12 sets written by genuine rar 7.23 for macOS with
  a.bin read from standard input (`-sia.bin`); the password of `si-p`
  and `si-hp` is `pw`.
- `file-*.partN.rar`: 3 control sets, the same bytes added as a file.
- `si-noqo` and `file-noqo` are written with `-qo-`; every other set
  holds a quick open record in its volumes (all but one small last
  volume), written by rar 7.23 unasked.
- `headers-7.23-macos-arm64.tsv`: 35 rows, one for each fragment of
  a.bin in the 15 sets: the header's flags and size field read from
  the volume's bytes, beside what `unrar lta` prints for it.
- `outcomes-7.23-macos-arm64.tsv`: 67 arms: each set whole, with one
  data bit changed in its first volume and in its last, and without
  its last volume (60); and 7 arms that rewrite one size field or
  flag, made on the two `-qo-` sets alone, since a quick open copy of
  a header may be read in the header's place.

rar 7.23 refuses `-ma4` (exit 7), so no set of the older container is
here. - `headers-7.23-linux-x86-64.tsv`, `outcomes-7.23-linux-x86-64.tsv`:
  the same judged by rar and unrar 7.23 for x86-64 Linux (11 Oct
  2026): every row the same as the macOS table's.

The programs are called; neither is opened or traced.
