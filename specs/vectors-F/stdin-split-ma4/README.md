# A member from standard input, split, in the older container (11 Oct 2026)

The sets and tables behind SPEC-F 3.5.4 J6. `../stdin-split-ma4-probe.py`
says in its first comment what a row of each table holds.

- `rar-5.50/si-ma4.part1.rar`, `.part2.rar` and `rar-6.24/` the same:
  written by genuine rar 5.50 and rar 6.24 for Linux with
  `a -ma4 -m0 -v1000b -sistream.bin` over the same 1,500 random bytes.
  They were made where those old programs are kept and are copied
  here byte for byte; `FACTS.txt` is the record made with them (the
  writers' banners, the SHA-256 of each volume, a listing).
  rar 7.23 writes no archive of the older container.
- Twelve more directories, made the same way on 11 Oct,
  each with its own `FACTS.txt`: `rar-5.50-m3-text-v60k`,
  `rar-6.24-m3-text-v60k`, `rar-5.50-m5-text-v60k`,
  `rar-6.24-m5-text-v60k` (compressed, 1,000,000 bytes of text, three
  volumes); `rar-5.50-stored-3vol`, `rar-6.24-stored-3vol` (stored,
  three volumes); `rar-5.20-stored-v60k`, `rar-5.20-m3-text-v60k` (the
  oldest writer that splits such a member); and four that are NOT
  split, `rar-5.50-unsplit-stored`, `rar-6.24-unsplit-stored`,
  `rar-5.50-unsplit-m3-text`, `rar-6.24-unsplit-m3-text`.
  `TABLE-of-all-sets.md` is the table made with them of every set
  that was written, 34 in all, copied and not made again (its
  heading alone is reworded).
- `headers-7.23-macos-arm64.tsv`: 32 rows, each volume's file header
  fields read from its bytes, beside what `unrar lta` prints.
- `outcomes-7.23-macos-arm64.tsv`: 206 arms over the 14 sets: each
  set whole and with a data bit changed in each volume; a split set
  without its last volume and with one header's size fields rewritten
  (the first, the last, and the middle where there are three); an
  unsplit archive with its size made one less, one more and all ones.
  The member's true bytes are what the reference prints from the set
  as written.

- `headers-7.23-linux-x86-64.tsv` and `outcomes-7.23-linux-x86-64.tsv`:
  the same judge with rar and unrar 7.23 for x86-64 Linux, 11 Oct 2026.
  Each is byte for byte the macOS table.

The programs are called; neither is opened or traced.
