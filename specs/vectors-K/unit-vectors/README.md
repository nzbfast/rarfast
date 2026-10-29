# Unit vectors nobody chose (11 Oct 2026)

`../unit-vectors-probe.py` and the table here are behind SPEC-K 5.1
and SPEC-B 3.4. The probe draws its passwords, salts and encrypted
bytes from the system's random source, has the genuine programs
decrypt them, and writes down what they deliver; it holds no cipher
and no key derivation, so it cannot compute an answer. Its first
comment says what a row holds.

THE CASE LIST IS OURS (made again later on 11 Oct 2026): 13 rows, one
for each path a reader of the four older ciphers can take, each with
its reason in the table's second column; the order by a rule the
probe states; every length drawn at run time but the four that are
edges of a format (16 and 17 characters for RAR 2.0, 27 and 28 for the
RAR 3 derivation). No count, order or length of the table that stood
here before is kept.

`unit-vectors-7.23-macos-arm64.tsv`: 13 rows, ONE draw, unrar 7.23 and
rar 7.23 for macOS on arm64 (SHA-256 `99720d63484b8db7` and
`fd6c7db73c659a28`, first 16), the two programs the same in every row.
One trial run before it drew other values; they were discarded and are
nowhere. Run the probe with `--check` on that table to put the same
rows to the programs again, on this system or another: it stops unless
every row comes out the same.

The `*-7.23-linux-x86-64.tsv` table beside it is that `--check` run on
11 Oct 2026 with rar and unrar 7.23 for x86-64 Linux (SHA-256
`56c3c4fd46faa7a9` and `926d3a00775ed96a`, first 16; an Intel Xeon
Platinum 8488C, as root): every row the same bytes as on macOS.

Owed: Windows; the older genuine programs.
