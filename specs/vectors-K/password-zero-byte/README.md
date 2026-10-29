# A password with a zero byte in it (11 Oct 2026)

`../password-zero-byte-probe.py` and the table here are behind the
genuine side of SPEC-API 4.5's line. No such password can be given on
a command line; the probe sends it on standard input, where both
programs ask for a password when none is given. For each of six
paths (the five ciphers, the RAR 3 one both without a salt and with
one) it draws a head and a tail of letters and digits and one
encrypted member, every LENGTH drawn at run time, and asks for the
member under the head, under head and tail joined, and under head, a
zero byte and tail typed in. The case list and its order are ours and
the probe's first comment states the rule. The probe holds no cipher.

`password-zero-byte-7.23-macos-arm64.tsv`: 12 rows, ONE draw (made
again later on 11 Oct 2026; one trial run before it drew other values,
discarded), rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`fd6c7db73c659a28` and `99720d63484b8db7`, first 16), the same in
every row. Each row is a vector: head, tail, salt, the encrypted bytes
given and the bytes delivered under head, zero byte, tail. For RAR 5
the row names `rar5-member-encrypted-under-the-head.rar`, kept here:
the archive rar wrote under the head. For the older ciphers the exits
of `t` are all 3, because the hand-built member carries no checksum;
the verdict is by the bytes delivered. Run the probe with `--check` on
the table to put the same rows to the programs again.

`password-zero-byte-7.23-linux-x86-64.tsv` is that `--check` run on 11
Oct 2026 with rar and unrar 7.23 for x86-64 Linux (SHA-256
`56c3c4fd46faa7a9` and `926d3a00775ed96a`, first 16; an Intel Xeon
Platinum 8488C, as root): every row as on macOS.

Owed: Windows, the older genuine programs.
