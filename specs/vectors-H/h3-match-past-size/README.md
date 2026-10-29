# A RAR 2.0 match that passes its member's declared size (8 Oct 2026)

Two archives behind SPEC-H3 3.5, "A match that passes the declared
size". Each is a solid chain of two members of unpack version 20:
`ONE.BIN` declares 651 bytes and its stream is 400 literals and a match
of 258, which ends 7 bytes past the declared size; `TWO.BIN` declares
207 bytes and its stream is 100 literals and a match of 100.

- `crc-of-what-the-reference-writes.rar`: each checksum field is the
  CRC32 of what the reference writes for that member (658 and 200
  bytes).
- `crc-of-declared-prefix-and-carried-rest.rar`: `ONE.BIN`'s field is
  the CRC32 of its first 651 bytes, and `TWO.BIN`'s is that of the 7
  left over bytes followed by its own 200.

They were hand built for bug sweep item SWEEP2-08OCT-52 and are kept as
they came (`cases.tsv` has each SHA-256). `outcomes.tsv` holds the exits
of `t` and of `x -kb` and the size of each file left, for rar 7.23 and
unrar 7.23 for macOS. Nothing a program printed is kept.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
