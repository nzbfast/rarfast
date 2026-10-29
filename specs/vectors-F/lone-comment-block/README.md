# A comment block alone behind the main header (9 Oct 2026)

The archives and answers behind SPEC-F 3.3.3 B2's last paragraph ("The
lone block right behind a main header that says a comment is present")
and 3.3.9. `../lone-comment-block-probe.py --build DIR` writes the 46
archives kept here and `cases.tsv` (each one's SHA-256); `--judge` puts
them to a program. The probe's docstring names the arms and the answers'
columns. Two of the three comment blocks are genuine: the ones DOS RAR
1.55 and 2.50 embedded in the main headers of the tracked
`fixtures/legacy/archives/d155_cmt.rar` and `d250_cmt.rar`, moved out
byte for byte. Nothing a program printed is kept.

The programs: rar 7.23 and unrar 7.23 for macOS on arm64 (SHA-256
`c98354aec9b71a5c` and `4c6a1df6f447c19e`, first 16), the two the same
on all 46. No older genuine version was run.

9 Oct 2026: the `*-7.23-linux-x86-64.tsv` files here are rar 7.23 and
unrar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and
`926d3a00775ed96a`, first 16) on the same vectors. They agree with the
macOS answers in every column.
