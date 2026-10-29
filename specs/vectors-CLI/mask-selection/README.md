# Which members a mask selects (10 Oct 2026)

The tables behind SPEC-CLI section 2. `read-masks-probe.py` makes them
with the genuine rar and unrar and says in its first comment what each
is; every name in them is one a genuine program printed.

- `read-tree-7.23-macos-arm64.tsv`: 114 masks over a tree of 24
  members.
- `read-dots-7.23-macos-arm64.tsv`: 723 masks over 118 members in one
  directory.

- `read-five-7.23-macos-arm64.tsv`: 18 masks over five members in one
  directory.
- `read-screen-7.23-macos-arm64.tsv`: 147 masks in `-x` and `-n` over
  the same tree (SPEC-CLI section 4).
- `create-7.23-macos-arm64.tsv`: 125 argument lines of `rar a` over a
  tree of 14 names, made by `create-masks-probe.py` (SPEC-CLI section
  3).
- `edit-7.23-macos-arm64.tsv`: 98 masks put to `rar d` and `rar rn`
  over an archive of 16 members, made by `edit-masks-probe.py`
  (SPEC-CLI section 5).

rar 7.23 and unrar 7.23 for macOS agree in all 855 read rows. x86-64 Linux,
Windows and the older genuine programs are owed.
