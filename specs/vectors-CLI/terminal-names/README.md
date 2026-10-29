# A control character in text from the archive, to a terminal and through a pipe (10 Oct 2026)

The table behind SPEC-CLI section 10. `terminal-names-probe.py` makes
it with the genuine rar and unrar and says in its first comment what a
row holds. Both programs are called; neither is opened or traced.

    ./terminal-names-probe.py RAR UNRAR LABEL DIR

- `terminal-names-7.23-macos-arm64.tsv`: 3,968 rows, rar 7.23 and
  unrar 7.23 on macOS (arm64).

A row is one control character (64 of them), one program, one command
and one place the character stands in (a member's name, a link's
target, the comment), with what was sent on each output stream as a
pipe and as a terminal. In every row the two are the same, and so are
the two runs in which one stream is a terminal and the other a pipe.

- `terminal-names-7.23-linux-x86-64.tsv`: the same 3,968 rows on
  x86-64 Linux (11 Oct 2026), every row the same as macOS.

Windows (11 Oct 2026) has a probe of its own,
`terminal-names-windows-probe.py`, which says in its first comment
what a row holds:

    terminal-names-windows-probe.py make RAR DIR
    terminal-names-windows-probe.py read RAR UNRAR LABEL DIR OUT

`make` was run on macOS, where a file name can hold the characters,
and wrote `windows-inputs`: 128 archives, two for each of the 64
characters. `read` was run on Windows 11 (x64) over them with Rar.exe
7.23 and UnRAR.exe 7.23:

- `terminal-names-7.23-windows-x64.tsv`: 3,968 rows, the same
  characters, programs, commands and places as the macOS table. A
  pipe's column is bytes; a console's column is what stood in the
  cells of a console screen buffer when the program had ended, as
  UTF-16 code units. The two are not the same kind of thing.
- `terminal-names-7.23-windows-x64.notes.txt`: the console's code
  pages (437) and the buffers' output modes.

Not measured on Windows: another code page, virtual terminal
processing switched on, a pseudo console.
