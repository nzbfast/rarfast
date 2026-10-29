# rarfast 0.9.0: known issues

## All systems

- **Creating under a small memory limit.** Under a memory limit (a
  cgroup cap) only a little above what a create needs, the create is
  killed by the kernel instead of being refused, and leaves a partial
  archive. With the default dictionary this was seen under limits below
  128 MiB at -m3 and below 160 MiB at -m5; with -md8m below 256 MiB,
  with -md16m below about 330 MiB (an estimate) and with -md32m below
  496 MiB. Give a capped create at least those limits, or a smaller
  dictionary. At 512 MiB and above no create was killed.
- **Linux: extracting under a memory limit.** When rarfast finds a
  memory limit on its own control group (a container, or a cgroup cap),
  it paces its writes so that extracted data waiting to reach the drive
  stays inside the limit; in our runs the kernel did not kill it
  there. What to know: under a tight limit, extraction runs at about
  the drive's own speed; an output directory on tmpfs inside the limit
  cannot be helped, because its pages are the limit's own memory; and
  this has been counted on one kernel and on ext4 only. Other file
  systems, cgroup v1, container runtimes and ARM Linux have not been
  counted yet. With no memory limit nothing changes. Windows and macOS
  are not affected.
- **Some old archives are refused where unrar reads them:** RAR 2.0
  archives written by non-RARLAB tools that reach past their declared
  dictionary, and a few RAR 3 solid archives whose members carry data
  past their declared size. rarfast reports an error; it does not write
  wrong data.
- **Differences from unrar when extracting over files that already
  exist:** a file with no permissions at all (mode 0000) is not
  overwritten (rarfast reports `Cannot create`); a hard link member is
  linked only to a file extracted in the same run.
- **Extracting over a file with other names, in a folder closed to
  writing.** Over an existing file that has other names (hard links), in
  a folder closed to writing, extraction stops with a create error
  instead of writing the file in place. A member whose folder path
  passes through a link that cannot be replaced there is refused as
  outside the destination.
- **Member names with an empty or single dot path component.** rarfast
  accepts such names when creating and renaming, as rar 7.23 does,
  although its own rules for the archives it writes forbid them. When
  extracting, a file member whose name ends in a single dot component,
  such as `d/.`, is written as a file named `d` inside the destination,
  where unrar refuses it. Both will be made to agree in 0.9.1.
- **A RAR 4 volume set whose next volume is missing or not a RAR
  archive.** rarfast reports the error, and exits with the code, as rar
  and unrar do for a RAR 5 set. RAR 4 sets were not tested for this
  case.
- **Output text.** A header-encrypted archive's progress ends at 100%
  where unrar prints 99%. Scripts that parse the output may notice.
- **Listing differences from unrar.** They are the same with or without
  `-v`, and they change only what is printed: archives, tests and
  extraction are not affected. `v` and `lt` print a percent where unrar
  prints the split marks and the `Pack-CRC32` label; `l`, `v` and `lb`
  without `-v`, run on a later volume of a set, leave out the member
  continued from the volume before; `lta` leaves out the quick open
  (`QO`) service record. Matching unrar here is planned for 0.9.1.
- **Exit codes on damaged archives.** On some damaged archives rarfast
  exits with code 1 where rar exits with 3, or the reverse; both are
  failure codes.
- **Testing (`t`) and damaged headers.** `t` does not yet check a RAR 5
  recovery record. A few rare or out of range header values in damaged
  or hand-made archives are reported differently from rar.
- **64-bit systems only.**
- **Linux: older systems are not supported by this build.** It needs
  glibc 2.34 or newer (Ubuntu 22.04, Debian 12, RHEL 9, Fedora 35 or
  newer), and it needs glibc: on an older system, or a musl system such
  as Alpine, it does not start (the README shows what is printed). A
  build for older systems is planned.
- **macOS: Apple silicon only, macOS 11 (Big Sur) or newer.** There is
  no build for Intel Macs yet.
- **Dictionaries over 4 GiB are refused.** An archive made with a
  dictionary larger than 4 GiB (RAR 7, `-md5g` and above) is not
  extracted: rarfast exits 2 and writes nothing.
- **A memory limit smaller than the archive needs.** Under an explicit
  `-mm` limit, or a memory cap, smaller than the dictionary the archive
  was made with, extraction is refused: rarfast names the size it needs
  and the size it is allowed, exits 2 and writes no file. `l`, `t` and
  `x` also honour a named `-mm` for the archive's member table: when the
  table cannot fit, they refuse in the same way, naming both sizes, and
  exit 2. Without `-mm` the same refusal comes when the table passes
  rarfast's default budget.
- **Recovery volumes (`rv`) need memory about the size of one volume.**
  Making recovery volumes for a volume set uses working memory a little
  above the size of its largest volume: for a set of 512 MiB volumes,
  about 520 MiB. The recovery volumes written are correct. If you name a
  memory limit with `-mm`, rarfast keeps to it: when one recovery volume
  cannot fit, it writes nothing, exits 8 and names the `-mm` that would
  be enough, for example:

      big.part1.rar: no recovery volume is written: one recovery volume needs 537919488 bytes of working memory, its parity and the encoder's read buffer, and -mm names 268435456. -mm513m or more lets it run.

- **Creating under a named `-mm`.** A memory limit you name with `-mm`
  bounds the whole rarfast process. If a create cannot fit inside it at
  its level and dictionary, rarfast refuses before writing anything,
  exits 8 and names the least `-mm` that would be enough, in the same
  words as `rv` above ("the archive is not written: it needs ... bytes
  of working memory at this level and dictionary, and -mm names ....
  -mm...m or more lets it run."). The figure depends on the input, the
  level, the dictionary and the machine. Counted at `-m5 -md32m`: many
  text files, 243 to 828 MiB (more for more text); one large binary
  file of 2 GiB, 477 to 507 MiB; one text member of 34 MiB, 409 to
  581 MiB (the next item). A solid create (`-s`) at `-md128m` named
  1,277 to 1,389 MiB. Every counted run stayed inside the figure it
  ran under, by 22 MiB or more. A larger `-mm` always runs where a
  smaller one does, a create that fits writes the same archive as
  without `-mm`, and a stored create (`-m0`) is never refused. At the
  smallest figure rarfast admits, it keeps to the limit with fewer
  threads, so a create of many small files can take up to about five
  times as long as without `-mm`, and one large file about twice as
  long; at twice that figure it runs at full speed.
- **One large text member under a named `-mm`.** A single large member
  of text, such as a word list or prose (one 34 MiB member counted, at
  `-m5 -md32m`), can need about 581 MiB under `-mm` on macOS and Linux,
  and about 501 MiB on a 2 CPU Windows machine. A smaller figure is
  refused before writing, naming the figure that runs.
- **Extracting a big solid archive under a tight `-mm`.** With `-mm`
  set at, or within a few MiB of, the smallest figure rarfast admits,
  extracting a big solid archive can be slower, most on Linux (about
  1.13 times as long at the smallest figure), because rarfast waits for
  memory rather than go past the limit you named.

## Commands and switches rarfast refuses

rarfast does not accept a switch and then ignore it. What it cannot do
yet it refuses by name, with a non-zero exit code, before it touches
anything. In this release:

- **Adding to an archive that already exists.** `a`, `u`, `f` and `m`
  create a new archive; over an existing one they are refused. (Where
  rar would update the archive in place.)
- **`d` (delete) on a solid archive.** `rn` (rename) on a solid archive
  works.
- **Any edit of a header-encrypted (`-hp`) archive.**
- **Edits of a locked archive**, as rar refuses them.
- **`r` (repair) of RAR 4 and older archives**, and a rebuild of a
  volume whose headers cannot be read. Repair of RAR 5 archives works.
- **Self-extracting archives:** `s` and `-sfx`.
- **When creating:** `-rv` as a switch (the `rv` command works), `-as`,
  `-ep2`, `-ep3`, `-ep4`, `-ap`, `-sl`, `-ta`, `-tb`, `-tn`, `-to`,
  `-e<attr>`, `-cl`, `-cu`, `-si`, `-f`, `-dr`, `-ol`.
- **When extracting (`x`, `e`):** `-ep`, `-ep1`, `-ep4`, `-ap`, `-ad`,
  `-f`, `-u`. `-op<path>` (the destination) works.
- **A bare `-p`** (a password to be asked for) on the reading commands;
  give the password with the switch, as `-p<password>`.
- **RAR 4 archives cannot be created:** `-ma4` is an unknown option, as
  in rar 7.

## Windows

- **Run on Windows 11 only.** Windows 10 has not been tested.
- **Slow extraction of archives with many files.** While rarfast writes
  its output, Microsoft Defender spends far more CPU on it than on the
  output of the other programs counted. On a Windows 11 PC (AMD Ryzen 7
  9800X3D), with Defender at its defaults, extracting 20,000 small
  files, median of 3 runs: rarfast took 6.2 s, `UnRAR.exe` 7.23 3.5 s
  and 7-Zip 26.03 4.5 s, and Defender used about 89 CPU s during each
  rarfast run against about 7 CPU s during each UnRAR or 7-Zip run.
  Listing the extracted files after each run cost Defender about 0.1
  CPU s for every program. As read on that PC, `rarfast.exe` and
  `7z.exe` carry no Authenticode signature, `UnRAR.exe` carries a valid
  one, and no file carries a Zone.Identifier (the mark of a download).
  An earlier count, of an earlier build of 0.9.0, extracting 4 GiB of
  stored program files (5,600 files on a desktop of the same CPU, 8,000
  on a laptop, both Windows 11): on the desktop rarfast took 1.8 times
  as long as an installed 7-Zip and the same time as an installed UnRAR
  (4.97 s against 4.99 s); on the laptop it was 2.4 times as fast as an
  installed UnRAR. Against a copy of the installed
  `7z.exe`, copied to another folder and run from there, rarfast was
  1.27 times as fast on the desktop and 1.2 to 1.3 times on the laptop.
  The extracted files are correct. Why Defender treats rarfast's output
  this way is being counted for 0.9.1. Moving `rarfast.exe` to another
  folder (Program Files included) changes nothing. Whether Defender
  stops doing this for a given `rarfast.exe` after some days on one PC
  is not known yet. Do not disable Defender or add an exclusion as a
  workaround.
- **Not profile optimised.** The macOS and Linux builds are tuned with
  profile-guided optimisation; this Windows build is not yet. Expect it
  to get faster.
- **Line endings.** Output lines end with LF, not CR LF.
- **SmartScreen warns on first run** because the program is new and
  unsigned. See the README.
- **Paths longer than 260 characters.** On Windows, rarfast writes
  paths longer than 260 characters when an archive holds them, up to
  4,096 characters. Some programs, Explorer included, cannot open or
  delete such paths. A member whose path in the destination is longer
  than 4,096 characters is refused with `Cannot create`, as on Linux at
  its own limit; the rest of the archive is extracted, and rarfast
  exits 9. unrar 7.23 refuses paths longer than 260 characters.

## macOS

- **Not notarized.** macOS refuses to open the downloaded program until
  its quarantine mark is cleared, and the mark must be cleared before
  the first run: a copy that macOS has already blocked once may stay
  blocked. See the README.
- **Tested on macOS 27 only.** macOS 11 is the minimum the program
  declares; it has not been run on versions older than macOS 27.
