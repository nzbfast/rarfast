#!/bin/sh
# Regenerate spec H's RAR 5 vectors with the reference rar.
#
#   mk-rar5.sh <input dir made by inputs.py> <output dir> [rar]
#
# Every archive here is written by RARLAB's own rar, so nothing in it came
# from any other writer. No rar binary is committed; the caller
# supplies one on PATH. The committed set was written by
#
#   RAR 7.23 (27 Jun 2026), the macOS arm64 command line build
#
# and this script reproduces it byte for byte with that build: the inputs
# are seeded, their modification times are set below, and the archive
# headers carry nothing else that varies (no owner record, no path, no
# host name; rar stores a name, a size, a time, a mode and a checksum).
#
# No owner switch is passed. This writer reads `-ow-` as `-ow` and then
# stores the account and group of whoever ran it in every file header
# (extra record type 6); without the switch it stores none. Checked
# 3 Oct 2026: `unrar lta` prints no "Unix owner" line for any archive, and
# h5-owner-record-diff.py against the set written with the switch finds
# that record, and the lengths and checksums tied to it, the only change.
set -eu
IN=$1; OUT=$2; RAR=${3:-rar}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# The stored modification times, in nanoseconds since the epoch (UTC).
# rar copies them from the files, so they are set here, with the mode.
python3 - "$IN" <<'PY'
import os, sys
T = {
    "TEXT.TXT": 1789766121590292175,
    "RUNS.BIN": 1789766121594051734,
    "FAR.BIN": 1789766121637667391,
    "RAND.BIN": 1789766121642229620,
    "X86.BIN": 1789766121644633298,
    "DELTA.BIN": 1789766121672123464,
    "TINY.TXT": 1789766121672280757,
    "EMPTY.DAT": 1789766121672323757,
}
for name, ns in T.items():
    path = os.path.join(sys.argv[1], name)
    os.chmod(path, 0o644)
    os.utime(path, ns=(ns, ns))
PY

a() { name=$1; shift; sw=$1; shift
  rm -f "$OUT/h5_$name.rar"
  (cd "$IN" && "$RAR" a -ep -idq $sw "$OUT/h5_$name.rar" "$@" >/dev/null); }

# One axis per archive. -md is the dictionary, -mc.. picks a filter,
# -m.. the level, -s solid.
a lit_m1        "-m1 -md128k"                TEXT.TXT
a text_m3       "-m3 -md1m"                  TEXT.TXT
a text_m5       "-m5 -md4m"                  TEXT.TXT
a runs_m5       "-m5 -md1m"                  RUNS.BIN
a far_m5        "-m5 -md1m"                  FAR.BIN
a far_small_md  "-m5 -md128k"                FAR.BIN
a rand_m5       "-m5 -md1m"                  RAND.BIN
a x86_m5        "-m5 -md1m"                  X86.BIN
a x86_nofilter  "-m5 -md1m -mc-"             X86.BIN
a delta_m5      "-m5 -md1m"                  DELTA.BIN
a delta_off     "-m5 -md1m -mc-"             DELTA.BIN
a tiny          "-m5 -md128k"                TINY.TXT
a empty         "-m5 -md128k"                EMPTY.DAT
a solid         "-m5 -md1m -s"               TINY.TXT TEXT.TXT RUNS.BIN DELTA.BIN
a solid_mixed   "-m5 -md1m -s"               X86.BIN RAND.BIN TEXT.TXT
a md_max        "-m5 -md64m"                 FAR.BIN
