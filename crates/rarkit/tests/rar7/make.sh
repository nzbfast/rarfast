#!/bin/sh
# Provenance of the archives beside this script (spec F 3.2.6.3): reference
# rar 7.23 writing a small input over standard input, where it cannot see
# the size and so keeps the dictionary it is asked for, with -qo- so no
# quick open copy of a header exists. Written on an M3 Mac, 27 Sep 2026;
# `rar` at -md5g takes about 12 GB of memory and -md8g more.
#
#     sh make.sh <rar> <unrar>
#
# The committed archives are the fixtures and this is how they were made:
# rar's packing may move between versions, so a run is not expected to be
# byte identical. It prints unrar's own listing and test verdict for the
# record. Over standard input rar never STORES a member, so a stored
# version 1 member is not among these (spec F 3.2.6.3 has one, 0x43c01,
# from a 5,200 MiB input).
set -eu
RAR=${1:-rar}
UNRAR=${2:-unrar}
HERE=$(cd "$(dirname "$0")" && pwd)
python3 - "$HERE/text.bin" <<'PY'
import random, sys
r = random.Random(20260927)
words = [b"solid", b"chain", b"window", b"dictionary", b"power", b"fraction",
         b"member", b"block", b"table", b"stream", b"version", b"seven"]
out = bytearray()
while len(out) < 108_894:
    out += r.choice(words) + (b"\n" if r.random() < 0.1 else b" ")
open(sys.argv[1], "wb").write(bytes(out[:108_894]))
PY
make() { # name input switches...
    name=$1; input=$2; shift 2
    rm -f "$HERE/$name.rar"
    "$RAR" a -idq -qo- -ep "$@" "-si$name.bin" "$HERE/$name.rar" < "$HERE/$input"
}
make md4g text.bin -m1 -md4g
make md4608m text.bin -m1 -md4608m
make md5g text.bin -m1 -md5g
make md8g text.bin -m1 -md8g
rm -f "$HERE/text.bin"
for a in md4g md4608m md5g md8g; do
    echo "== $a.rar"
    "$UNRAR" lt "$HERE/$a.rar" | grep -E "Compression"
    "$UNRAR" t -idq -md64g "$HERE/$a.rar" && echo "unrar t -md64g: OK"
done
