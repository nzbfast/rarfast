#!/bin/sh
# Regenerates this directory's archives with REFERENCE rar 7.23.
# The committed archives are the
# ones `tests/unrar_parity_leftovers.rs` holds; SHA256SUMS pins them, and
# `capture.py` records what reference unrar 7.23 prints for each cell the
# test asks about.
#
#   two.partN.rar    a.bin (10,000 bytes) over three 4 KB volumes, b.bin
#                    (2,000) starting in the third and ending in the fourth;
#                    stored
#   twoc.partN.rar   the same, -m3
#   twop.partN.rar   the same, stored, -psecret (data enciphered)
#   hv.partN.rar     a.bin alone over 4 KB volumes, -hpsecret (headers
#                    enciphered)
#   window.rar       a SOLID pair whose window is above 4 GiB: 4,400 MiB of
#                    zero bytes, then tiny.txt, -md8g (rar records the
#                    dictionary it needs, -md=4608m). rarkit's window
#                    ceiling is at most 4 GiB on any machine, so its default
#                    policy refuses this archive everywhere.
#
# The payloads are pinned PRNG bytes and every mtime is stamped, so a
# rerun writes the same members; rar's own salts make an enciphered
# archive's bytes differ from run to run, and SHA256SUMS is re-cut then.
#
#   RARBIN=/path/to/rar sh make.sh OUTDIR
set -eu
RARBIN=${RARBIN:-rar}
OUT=$(cd "${1:?OUTDIR}" && pwd)
unset RAR
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"

noise() { # noise LEN SEED > file: xorshift32, the tests' own generator
    python3 -c '
import sys
n, x = int(sys.argv[1]), (int(sys.argv[2]) * 2654435761) & 0xffffffff or 1
out = bytearray()
for _ in range(n):
    x ^= (x << 13) & 0xffffffff; x ^= x >> 17; x ^= (x << 5) & 0xffffffff
    out.append(x & 0xff)
sys.stdout.buffer.write(out)' "$1" "$2"
}
noise 10000 1 > a.bin
noise 2000 2 > b.bin
printf 'tiny\n' > tiny.txt
touch -t 202001020304.05 a.bin b.bin tiny.txt

rm -f "$OUT"/two.part*.rar "$OUT"/twoc.part*.rar "$OUT"/twop.part*.rar "$OUT"/hv.part*.rar "$OUT"/window.rar
"$RARBIN" a -idq -y -ma5 -m0 -v4k "$OUT/two.rar" a.bin b.bin
"$RARBIN" a -idq -y -ma5 -m3 -v4k "$OUT/twoc.rar" a.bin b.bin
"$RARBIN" a -idq -y -ma5 -m0 -v4k -psecret "$OUT/twop.rar" a.bin b.bin
"$RARBIN" a -idq -y -ma5 -m0 -v4k -hpsecret "$OUT/hv.rar" a.bin

# A sparse file where the file system has them; rar reads zeros either way.
dd if=/dev/zero of=zeros bs=1048576 count=0 seek=4400 2>/dev/null
touch -t 202001020304.05 zeros
"$RARBIN" a -idq -y -ma5 -m1 -s -md8g "$OUT/window.rar" zeros tiny.txt

cd "$OUT"
shasum -a 256 two.part*.rar twoc.part*.rar twop.part*.rar hv.part*.rar window.rar > SHA256SUMS
