#!/bin/sh
# Regenerates this directory's archives with REFERENCE rar 7.23.
# The committed archives are the ones
# `tests/parity_land3.rs` holds; SHA256SUMS pins them, and `capture.py`
# records what reference rar and unrar 7.23 print for each cell.
#
#   s9k.partN.rar    seven members of 2 to 20,000 bytes over 9 KB volumes,
#                    stored, a quick-open index in every volume (rar's
#                    default)
#   qo3.partN.rar    the same members over 20 KB volumes with -qo+
#   tail9k.partN.rar the same over 9 KB volumes with the third member cut
#                    to 3,750 bytes, so its last bytes land in the next
#                    volume without moving the counter
#   mixsc.partN.rar  a.dat (10,000 bytes, stored by -msdat) over three 4 KB
#                    volumes and b.bin (2,000, -m3) starting in the third
#   mixcs.partN.rar  the same with a.bin compressed and b.dat stored
#
# The payloads are pinned PRNG bytes and every mtime is stamped, so a
# rerun writes the same members.
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
seed=1
for size in 300 5000 12000 800 20000 2 7000; do
    noise "$size" "$seed" > "m$seed.bin"
    seed=$((seed + 1))
done
touch -t 202001020304.05 m*.bin

rm -f "$OUT"/s9k.part*.rar "$OUT"/qo3.part*.rar "$OUT"/tail9k.part*.rar
"$RARBIN" a -idq -y -ma5 -m0 -v9k "$OUT/s9k.rar" m1.bin m2.bin m3.bin m4.bin m5.bin m6.bin m7.bin
"$RARBIN" a -idq -y -ma5 -m0 -v20k -qo+ "$OUT/qo3.rar" m1.bin m2.bin m3.bin m4.bin m5.bin m6.bin m7.bin
noise 3750 3 > m3.bin
touch -t 202001020304.05 m3.bin
"$RARBIN" a -idq -y -ma5 -m0 -v9k "$OUT/tail9k.rar" m1.bin m2.bin m3.bin m4.bin m5.bin m6.bin m7.bin

noise 10000 1 > a.dat
cp a.dat a.bin
noise 2000 2 > b.dat
cp b.dat b.bin
touch -t 202001020304.05 a.dat a.bin b.dat b.bin
rm -f "$OUT"/mixsc.part*.rar "$OUT"/mixcs.part*.rar
"$RARBIN" a -idq -y -ma5 -m3 -msdat -v4k "$OUT/mixsc.rar" a.dat b.bin
"$RARBIN" a -idq -y -ma5 -m3 -msdat -v4k "$OUT/mixcs.rar" a.bin b.dat

cd "$OUT"
shasum -a 256 s9k.part*.rar qo3.part*.rar tail9k.part*.rar mixsc.part*.rar mixcs.part*.rar > SHA256SUMS
