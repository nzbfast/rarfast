#!/bin/sh
# Does rar 7.23 store a member that will not compress, and in which forms?
# (SPEC-G 3.8.3.)
#
#     ./g5-store-verdict-probe.sh [WORKDIR]
#
# Needs `rar` 7.23 on PATH. Seeded inputs: noise (bytes of Python's random,
# seed 7) of 300,000 and 3,000,000 bytes, and 300,000 bytes of text. Prints
# each member's method, dictionary power, solid bit, sizes, read by
# r5dump.py.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
w=${1:-$(mktemp -d)}
mkdir -p "$w" && cd "$w"
python3 - <<'PY'
import random
r = random.Random(7)
open('n300k.bin', 'wb').write(bytes(r.getrandbits(8) for _ in range(300000)))
open('n3m.bin', 'wb').write(bytes(r.getrandbits(8) for _ in range(3000000)))
open('t300k.txt', 'wb').write((b'the quick brown fox jumps over the lazy dog\n' * 7000)[:300000])
open('m300k.bin', 'wb').write(bytes(r.getrandbits(8) for _ in range(150000)) + (b'the quick brown fox jumps over the lazy dog\n' * 3500)[:150000])
PY
show() { python3 "$here/r5dump.py" "$1" | grep -E 'unp_size=|comp_info=' | sed -e 's/ attr=.*//' -e 's/ host_os=[0-9]*//' | paste - - | tr -s ' \t' ' '; }
for sw in "-m1" "-m3" "-m5" "-m3 -s -ds" "-m5 -s -ds" "-m3 -s -ds -msbin"; do
  rm -f a.rar
  rar a -idq -cfg- -qo- -ep $sw a.rar n300k.bin t300k.txt n3m.bin m300k.bin
  echo "== rar a $sw: n300k.bin t300k.txt n3m.bin m300k.bin"
  show a.rar
done
