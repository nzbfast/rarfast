#!/bin/sh
# Rebuild the specification F vectors. Run from an empty scratch directory.
#
#     sh generate.sh <output directory>
#
# RAR 5 archives are written by reference `rar` 7.23 (the same binary the
# specification quotes). The four legacy archives in archives/ are NOT
# rebuilt here: they were written by genuine RARLAB legacy builds under the
# recipe of fixtures/legacy/README.md, which
# needs containers and the original packages, and their provenance is in
# MANIFEST.tsv. Nothing here fetches or commits a RARLAB binary.
#
# The mtimes are pinned so a rebuild differs from the committed copies only
# in the archive-creation fields the format records per run.
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out/in/sub/nested"
cd "$out"
python3 - <<'PY'
import random
open('in/hello.txt','w').write('hello rar world\n')
open('in/sub/nested/deep.txt','w').write('deep file\n')
open('in/text.txt','w').write('The quick brown fox jumps over the lazy dog. '*260)
random.seed(7)
open('in/rand.bin','wb').write(bytes(random.randrange(256) for _ in range(12000)))
open('in/comment.txt','w').write('a comment line\nsecond line\n')
PY
for f in in/hello.txt in/text.txt in/rand.bin in/sub/nested/deep.txt in/sub/nested in/sub; do
  touch -t 202609180000.00 "$f"
done
rar a -idq -ep1 -m0 f01_stored.rar in/hello.txt
rar a -idq -r  -m0 f02_dirs.rar in/sub
rar a -idq -ep1 -m3 f03_m3.rar in/text.txt
rar a -idq -ep1 -m3 -s f04_solid.rar in/hello.txt in/text.txt
rar a -idq -ep1 -m0 -htb f05_blake.rar in/hello.txt
rar a -idq -ep1 -m0 -z"in/comment.txt" f06_comment.rar in/hello.txt
rar a -idq -ep1 -m0 -pSecret f07_pw.rar in/hello.txt
rar a -idq -ep1 -m0 -hpSecret f08_hp.rar in/hello.txt
rar a -idq -ep1 -m0 -rr3 f09_rr.rar in/text.txt
rar a -idq -ep1 -m0 -qo+ f10_qo.rar in/hello.txt in/text.txt
rar a -idq -ep1 -m0 -v4k f11_svol.rar in/rand.bin
rar a -idq -ep1 -m3 -v4k f12_cvol.rar in/text.txt in/rand.bin
# f17 to f19: the TIME extra record. They want a mtime with a NANOSECOND
# part, which `touch -t` cannot set, so htime-record.py builds them.
python3 "$here/htime-record.py" build .
python3 - <<'PY'
d=open('f03_m3.rar','rb').read()
open('f13_truncated.rar','wb').write(d[:len(d)//2])
b=bytearray(open('f01_stored.rar','rb').read()); b[0x17] ^= 0x01
open('f14_bad_header_crc.rar','wb').write(bytes(b))
b=bytearray(open('f01_stored.rar','rb').read()); b[len(b)-4] ^= 0x80
open('f15_bad_data_crc.rar','wb').write(bytes(b))
open('f16_sfx_prefix.rar','wb').write(b'MZ'+b'\0'*4094+open('f01_stored.rar','rb').read())
PY
