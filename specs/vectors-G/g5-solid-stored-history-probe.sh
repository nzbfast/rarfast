#!/bin/sh
# Does a member stored inside a solid archive enter the history the later
# members are packed against? (specification G section 3.9)
#   sh g5-solid-stored-history-probe.sh /path/to/rar /path/to/unrar
# x.jpg and z.bin hold the same 30,000 random bytes. If the stored x.jpg
# entered the history, z.bin after it would pack to a few bytes, as it
# does in the third archive, where x.jpg is packed.
set -e
RAR=$1; UNRAR=$2; D=$(mktemp -d); cd "$D"
python3 -c '
import random
r = random.Random(5); n = bytes(r.randrange(256) for _ in range(30000))
open("a.txt", "wb").write(b"some text here\n" * 2000)
open("x.jpg", "wb").write(n); open("z.bin", "wb").write(n)'
"$RAR" a -idq -cfg- -s -m3 -ds -msjpg stored-between.rar a.txt x.jpg z.bin
"$RAR" a -idq -cfg- -s -m3 -ds absent.rar a.txt z.bin
"$RAR" a -idq -cfg- -s -m3 -ds packed-between.rar a.txt x.jpg z.bin
for f in stored-between absent packed-between; do
  echo "== $f"; "$UNRAR" lt $f.rar | grep -E "Name:|Packed size|Compression|Flags"
  "$UNRAR" t -idq $f.rar && echo "unrar t: OK"
done
cd /; rm -rf "$D"
