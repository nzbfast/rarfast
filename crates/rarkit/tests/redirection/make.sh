#!/bin/sh
# Regenerates this directory's archives with GENUINE writers:
# reference rar 7.23 for every
# RAR 5 archive and Linux rar 4.2.0 (rarlinux-x64-4.2.0.tar.gz, sha256
# db4a35d1092eade42fd4233e200c8a24b942c7d67a4b7d0f92914781924b3985) for the
# RAR 4 family's links. Each archive covers rows of spec F 3.2.6.2, 3.3.12
# and 3.8 that a genuine writer can produce; the rows no Linux writer makes
# are rewritten from these at test time (`tests/redirection.rs`). rar is
# not byte-deterministic across runs, so the committed archives are the
# ones the tests hold and their digests are in SHA256SUMS.
#
#   RARBIN=/path/to/rar RAR4BIN=/path/to/rar4 sh make.sh OUTDIR
set -eu
RARBIN=${RARBIN:-rar}
RAR4BIN=${RAR4BIN:-rar4}
OUT=$(cd "${1:?OUTDIR}" && pwd)
unset RAR
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
stamp() { find . -exec touch -h -d "2020-01-02 03:04:05" {} +; }
fresh() { cd "$W" && rm -rf t && mkdir t && cd t; }

# 1. Symbolic links at every row of 3.8.2's safety table, a directory
# link, a dangling one, and a hard link (-ol -oh).
fresh
mkdir -p d/e
echo top > top.txt
echo a-content > a.txt
ln -s a.txt sym_rel
ln -s /etc/hostname sym_abs
ln -s ../../escape sym_up
ln -s .. dotdot_only
ln -s ../top.txt d/up_in
ln -s ../../top.txt d/e/up_in2
ln -s ../../top.txt d/up_out
ln -s d/../top.txt dotdot_mid
ln -s ./top.txt dotslash
ln -s d sym_dir
ln -s nothere sym_dangling
ln a.txt hard_a
# Stored as type 1 on Linux; the tests rewrite them to types 2 and 3.
ln -s 'C:\x\a.txt' win_abs
ln -s '\??\C:\x' junc_abs
ln -s 'd' junc_rel
ln -s 'd\f.txt' backslash
stamp
"$RARBIN" a -idq -y -ma5 -m3 -r -ol -oh "$OUT/links5.rar" .

# 2. File copies (-oi:1): big2 and e/big3 equal big1, 300,000 bytes.
fresh
mkdir e
i=0; while [ $i -lt 10000 ]; do echo "line $i of the big file ....."; i=$((i+1)); done | head -c 300000 > big1
cp big1 big2; cp big1 e/big3
echo small > s.txt
stamp
"$RARBIN" a -idq -y -ma5 -m3 -r -oi:1 "$OUT/copies5.rar" big1 big2 e s.txt

# 3. A solid archive whose compressed stream runs across every kind:
# a link FIRST, then files, links, a hard link and copies between them.
fresh
i=0; while [ $i -lt 3000 ]; do echo "alpha $i beta $((i * 7 % 13)) gamma"; i=$((i+1)); done > f1.txt
cp f1.txt f3.txt
i=0; while [ $i -lt 3000 ]; do echo "delta $i epsilon $((i * 3 % 11))"; i=$((i+1)); done > f2.txt
ln -s f1.txt a_link
ln f2.txt h2.txt
stamp
"$RARBIN" a -idq -y -ma5 -m3 -s -ol -oh -oi:1 "$OUT/solid5.rar" a_link f1.txt f2.txt h2.txt f3.txt

# 4. BLAKE2sp (-htb): a file, a link to it and a hard link to it.
fresh
head -c 3000 /dev/zero | tr '\0' 'b' > b.txt
ln -s b.txt b_link
ln b.txt b_hard
stamp
"$RARBIN" a -idq -y -ma5 -m0 -htb -ol -oh "$OUT/blake5.rar" b.txt b_link b_hard

# 5. Data encryption (-p, headers in the clear): a file, a link, a hard
# link. The password is `redir`.
fresh
echo secret-data > p.txt
ln -s p.txt p_link
ln p.txt p_hard
stamp
"$RARBIN" a -idq -y -ma5 -m3 -predir -ol -oh "$OUT/crypt5.rar" p.txt p_link p_hard

# 6. The write-through attack of 3.8.3: `dl -> /nonexistent-rarkit-victim`
# and `dl2 -> sub`, then, APPENDED once the links are real directories,
# `dl/evil` and `dl2/evil2`.
fresh
mkdir sub
echo keep > sub/keep
ln -s /nonexistent-rarkit-victim dl
ln -s sub dl2
stamp
"$RARBIN" a -idq -y -ma5 -m3 -ol "$OUT/attack5.rar" dl dl2 sub
rm dl dl2
mkdir dl dl2
echo evil > dl/evil
echo evil2 > dl2/evil2
stamp
"$RARBIN" a -idq -y -ma5 -m3 "$OUT/attack5.rar" dl/evil dl2/evil2

# 7. The RAR 4 family (rar 4.2.0 -ol): links as the member's content.
fresh
mkdir d
echo a-content > a.txt
ln -s a.txt sym_rel
ln -s d sym_dir
ln -s /etc/hostname sym_abs
ln -s ../../escape sym_up
stamp
"$RAR4BIN" a -idq -y -m3 -ol "$OUT/links4.rar" a.txt sym_rel sym_dir sym_abs sym_up d

# 8. A file copy whose `e` output is its own source (-oi:1): `d/big1` and
# `d/BIG1` are references to `big1`, so `e` flattens each onto `big1`'s
# path (the second only on a case-insensitive volume). Written by
# reference rar 7.23 on macOS on 22 Oct 2026, unstamped.
fresh
mkdir d
i=0; while [ $i -lt 10000 ]; do echo "line $i of the big file ....."; i=$((i+1)); done | head -c 300000 > big1
cp big1 d/big1
"$RARBIN" a -idq -y -ma5 -m3 -r -oi:1 "$OUT/samename5.rar" big1 d
rm d/big1
cp big1 d/BIG1
"$RARBIN" a -idq -y -ma5 -m3 -r -oi:1 "$OUT/samecase5.rar" big1 d

set -- links5.rar copies5.rar solid5.rar blake5.rar crypt5.rar attack5.rar links4.rar \
    samename5.rar samecase5.rar
cd "$OUT" && { sha256sum "$@" 2>/dev/null || shasum -a 256 "$@"; } > SHA256SUMS
cat SHA256SUMS
