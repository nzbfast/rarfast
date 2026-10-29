#!/bin/sh
# Runs INSIDE a linux container, with a genuine RARLAB rar binary.
#   $1 = path to rar_static (e.g. rarlinux-x64-4.2.0/rar/rar_static)
#   $2 = absolute path of the vectors-G directory (mounted at its real path)
# Writes one archive per shape into $2/archives from the inputs in $2/in.
RAR=$1
cd "$2/in" || exit 1
O=../archives
$RAR a -ep1 -y -m0 $O/r4_store.rar hello.txt empty.dat sub >/dev/null 2>&1; echo "store $?"
$RAR a -ep1 -y -m3 $O/r4_m3.rar text.txt >/dev/null 2>&1; echo "m3 $?"
$RAR a -ep1 -y -m5 -s $O/r4_solid.rar hello.txt text.txt >/dev/null 2>&1; echo "solid $?"
$RAR a -ep1 -y -m0 -v4k $O/r4_vol.rar split.bin >/dev/null 2>&1; echo "vol $?"
$RAR a -ep1 -y -m0 -v4k -vn $O/r4_volvn.rar split.bin >/dev/null 2>&1; echo "volvn $?"
$RAR a -ep1 -y -m0 -rr5 $O/r4_rr.rar text.txt >/dev/null 2>&1; echo "rr $?"
$RAR a -ep1 -y -m0 -pSecret $O/r4_pw.rar hello.txt >/dev/null 2>&1; echo "pw $?"
$RAR a -ep1 -y -m0 -hpSecret $O/r4_hpw.rar hello.txt >/dev/null 2>&1; echo "hpw $?"
$RAR a -ep1 -y -m0 -k $O/r4_lock.rar hello.txt >/dev/null 2>&1; echo "lock $?"
$RAR a -ep1 -y -m0 -zcomment.txt $O/r4_cmt.rar hello.txt >/dev/null 2>&1; echo "cmt $?"
$RAR a -ep1 -y -m0 -ts $O/r4_ts.rar hello.txt >/dev/null 2>&1; echo "ts $?"
$RAR a -ep1 -y -m0 -pSecret -v4k $O/r4_pwvol.rar split.bin >/dev/null 2>&1; echo "pwvol $?"
$RAR a -ep1 -y -m3 -pSecret -v4k $O/r4_pwvolc.rar split.bin >/dev/null 2>&1; echo "pwvolc $?"
