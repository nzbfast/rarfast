#!/bin/sh
# Runs INSIDE the network-less container, from the input directory.
# $1 = rar binary, $2 = output directory. Every archive: one rar command.
R=$1; O=$2
# a <archive> "<switches>" <files...>
a() { name=$1; sw=$2; shift 2; rm -f "$O/$name"; "$R" a -ep -idq $sw "$O/$name" "$@" >/dev/null 2>&1; echo "$name $?"; }
a i01_t1_default.rar "-m5 -mct+" T1.TXT
a i02_t1_o2_m1.rar "-m5 -mc2:1t+" T1.TXT
a i03_t1_o63_m128.rar "-m5 -mc63:128t+" T1.TXT
a i04_t1_o16_m8.rar "-m5 -mc16:8t+" T1.TXT
a i05_t1_o17_m8.rar "-m5 -mc17:8t+" T1.TXT
a i06_solid3.rar "-m5 -s -mct+" T1.TXT T2.TXT T3.TXT
a i07_nonsolid3.rar "-m5 -mct+" T1.TXT T2.TXT T3.TXT
a i08_esc.rar "-m5 -mct+" ESC.TXT
a i09_bin_forced.rar "-m5 -mct+" BIN.DAT
a i10_mix_auto.rar "-m5 -mct" MIX.DAT
a i11_runs.rar "-m5 -mct+" RUNS.TXT
a i12_one.rar "-m5 -mct+" ONE.TXT
a i13_empty_and_one.rar "-m5 -s -mct+" EMPTY.TXT ONE.TXT T2.TXT
a i14_big_o63_m1.rar "-m5 -mc63:1t+" BIG.TXT
a i15_big_o8_m1.rar "-m5 -mc8:1t+" BIG.TXT
a i16_mix_forced.rar "-m5 -mct+" MIX.DAT
a i17_vol.rar "-m5 -mct+ -v20k" MIX.DAT
a i18_solid_mixed_auto.rar "-m5 -s -mct" T1.TXT BIN.DAT T2.TXT
# order sweep: which byte each documented order becomes
for o in 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 1; do
  a sweep_o$o.rar "-m5 -mc$o:4t+" T2.TXT
done
for m in 1 2 3 7 8 16 64 127 128 129 255 256; do
  a sweep_m$m.rar "-m5 -mc6:${m}t+" T2.TXT
done
# a PPM member followed by an LZ member in one solid stream
a i19_solid_ppm_then_lz.rar "-m5 -s -mct" T1.TXT ZBIN.TXT
