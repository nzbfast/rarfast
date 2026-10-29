#!/bin/sh
# Runs INSIDE the container. $1 = path to rar_static, $2 = archive prefix.
# a <name> "<switches>" <files...>
set -u
RAR=$1; P=$2; cd /r/in
a() { name=$1; sw=$2; shift 2; "$RAR" a -idq -ep -m3 $sw "/r/out/${P}_${name}.rar" "$@" > "/r/out/${P}_${name}.log" 2>&1; echo "$P $name exit $? :: $sw $*"; }
a x86_e    "-mcE+" X86.BIN
a x86_auto "-m5" X86.BIN
a ia64_i   "-mcI+" IA64.BIN
a rgb_c    "-mcC+" RGB.RAW
a bmp_auto "-m5" IMAGE.BMP
a pcm_a4   "-mc4A+" PCM.RAW
a pcm_a2   "-mc2A+" PCM.RAW
a wav_auto "-m5" SOUND.WAV
a tab_d3   "-mc3D+" TABLE.BIN
a tab_auto "-m5" TABLE.BIN
a bigrgb_c "-mcC+" BIGRGB.RAW
a mixed_solid "-m5 -s" X86.BIN IA64.BIN IMAGE.BMP SOUND.WAV TABLE.BIN RGB.RAW PCM.RAW
a mixed_nonsolid "-m5" X86.BIN IA64.BIN IMAGE.BMP SOUND.WAV TABLE.BIN
