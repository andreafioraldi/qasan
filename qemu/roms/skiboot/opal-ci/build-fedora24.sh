#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=`grep -c processor /proc/cpuinfo`
export CROSS="ccache powerpc64-linux-gnu-"

make -j${MAKE_J} all
make -j${MAKE_J} check
(make clean; cd external/gard && CROSS= make -j${MAKE_J})
(cd external/pflash; make -j${MAKE_J})
make clean
# Disable GCOV builds on Fedora 24 as toolchain gives us:
# /usr/bin/powerpc64-linux-gnu-ld: section .bss VMA [0000000000200000,000000000024d757] overlaps section .sym_map VMA [000000000019f340,0000000000208e5c]
# (we shoud fix it, but not yet)
#SKIBOOT_GCOV=1 make -j${MAKE_J}
#SKIBOOT_GCOV=1 make -j${MAKE_J} check

make clean
rm -rf builddir
mkdir builddir
make SRC=`pwd` -f ../Makefile -C builddir -j${MAKE_J}
make clean
