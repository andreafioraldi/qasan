#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=`grep -c processor /proc/cpuinfo`

export CROSS="ccache powerpc64le-linux-gnu-"

make -j${MAKE_J} all
#(cd opal-ci; ./build-qemu-powernv.sh)
./opal-ci/fetch-debian-jessie-installer.sh
make -j${MAKE_J} check
(make clean; cd external/gard && CROSS= make -j${MAKE_J})
(cd external/pflash; ./build-all-arch.sh)
make clean
SKIBOOT_GCOV=1 make -j${MAKE_J}
SKIBOOT_GCOV=1 make -j${MAKE_J} check

make clean
rm -rf builddir
mkdir builddir
make SRC=`pwd` -f ../Makefile -C builddir -j${MAKE_J}
make clean
