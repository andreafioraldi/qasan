#!/bin/sh

SCRIPT=`readlink -f "$0"`
SCRIPTPATH=`dirname "$SCRIPT"`

# export LIBRARY_PATH=$LIBRARY_PATH:$SCRIPTPATH

cd qemu

./configure --target-list="x86_64-linux-user" --disable-system --enable-pie \
  --cc="clang-8" --cxx="clang++-8" --extra-cflags="-O3 -ggdb" \
  --extra-ldflags="-L $SCRIPTPATH -lclang_rt.asan-x86_64 -Wl,-rpath,.,-rpath,$SCRIPTPATH" \
  --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --disable-strip

make -j `nproc`

cp x86_64-linux-user/qemu-x86_64 ../

cd ..
cd libqasan

make

cp libqasan.so ..

cd ..
