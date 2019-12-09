#!/bin/sh

cd qemu

./configure --target-list="x86_64-linux-user" --disable-system --enable-pie \
    --cc="clang-8" --cxx="clang++-8" --extra-cflags="-O3 -ggdb" \
    --extra-ldflags="-L /usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/ -lclang_rt.asan-x86_64 -Wl,-rpath=/usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/" \
    --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --disable-strip

make -j `nproc`

cp x86_64-linux-user/qemu-x86_64 ../

cd ../libqasan

make

cp libqasan.so ..

cd ..


