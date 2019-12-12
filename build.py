#!/usr/bin/env python3

import os
import sys
import shutil
import argparse
try:
    import lief
except ImportError:
    print("ERROR: lief not installed.")
    print("   $ pip3 install lief --user")
    print("")
    exit(1)

DESCR = """QEMU-AddressSanitizer Builder
Copyright (C) 2019 Andrea Fioraldi <andreafioraldi@gmail.com>
"""

ARCHS = {
  "x86_64": "x86_64",
  "amd64": "x86_64",
  "x86": "i386",
  "i386": "i386",
}

dir_path = os.path.dirname(os.path.realpath(__file__))

opt = argparse.ArgumentParser(description=DESCR, formatter_class=argparse.RawTextHelpFormatter)
opt.add_argument("--arch", help="Set target architecture (default x86_64)", action='store', default="x86_64")
opt.add_argument('--asan-dso', help="Path to ASAN DSO (e.g. /usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so on Ubuntu 18.04 x86_64)", action='store', required=True)

args = opt.parse_args()

if args.arch not in ARCHS:
    print("ERROR:", args.arch, "is not a supported architecture.")
    print("Supported architectures are", ", ".join(ARCHS.keys()))
    print("")
    exit(1)

# on Ubuntu 18.04: /usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so
if not os.path.exists(args.asan_dso):
    print("ERROR:", args.asan_dso, "not found.")
    print("")
    exit(1)

arch = ARCHS[args.arch]

def deintercept(asan_dso, output_dso):
    global arch
    print("Patching", asan_dso)
    lib = lief.parse(asan_dso)

    names = []
    for index, symbol in enumerate(lib.symbols):
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.name.startswith("__interceptor_"):
            names.append(lib.symbols[index].name[len("__interceptor_"):])

    #names = ["malloc", "calloc", "realloc", "valloc", "pvalloc", "memalign", "posix_memalign", "free"]

    for index, symbol in enumerate(lib.symbols):
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.binding == lief.ELF.SYMBOL_BINDINGS.WEAK and symbol.name in names:
            print("Renaming ", symbol)
            lib.symbols[index].name = "__qasan_" + symbol.name

    lib.write(output_dso)

output_dso = os.path.join(dir_path, "libclang_rt.asan-%s.so" % arch)
deintercept(args.asan_dso, output_dso)

os.system("""cd '%s' ; ./configure --target-list="%s-linux-user" --disable-system --enable-pie \
  --cc="clang-8" --cxx="clang++-8" --extra-cflags="-O3 -ggdb" \
  --extra-ldflags="-L %s -lclang_rt.asan-x86_64 -Wl,-rpath,.,-rpath,%s" \
  --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --disable-strip"""
  % (os.path.join(dir_path, "qemu"), arch, dir_path, dir_path))

os.system("""cd '%s' ; make -j `nproc`""" % (os.path.join(dir_path, "qemu")))

shutil.copy2(
  os.path.join(dir_path, "qemu", arch + "-linux-user", "qemu-" + arch),
  os.path.join(dir_path, "qasan-qemu")
)

os.system("""cd '%s' ; make ; cp libqasan.so ..""" % (os.path.join(dir_path, "libqasan")))

print("Successful build.")
print("Test it with ./qasan /bin/ls")
print("")
