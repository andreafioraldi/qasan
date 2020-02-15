# QASan (QEMU-AddressSanitizer)

> Written and maintaned by Andrea Fioraldi <andreafioraldi@gmail.com>

QASan is a custom QEMU 3.1.1 that detects memory errors in the guest using clang's AddressSanitizer.

Dowload it with:

```
git clone --recursive https://github.com/andreafioraldi/qasan.git
```

## Build

QASan comes in two possible twists, one based on my own ASan implementation and the other on the clang's implementation of ASan.

`build.py` is the script used to build all.

The flag `--system` allows you to build full-system QASan, an experimental feature ATM.

### asan-giovese

asan-giovese is my implementation of AddressSanitizer. It is in pure C99 and allows
you to get useful informations from the target process like stacktraces on allocations
and on errors.

It will be the only supported option in future, but at the moment is not already completely thread safe.

This is the default mode, built when you don't specify the `--asan-dso` flag.

### compiler-rt ASan

You need the lief python3 package.

Build using the `build.py` script specifying the path to the ASan DSO.

```
./build.py --asan-dso /path/to/libclang_rt.asan-ARCH.so
```

On Ubuntu 18.04, the path is `/usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so`

Note that QASan will not output meaningful stacktraces or error reports when using this mode.

The reported errors show informaton about the QEMU host and so they are not useful for debugging.

### other options

Other available build options are:

+ `--arch` to specify the target architecture (default is x86_64)
+ `--cc` and `--cxx` to specify C and C++ compilers (default clang-8)
+ `--cross` to specify the cross C compiler for libqasan
+ `--clean` to clean builded files

Tested only on Ubuntu 18.04 with x86[_64] and arm[64] targets.

## Usage

To simply run a binary under QASan:

`./qasan ./program args...`

To get a verbose debug output of the hooked actions:

`./qasan --verbose ./program args...`

By default, only the main executable memory accesses are instrumented. To enable the instrumentation of all the libraries, use `AFL_INST_LIBS=1`.

Beware that glibc have a lot of assumptions on buffer size and a lot of handwritten magic (see [this](https://twitter.com/andreafioraldi/status/1227635146452541441)).
If you have an error caused by these optimizations you can disable the instrumentation for single functions adding them to [libqasan/uninstrument.c](libqasan/uninstrument.c).

### Fuzzing

To fuzz a binary with QASan and AFL++ use a command similar to the following:

```
~/AFLplusplus/afl-fuzz -U -i in -o out -m none -- python3 ~/qasan/qasan ./program
``` 

It supports all the AFL++ QEMU configurations, `AFL_COMPCOV_LEVEL=2` is higly suggested.

## FAQ

> When I should use QASan?

If your target binary is PIC x86_64, you should before give a try to [retrowrite](https://github.com/HexHive/retrowrite) for static rewriting.

If it fails, or if your binary is for another architecture, QASan is the tool that you want/have to use.

Note that the overhead of AFL++ libdislocator is much lower but it can catch less bugs. This is a short blanket, take your choice.

Another discriminat for the choice is [CompareCoverage](https://andreafioraldi.github.io/articles/2019/07/20/aflpp-qemu-compcov.html). If your target has fuzzing roadblocks, you can use QASan+CompCov to fuzz it with Sanitization and Roadblocks bypassing.

> QEMU segfaults with big endian archs

See https://bugs.launchpad.net/qemu/+bug/1701798, use the workaround described here.

## Performance

Native (slowdown: 1x):

```
$ time /usr/bin/objdump -g -x /usr/bin/objdump
...
real	0m0,058s
user	0m0,010s
sys	0m0,029s
```

QEMU (slowdown: 2.4x):

```
$ time qemu-x86_64 /usr/bin/objdump -g -x /usr/bin/objdump
...
real	0m0,141s
user	0m0,096s
sys	0m0,020s
```

QASan (slowdown: 3.6x):

```
$ time ./qasan /usr/bin/objdump -g -x /usr/bin/objdump
...
real	0m0,209s
user	0m0,120s
sys	0m0,032s
```

Valgrind (slowdown: 17.4x):

```
$ time valgrind /usr/bin/objdump -g -x /usr/bin/objdump
...
real	0m1,009s
user	0m0,921s
sys	0m0,076s
```

