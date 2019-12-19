# QASan (QEMU-AddressSanitizer)

QASan is a custom QEMU 3.1.1 that detects memory errors in the guest using clang's AddressSanitizer.

## Build

Tested only on Ubuntu 18.04 with clang-8 installed.

You need the lief python3 package.

Build using the `build.py` script specifying the path to the ASan DSO.


```
./build.py --asan-dso /path/to/libclang_rt.asan-ARCH.so
```

On Ubuntu 18.04, the path is `/usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so`

Other available options are:

+ `--arch` to specify the target architecture (default is x86_64)
+ `--cc` and `--cxx` to specify C and C++ compilers (default clang-8)
+ `--cross` to specify the cross C compiler for libqasan
+ `--clean` to clean builded files

ATM, the supported architectures are x86, x86_64, arm and arm64.

## Usage

To simply run a binary under QASan:

`./qasan ./program args...`

To get a verbose debug output of the hooked actions:

`./qasan --verbose ./program args...`

Note that QASan will not output meaningful stacktraces or error reports.

The reported errors show informaton about the QEMU host and so they are not useful for debugging, I suggest to use Valgrind instead.

As the main use case is fuzzing and the advantage over other binary-level memory checkers is the speed, they are not really needed.

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

No that the overhead of AFL++ libdislocator is much lower but it can catch less bugs. This is a short blanket, take your choice.

Another discriminat for the choice is [CompareCoverage](https://andreafioraldi.github.io/articles/2019/07/20/aflpp-qemu-compcov.html). If your target has fuzzing roadblocks, you can use QASan+CompCov to fuzz it with Sanitization and Roadblocks bypassing.

> QEMU segfaults with big endian archs

See https://bugs.launchpad.net/qemu/+bug/1701798, use the workaround described here.

> MIPS doesn't work!

Only MIPS64 is supported ATM, there are issues with the compatibility of the address spaces between MIPS and x86.

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

