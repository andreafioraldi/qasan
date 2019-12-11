# QASAN (QEMU AddressSanitizer)

QASAN is a custom QEMU 3.1.1 that detects memory errors in the guest using clang's AddressSanitizer.

# Build

You need Ubuntu 18.04 and the clang-8 package installed.

You need also the lief python3 package.

Generate a patched ASAN DSO doing:

```
python3 patch_asan_dso.py /path/to/libclang_rt.asan-x86_64.so
```

On Ubuntu 18.04, the path is `/usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so`

Then run `./build.sh`.

# Usage

To simply run a binary under QASAN:

`./qasan ./program args...`

To get a verbose debug output of the hooked actions:

`./qasan --verbose ./program args...`
