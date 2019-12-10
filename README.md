# QASAN (QEMU AddressSanitizer)

QASAN is a custom QEMU 3.1.1 that detects memory errors in the guest using clang's AddressSanitizer.

# Build

You need Ubuntu 18.04 and the clang-8 package installed.

Then run `./build.sh`

# Usage

To simply run a binary under QASAN:

`./qasan ./program args...`

To get a verbose debug output of the hooked actions:

`./qasan --verbose ./program args...`

