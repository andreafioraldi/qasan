/*******************************************************************************
Copyright (c) 2019-2020, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include "libqasan.h"

int __qasan_debug;

// void* __qasan_backdoor(int a, void* b, void* c, void* d) { return NULL; }

void __libqasan_print_maps(void) {

  int fd = open("/proc/self/maps", O_RDONLY);
  char buf[4096] = {0};
  
  read(fd, buf, 4095);
  close(fd);

  size_t len = strlen(buf);

  QASAN_LOG("Guest process maps:\n");
  int i;
  char * line = NULL;
  for (i = 0; i < len; i++) {
    if (!line) line = &buf[i];
    if (buf[i] == '\n') {
      buf[i] = 0;
      QASAN_LOG("%s\n", line);
      line = NULL;
    }
  }
  if (line) QASAN_LOG("%s\n", line);
  QASAN_LOG("\n");

}

__attribute__((constructor)) void __libqasan_init() {

  __libqasan_init_hooks();
  
  __qasan_debug = getenv("QASAN_DEBUG") != NULL;

  QASAN_LOG("QEMU-AddressSanitizer (v%s)\n", QASAN_VERSTR);
  QASAN_LOG("Copyright (C) 2019-2020 Andrea Fioraldi <andreafioraldi@gmail.com>\n");
  QASAN_LOG("\n");

  if (__qasan_debug)
    __libqasan_print_maps();

}
