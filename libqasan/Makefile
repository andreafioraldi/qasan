CC := clang-8
CFLAGS += -Wno-int-to-void-pointer-cast -ggdb
LDFLAGS += -ldl

SRC := libqasan.c hooks.c malloc.c
HDR := libqasan.h

all: arch_x86_64

arch_i386: $(HDR) $(SRC) backdoor_i386.s
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) backdoor_i386.s -o libqasan.so $(LDFLAGS)

arch_x86_64: $(HDR) $(SRC) backdoor_x86_64.s
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) backdoor_x86_64.s -o libqasan.so $(LDFLAGS)

arch_other: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

