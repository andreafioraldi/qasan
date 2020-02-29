CC := clang-8
CFLAGS += -Wno-int-to-void-pointer-cast -ggdb
LDFLAGS += -ldl

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c
HDR := libqasan.h

all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

