CC := clang
CFLAGS += -Wno-int-to-void-pointer-cast -ggdb
LDFLAGS += -ldl -pthread

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

debug: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -DDEBUG=1 -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

