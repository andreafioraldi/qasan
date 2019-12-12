CC := clang-8

all:
	$(CC) $(CFLAGS) -fPIC -shared -I ../include libqasan.c -o libqasan.so -ldl $(LDFLAGS)
