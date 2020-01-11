CC := clang-8

arch_i386:
	$(CC) $(CFLAGS) -fPIC -shared -I ../include libqasan.c backdoor_i386.s -o libqasan.so -ldl $(LDFLAGS)

arch_x86_64:
	$(CC) $(CFLAGS) -fPIC -shared -I ../include libqasan.c backdoor_x86_64.s -o libqasan.so -ldl $(LDFLAGS)

arch_other:
	$(CC) $(CFLAGS) -fPIC -shared -I ../include libqasan.c -o libqasan.so -ldl $(LDFLAGS)

