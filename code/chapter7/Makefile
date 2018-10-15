CC=gcc
AS=nasm
OBJ=xor_encrypt heapoverflow elfinject heapcheck.so

.PHONY: all clean

all: $(OBJ)

xor_encrypt: xor_encrypt.c
	$(CC) -o xor_encrypt -O2 xor_encrypt.c

heapoverflow: heapoverflow.c
	$(CC) -o heapoverflow -O2 -fno-builtin heapoverflow.c

elfinject: elfinject.c
	$(CC) -o elfinject -O2 elfinject.c -lelf

hello.bin: hello.s
	$(AS) -f bin -o hello.bin hello.s

hello-ctor.bin: hello-ctor.s
	$(AS) -f bin -o hello-ctor.bin hello-ctor.s

hello-got.bin: hello-got.s
	$(AS) -f bin -o hello-got.bin hello-got.s

test_elfinject: elfinject hello.bin
	@cp /bin/ls ./test
	@./elfinject ./test hello.bin ".injected" 0x800000 0
	@./test | grep "hello world!" > /dev/null
	#@rm -f ./test
	@echo "******* ALL TESTS PASSED *******"

heapcheck.so: heapcheck.c
	$(CC) -o heapcheck.so -fPIC -shared -D_GNU_SOURCE heapcheck.c -ldl

clean:
	rm -f $(OBJ)

