CC=gcc
OBJ=compilation_example
 
.PHONY: all clean

all: $(OBJ)

compilation_example: compilation_example.c
	$(CC) -E -P compilation_example.c > compilation_example.i
	$(CC) -S -masm=intel compilation_example.c
	$(CC) -c compilation_example.c
	$(CC) compilation_example.c
	cp a.out a.out.stripped
	strip --strip-all a.out.stripped
	@echo
	@echo "******* CREATED FILES *******"
	@echo "compilation_example.i: preprocessed source"
	@echo "compilation_example.s: assembly code"
	@echo "compilation_example.o: object file"
	@echo "a.out                : binary executable"
	@echo "a.out.stripped       : stripped binary executable"
	@echo "******* CREATED FILES *******"
	@echo

clean:
	rm -f *.i *.s *.o a.out a.out.stripped

