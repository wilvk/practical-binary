PIN_HOME=/home/binary/libdft/pin-2.13-61206-gcc.4.4.7-linux
DFT_HOME=/home/binary/libdft/libdft-ng_linux-i386/src

CC           = gcc-4.9
CXX          = g++-4.9
CFLAGS      += -m32 -mno-mmx -mno-sse -mno-sse2 -mno-sse3
CXXFLAGS    += -Wall -Wno-unknown-pragmas                         \
                -c -fomit-frame-pointer -std=c++0x -O3            \
               -fno-strict-aliasing -fno-stack-protector          \
               -DBIGARRAY_MULTIPLIER=1 -DUSING_XED                \
               -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX -m32 
CXXFLAGS_SO += -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared -m32  \
               -Wl,-rpath=$(PIN_HOME)/ia32/runtime/cpplibs	  \
               -Wl,--version-script=$(PIN_HOME)/source/include/pin/pintool.ver
LIBS        += -ldft -lpin -lxed -ldwarf -lelf -ldl
H_INCLUDE   += -I$(DFT_HOME)                                      \
               -I$(PIN_HOME)/source/include/pin                   \
               -I$(PIN_HOME)/source/include/pin/gen               \
               -I$(PIN_HOME)/extras/xed2-ia32/include             \
               -I$(PIN_HOME)/extras/components/include
L_INCLUDE   += -L$(DFT_HOME)                                      \
               -L$(PIN_HOME)/extras/xed2-ia32/lib                 \
               -L$(PIN_HOME)/ia-32/runtime/cpplibs                \
               -L$(PIN_HOME)/ia32/lib -L$(PIN_HOME)/ia32/lib-ext

.PHONY: all clean

all: dta-execve.so dta-dataleak.so execve-test execve-test-overflow execve-test-overflow-implicit dataleak-test dataleak-test-xor date echo

date: date.c
	$(CC) $(CFLAGS) -o date date.c

echo: echo.c
	$(CC) $(CFLAGS) -o echo echo.c

execve-test: execve-test.c
	$(CC) $(CFLAGS) -o execve-test execve-test.c

execve-test-overflow: execve-test-overflow.c
	$(CC) $(CFLAGS) -o execve-test-overflow execve-test-overflow.c

execve-test-overflow-implicit: execve-test-overflow-implicit.c
	$(CC) $(CFLAGS) -o execve-test-overflow-implicit execve-test-overflow-implicit.c

dataleak-test: dataleak-test.c
	$(CC) $(CFLAGS) -o dataleak-test dataleak-test.c

dataleak-test-xor: dataleak-test-xor.c
	$(CC) $(CFLAGS) -o dataleak-test-xor dataleak-test-xor.c

dta-execve.so: dta-execve.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)

dta-execve.o: dta-execve.cpp $(DFT_HOME)/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

dta-dataleak.so: dta-dataleak.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)

dta-dataleak.o: dta-dataleak.cpp $(DFT_HOME)/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

clean:
	rm -f *.o *.so execve-test execve-test-overflow execve-test-overflow-implicit dataleak-test dataleak-test-xor date echo

