PIN_HOME=/home/binary/triton/pin-2.14-71313-gcc.4.4.7-linux
TRITON_HOME=$(PIN_HOME)/source/tools/Triton

CC=gcc-4.9
CXX=g++-4.9
CXXFLAGS=-Wall -Wno-unknown-pragmas -Wno-unused-variable -O2 -std=c++11 -fno-stack-protector -I$(TRITON_HOME)/src/libtriton/includes/ -L$(TRITON_HOME)/build/src/libtriton/

.PHONY: all clean

all: backward_slicing code_coverage branch icall license

loader.o: ../inc/loader.cc
	$(CXX) -std=c++11 -c ../inc/loader.cc

triton_util.o: triton_util.cc
	$(CXX) -std=c++11 -c triton_util.cc

disasm_util.o: disasm_util.cc
	$(CXX) -std=c++11 -c disasm_util.cc

backward_slicing: backward_slicing.cc loader.o triton_util.o disasm_util.o
	$(CXX) $(CXXFLAGS) -o backward_slicing backward_slicing.cc loader.o triton_util.o disasm_util.o -ltriton -lbfd -lcapstone

code_coverage: code_coverage.cc loader.o triton_util.o disasm_util.o
	$(CXX) $(CXXFLAGS) -o code_coverage code_coverage.cc loader.o triton_util.o disasm_util.o -ltriton -lbfd -lcapstone

branch: branch.c
	$(CC) -o branch branch.c

icall: icall.c
	$(CC) -o icall icall.c -lcrypt
	echo "binary" | sudo -S chown root.root icall
	echo "binary" | sudo -S chmod +s icall

license: license.c
	$(CC) -o license license.c

clean:
	rm -f backward_slicing code_coverage branch icall license *.o

