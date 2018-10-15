CC=gcc
CXX=g++
OBJ=overlapping_bb basic_capstone_linear basic_capstone_recursive capstone_gadget_finder

.PHONY: all clean

all: $(OBJ)

loader.o: ../inc/loader.cc
	$(CXX) -std=c++11 -c ../inc/loader.cc

basic_capstone_linear: loader.o basic_capstone_linear.cc
	$(CXX) -std=c++11 -o basic_capstone_linear basic_capstone_linear.cc loader.o -lbfd -lcapstone

basic_capstone_recursive: loader.o basic_capstone_recursive.cc
	$(CXX) -std=c++11 -o basic_capstone_recursive basic_capstone_recursive.cc loader.o -lbfd -lcapstone

capstone_gadget_finder: loader.o capstone_gadget_finder.cc
	$(CXX) -std=c++11 -o capstone_gadget_finder capstone_gadget_finder.cc loader.o -lbfd -lcapstone

overlapping_bb: overlapping_bb.c
	$(CC) -o overlapping_bb overlapping_bb.c

clean:
	rm -f $(OBJ)
	rm -f *.o

