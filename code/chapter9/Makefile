PIN_ROOT=/home/binary/pin/pin-3.6-97554-g31f0a167d-gcc-linux

.PHONY: all clean unpacker profiler

all: packed unpacker profiler

packed: /bin/ls
	cp /bin/ls packed
	upx packed

unpacker: unpacker/makefile unpacker/makefile.rules unpacker/unpacker.cpp
	export PIN_ROOT=$(PIN_ROOT) && cd unpacker && $(MAKE)

profiler: profiler/makefile profiler/makefile.rules profiler/profiler.cpp
	export PIN_ROOT=$(PIN_ROOT) && cd profiler && $(MAKE)

clean:
	rm -f packed
	cd unpacker && rm -rf obj-intel64
	cd profiler && rm -rf obj-intel64

