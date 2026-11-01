# Host-side FDX-B modulator test (no ARM toolchain needed).
LF := $(abspath ..)
CFLAGS := -std=gnu11 -O1 -Wall -Wno-unused -Istubs -I$(LF) -I$(LF)/protocols -I$(LF)/..

test_fdxb_modulator: test_fdxb_modulator.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: test clean
test: test_fdxb_modulator
	./test_fdxb_modulator

clean:
	rm -f test_fdxb_modulator
