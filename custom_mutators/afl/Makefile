PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
        -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
        -DBIN_PATH=\"$(BIN_PATH)\"

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl -lm
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: afl-mutator.so havoc
clean:
	rm -rf *.o *.so havoc

afl-mutator.so.o: afl-mutator.so.c $(COMM_HDR)
	$(CC) -fPIC $(CFLAGS) -c afl-mutator.so.c -o $@

afl-mutator.so: afl-mutator.so.o
	$(CC) -shared -fPIC $(CFLAGS) $@.o -o $@ $(LDFLAGS)

havoc: havoc.c $(COMM_HDR) afl-mutator.so.o
	$(CC) $(CFLAGS) $@.c afl-mutator.so.o -o $@ $(LDFLAGS)