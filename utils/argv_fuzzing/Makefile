#
# american fuzzy lop++ - argvfuzz
# --------------------------------
#
# Copyright 2019-2023 Kjell Braden <afflux@pentabarf.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

.PHONY: all install clean argv_fuzz_persistent_demo argv_fuzz_demo demo

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl

CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared

UNAME_SAYS_LINUX=$(shell uname | grep -E '^Linux|^GNU' >/dev/null; echo $$?)
UNAME_SAYS_LINUX:sh=uname | grep -E '^Linux|^GNU' >/dev/null; echo $$?

_LDFLAGS_ADD=$(UNAME_SAYS_LINUX:1=)
LDFLAGS_ADD=$(_LDFLAGS_ADD:0=-ldl)
LDFLAGS  += $(LDFLAGS_ADD)

# on gcc for arm there is no -m32, but -mbe32
M32FLAG = -m32
M64FLAG = -m64

CC_IS_GCC=$(shell $(CC) --version 2>/dev/null | grep -q gcc; echo $$?)
CC_IS_GCC:sh=$(CC) --version 2>/dev/null | grep -q gcc; echo $$?
CC_IS_ARMCOMPILER=$(shell $(CC) -v 2>&1 >/dev/null | grep -q arm; echo $$?)
CC_IS_ARMCOMPILER:sh=$(CC) -v 2>&1 >/dev/null | grep -q arm; echo $$?

_M32FLAG=$(CC_IS_GCC)$(CC_IS_ARMCOMPILER)
__M32FLAG=$(_M32FLAG:00=-mbe32)
___M32FLAG=$(__M32FLAG:$(CC_IS_GCC)$(CC_IS_ARMCOMPILER)=-m32)
M32FLAG=$(___M32FLAG)

all: argvfuzz32.so argvfuzz64.so demo

argvfuzz32.so: argvfuzz.c
	-@$(CC) $(M32FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@ 2>/dev/null || echo "argvfuzz32 build failure (that's fine)"

argvfuzz64.so: argvfuzz.c
	-@$(CC) $(M64FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@ 2>/dev/null || echo "argvfuzz64 build failure (that's fine)"

install: argvfuzz32.so argvfuzz64.so
	install -d -m 755 $(DESTDIR)$(HELPER_PATH)/
	if [ -f argvfuzz32.so ]; then set -e; install -m 755 argvfuzz32.so $(DESTDIR)$(HELPER_PATH)/; fi
	if [ -f argvfuzz64.so ]; then set -e; install -m 755 argvfuzz64.so $(DESTDIR)$(HELPER_PATH)/; fi

argv_fuzz_persistent_demo: argv_fuzz_persistent_demo.c
	../../afl-cc -fsanitize=address -g -o $@ $^

argv_fuzz_demo: argv_fuzz_demo.c
	../../afl-cc -fsanitize=address -g -o $@ $^

demo: argv_fuzz_persistent_demo argv_fuzz_demo

clean:
	rm -f argvfuzz32.so argvfuzz64.so argv_fuzz_demo argv_fuzz_persistent_demo

