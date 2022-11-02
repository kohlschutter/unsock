# unsock: shim to automatically change AF_INET sockets to AF_UNIX, etc.
#
# Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>
# SPDX-License-Identifier: Apache-2.0
#

LIBUNSOCK_API_VER_MAJOR = 1
LIBUNSOCK_API_VER_MINOR = 1
LIBUNSOCK_API_VER_PATCH = 0

CC ?= cc
EXTRA_CFLAGS ?=
PREFIX ?= /usr/local
INSTALL_LIB_DIR ?= lib

LIBUNSOCK_INSTALL_DIR = $(PREFIX)/$(INSTALL_LIB_DIR)/
LIBUNSOCK_SUFFIX = .so

DEBUG ?= 0
DEBUG_CFLAGS ?=
ifeq ($(DEBUG), 1)
	DEBUG_CFLAGS += -DDEBUG
	LIBUNSOCK_SUFFIX = -debug.so
endif

LIBUNSOCK = libunsock$(LIBUNSOCK_SUFFIX)
LIBUNSOCK_API_VER = $(LIBUNSOCK_API_VER_MAJOR).$(LIBUNSOCK_API_VER_MINOR).$(LIBUNSOCK_API_VER_PATCH)

CFLAGS = -std=c17 -Wall -Wextra -Os $(DEBUG_CFLAGS) $(EXTRA_CFLAGS)

all: $(LIBUNSOCK) clean-postbuild

test-ld:
	$(CC) -o test-ld -shared /dev/null

clean-postbuild:
	@rm -f test-ld

$(LIBUNSOCK): INTERP = `ldd test-ld | grep ".so" | grep -v " => " | tail -n 1 | cut -d'(' -f1|tr -d '\t '`
$(LIBUNSOCK): test-ld src/unsock.c src/main.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -fvisibility=hidden \
		-DINTERP=$(INTERP) \
		-shared -fPIC -e unsock_main \
		-o $(LIBUNSOCK).$(LIBUNSOCK_API_VER) \
		src/unsock.c src/main.c \
		-ldl

install: $(LIBUNSOCK)
	@echo "Installing to $(LIBUNSOCK_INSTALL_DIR)"
	@mkdir -p $(LIBUNSOCK_INSTALL_DIR)
	@cp -v $(LIBUNSOCK).$(LIBUNSOCK_API_VER) $(LIBUNSOCK_INSTALL_DIR)/
	cd $(LIBUNSOCK_INSTALL_DIR)/ ; ln -sf $(LIBUNSOCK).$(LIBUNSOCK_API_VER_MAJOR) $(LIBUNSOCK) ; ln -sf $(LIBUNSOCK).$(LIBUNSOCK_API_VER) $(LIBUNSOCK).$(LIBUNSOCK_API_VER_MAJOR)

uninstall:
	@echo "Uninstalling from $(LIBUNSOCK_INSTALL_DIR)"
	@rm -fv $(LIBUNSOCK_INSTALL_DIR)/$(LIBUNSOCK) $(LIBUNSOCK_INSTALL_DIR)/$(LIBUNSOCK).$(LIBUNSOCK_API_VER_MAJOR) $(LIBUNSOCK_INSTALL_DIR)/$(LIBUNSOCK).$(LIBUNSOCK_API_VER)

test: test_prepare test_nc test_bind0
	@echo "Tests PASS."

test_prepare: $(LIBUNSOCK) clean-postbuild

test_nc: test_prepare
	# Test unsock with "nc", pretending to listen on TCP port 7000 (which will turn into UNIX domain socket test/7000.sock)
	@mkdir -p test
	@rm -f "test/7000.sock" "test/7000.txt"
	UNSOCK_DIR="$(PWD)/test" LD_PRELOAD=./$(LIBUNSOCK).$(LIBUNSOCK_API_VER) nc -l 127.175.0.0 7000 | head -n 1 > test/7000.txt &
	timeout 10s sh -c 'until [ -e "test/7000.sock" ]; do sleep 0.1; done'
	echo "Hello world" | nc -U test/7000.sock
	cat test/7000.txt | grep -q "Hello world"

test_bind0: test_prepare
	# Test binding on port 0 (random/anonymous port)
	@rm -rf test/zero
	@mkdir -p test/zero
	( UNSOCK_DIR="$(PWD)/test/zero" LD_PRELOAD=./$(LIBUNSOCK).$(LIBUNSOCK_API_VER) timeout 1 nc -l 127.175.0.0 0 ) || true
	[ `ls test/zero/*sock | grep -c ".sock"` -eq 1 ]

.PHONY: test_prepare

clean:
	rm -rf libunsock*.so* test
