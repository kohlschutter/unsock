/*
 * unsock: shim to automatically change AF_INET sockets to AF_UNIX, etc.
 *
 * Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>
 * SPDX-License-Identifier: Apache-2.0
 * See NOTICE and LICENSE for license details.
 */ 
#include "ckmacros.h"

#include <stdio.h>
#include <stdlib.h>

#define xstr(s) str(s)
#define str(s) #s

// something like "/lib/ld-musl-x86_64.so.1";
const char my_interp[] __attribute__((section(".interp"))) = xstr(INTERP);

int unsock_main() {
fprintf(stderr,
"unsock: shim to automatically change AF_INET sockets to AF_UNIX, etc.\n"
"\n"
"Usage: UNSOCK_DIR=path LD_PRELOAD=./libunsock.so target_command\n"
"\n"
"       path := absolute directory where UNIX domain sockets are stored\n"
"       target_command := the target command you want to inject the library into\n"
"\n"
"Copyright (C) 2022 Christian Kohlschuetter <christian@kohlschutter.com>\n"
"SPDX-License-Identifier: Apache-2.0\n"
"See NOTICE and LICENSE for license details.\n"
);
exit(0);
}
