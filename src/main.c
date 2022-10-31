/*
 * unsock: shim to automatically change AF_INET sockets to AF_UNIX, etc.
 *
 * Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>
 * SPDX-License-Identifier: Apache-2.0
 * See NOTICE and LICENSE for license details.
 */ 
#include "ckmacros.h"

#include "unsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/limits.h>

#define xstr(s) str(s)
#define str(s) #s

// something like "/lib/ld-musl-x86_64.so.1";
const char my_interp[] __attribute__((section(".interp"))) = xstr(INTERP);

static int writeFile(char *sockFile, struct unsock_socket_info *si) {
    int fd = open(sockFile, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if(fd == -1) {
        fprintf(stderr, "Could not open '%s' for writing: %s\n", sockFile, strerror(errno));
        return -1;
    }
    ssize_t written = write(fd, si, sizeof(struct unsock_socket_info));
    if(written == -1) {
        fprintf(stderr, "Could not write: %s: %s\n", sockFile, strerror(errno));
        return -1;
    } else if(written != sizeof(struct unsock_socket_info)) {
        fprintf(stderr, "Error: Unexpected response from write: %li\n", written);
    }
    close(fd);

    return 0;
}

static int createProxyFile(char *sockFile, char *targetFile, int vsockPort) {
    char targetFileAbs[PATH_MAX];
    if(realpath(targetFile, targetFileAbs) == NULL) {
        if(targetFile[0] == '/') {
            fprintf(stderr, "WARNING: UNSOCK_FC_SOCK does not exist: %s\n", targetFile);
        } else {
            fprintf(stderr, "UNSOCK_FC_SOCK does not exist: %s\n", targetFile);
            return -1;
        }
    } else {
        targetFile = targetFileAbs;
    }
    fprintf(stderr, "UNSOCK_FILE: %s\n", sockFile);
    fprintf(stderr, "UNSOCK_FC_SOCK: %s\n", targetFile);
    fprintf(stderr, "UNSOCK_VSOCK_PORT: %i\n", vsockPort);

    size_t targetFileLen = strlen(targetFile);
    if(targetFileLen > sizeof(struct sockaddr_un)-offsetof(struct sockaddr_un, sun_path)) {
        fprintf(stderr, "UNSOCK_FC_SOCK path too long: %s\n", targetFile);
        return -1;
    }

    struct unsock_socket_info si = {0};
    si.magicHeader = UNSOCK_SOCKET_INFO_MAGIC;
    si.options = UNSOCK_SOCKET_INFO_OPT_FIRECRACKER_PROXY;
    si.proxyLen = sizeof(struct sockaddr_un);
    si.destLen = sizeof(struct sockaddr_vm);
    si.proxy.un.sun_family = AF_UNIX;
    memcpy(si.proxy.un.sun_path, targetFile, targetFileLen);

    si.dest.vsock.svm_family = AF_VSOCK;
    si.dest.vsock.svm_cid = VMADDR_CID_ANY; // not used
    si.dest.vsock.svm_port = vsockPort;

    return writeFile(sockFile, &si);
}

static int createVsockFile(char *sockFile, int vsockPort) {
    fprintf(stderr, "UNSOCK_FILE: %s\n", sockFile);
    fprintf(stderr, "UNSOCK_VSOCK_PORT: %i\n", vsockPort);

    struct unsock_socket_info si = {0};
    si.magicHeader = UNSOCK_SOCKET_INFO_MAGIC;
    si.options = 0;
    si.proxyLen = 0;
    si.destLen = sizeof(struct sockaddr_vm);

    si.dest.vsock.svm_family = AF_VSOCK;
    si.dest.vsock.svm_cid = VMADDR_CID_ANY;
    si.dest.vsock.svm_port = vsockPort;

    return writeFile(sockFile, &si);
}

int unsock_main() {
    char *sockFile = getenv("UNSOCK_FILE");
    char *targetFile = getenv("UNSOCK_FC_SOCK");
    char *vsockPortStr = getenv("UNSOCK_VSOCK_PORT");
    int vsockPort = vsockPortStr ? strtol(vsockPortStr, NULL, 10) : 0;
    if(sockFile && targetFile && vsockPort) {
        int ret = createProxyFile(sockFile, targetFile, vsockPort);
        exit(-ret);
    } else if(sockFile && vsockPort) {
        int ret = createVsockFile(sockFile, vsockPort);
        exit(-ret);
    }
fprintf(stderr, "%s\n",
"unsock: shim to automatically change AF_INET sockets to AF_UNIX, etc.\n"
"\n"
"Usage: UNSOCK_DIR=/path/to/sockets LD_PRELOAD=/path/to/libunsock.so target_command\n"
"       Enable libunsock for the given command\n"
"\n"
"       /path/to/sockets := absolute directory where UNIX domain sockets are stored\n"
"       target_command := the target command you want to inject the library into\n"
"\n"
"Call this library as an executable to create control files:\n"
"       UNSOCK_FILE=/path/to/proxy-file UNSOCK_FC_SOCK=/path/to/firecracker-socket UNSOCK_VSOCK_PORT=1234 /path/to/libunsock.so\n"
"       Create a control file to simplify connecting to Firecracker Unix sockets that forward to VSOCK ports\n"
"\n"
"       UNSOCK_FILE=/path/to/proxy-file UNSOCK_VSOCK_PORT=1234 /path/to/libunsock.so\n"
"       Create a control file that allows listening on an VSOCK port (CID=any)\n"
"\n"
"Copyright (C) 2022 Christian Kohlschuetter <christian@kohlschutter.com>\n"
"SPDX-License-Identifier: Apache-2.0\n"
"See NOTICE and LICENSE for license details.\n"
);
exit(0);
}
