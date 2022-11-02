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

static int createVsockFile(char *sockFile, int vsockPort, int vsockCid) {
    fprintf(stderr, "UNSOCK_FILE: %s\n", sockFile);
    fprintf(stderr, "UNSOCK_VSOCK_PORT: %i\n", vsockPort);
    fprintf(stderr, "UNSOCK_VSOCK_CID: %i\n", vsockCid);

    struct unsock_socket_info si = {0};
    si.magicHeader = UNSOCK_SOCKET_INFO_MAGIC;
    si.options = 0;
    si.proxyLen = 0;
    si.destLen = sizeof(struct sockaddr_vm);

    si.dest.vsock.svm_family = AF_VSOCK;
    si.dest.vsock.svm_cid = vsockCid;
    si.dest.vsock.svm_port = vsockPort;

    return writeFile(sockFile, &si);
}

static int createTipcFile(char *sockFile, char addrtype, char scope, uint32_t type, uint32_t lower, uint32_t upper) {
    fprintf(stderr, "UNSOCK_TIPC_ADDRTYPE: %i\n", (int)addrtype);
    fprintf(stderr, "UNSOCK_TIPC_SCOPE: %i\n", (int)scope);
    fprintf(stderr, "UNSOCK_TIPC_TYPE: %i\n", type);
    fprintf(stderr, "UNSOCK_TIPC_LOWER: %i\n", lower);
    fprintf(stderr, "UNSOCK_TIPC_UPPER: %i\n", upper);

    struct unsock_socket_info si = {0};
    si.magicHeader = UNSOCK_SOCKET_INFO_MAGIC;
    si.options = 0;
    si.proxyLen = 0;
    si.destLen = sizeof(struct sockaddr_tipc);

    si.dest.tipc.family = AF_TIPC;
    si.dest.tipc.addrtype = addrtype;
    si.dest.tipc.scope = scope;
    si.dest.tipc.addr.nameseq.type = type;
    si.dest.tipc.addr.nameseq.lower = lower;
    si.dest.tipc.addr.nameseq.upper = upper;

    return writeFile(sockFile, &si);
}


int unsock_main() {
    char *sockFile = getenv_unsock("UNSOCK_FILE");
    if(sockFile) {
        char *targetFile = getenv_unsock("UNSOCK_FC_SOCK");
        char *vsockPortStr = getenv_unsock("UNSOCK_VSOCK_PORT");
        char *vsockCidStr = getenv_unsock("UNSOCK_VSOCK_CID");

        char *tipcAddrTypeStr = getenv_unsock("UNSOCK_TIPC_ADDRTYPE");
        char *tipcScopeStr = getenv_unsock("UNSOCK_TIPC_SCOPE");
        char *tipcTypeStr = getenv_unsock("UNSOCK_TIPC_TYPE");
        char *tipcLowerStr = getenv_unsock("UNSOCK_TIPC_LOWER");
        char *tipcUpperStr = getenv_unsock("UNSOCK_TIPC_UPPER");

        int vsockPort = vsockPortStr ? strtol(vsockPortStr, NULL, 10) : 0;
        int vsockCid = vsockCidStr ? strtol(vsockCidStr, NULL, 10) : VMADDR_CID_ANY;
        if(targetFile && vsockPort) {
            exit(-createProxyFile(sockFile, targetFile, vsockPort));
        } else if(vsockPort) {
            exit(-createVsockFile(sockFile, vsockPort, vsockCid));
        } else if(tipcAddrTypeStr && tipcScopeStr && tipcTypeStr && tipcLowerStr && tipcUpperStr) {
            char addrtype = (char)strtol(tipcAddrTypeStr, NULL, 10);
            char scope = (char)(strtol(tipcScopeStr, NULL, 10));
            uint32_t type = strtol(tipcTypeStr, NULL, 10);
            uint32_t lower = strtol(tipcLowerStr, NULL, 10);
            uint32_t upper = strtol(tipcUpperStr, NULL, 10);

            exit(-createTipcFile(sockFile, addrtype, scope, type, lower, upper));
        }
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
"\n"
"       UNSOCK_FILE=/tmp/unsockets/2345.sock UNSOCK_FC_SOCK=/path/to/firecracker-vsocket UNSOCK_VSOCK_PORT=1234 /path/to/libunsock.so\n"
"       Create a control file to simplify connecting to Firecracker Unix sockets that forward to VSOCK ports\n"
"\n"
"       UNSOCK_FILE=/tmp/unsockets/2345.sock UNSOCK_VSOCK_PORT=1234 UNSOCK_VSOCK_CID=-1 /path/to/libunsock.so\n"
"       Create a control file that allows listening on an VSOCK port (CID=any)\n"
"\n"
"       UNSOCK_FILE=/tmp/unsockets/5678.sock UNSOCK_TIPC_ADDRTYPE=2 UNSOCK_TIPC_SCOPE=2 \\\n"
"          UNSOCK_TIPC_TYPE=128 UNSOCK_TIPC_LOWER=99 UNSOCK_TIPC_UPPER=0 /usr/local/lib/libunsock.so\n"
"       Create a control file that allows communicating with an TIPC port (service type 128, id 99)\n"
"\n"
"Copyright (C) 2022 Christian Kohlschuetter <christian@kohlschutter.com>\n"
"SPDX-License-Identifier: Apache-2.0\n"
"See NOTICE and LICENSE for license details.\n"
);
exit(0);
}
