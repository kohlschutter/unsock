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
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define UNSOCK_WRAP_SYM(sym) unsock_ ## sym = resolveSymbol( #sym )
static void* resolveSymbol(char *symbol) {
    void* resolved = dlsym(RTLD_NEXT, symbol);
    if(resolved == NULL) {
        fprintf(stderr, "unsock: Could not resolve symbol: %s\n", symbol);
    }
    return resolved;
}

static int (*unsock_socket)(int, int, int);
static int (*unsock_bind)(int, const struct sockaddr *, socklen_t);
static int (*unsock_connect)(int, const struct sockaddr *, socklen_t);
static int (*unsock_listen)(int, int);
static int (*unsock_accept)(int, const struct sockaddr *, socklen_t *);
static int (*unsock_accept4)(int, const struct sockaddr *, socklen_t *, int);
static int (*unsock_getsockname)(int, const struct sockaddr *, socklen_t *);
static int (*unsock_getpeername)(int, const struct sockaddr *, socklen_t *);
static int (*unsock_getsockopt)(int, int, int,void *, socklen_t *optlen);
static int (*unsock_setsockopt)(int, int, int, const void *, socklen_t);
static int (*unsock_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static int (*unsock_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static int (*unsock_shutdown)(int,int);

static struct sockaddr_un addrTemplate = {0};
static const size_t SUN_PATH_LEN = sizeof(struct sockaddr_un) - (size_t) (((struct sockaddr_un *) 0)->sun_path);
static const int FILE_LENGTH_MAX = 1 /* / */ + 5 /* 65536 */ + 5 /* .sock */ + 1 /* always zero-terminated */;

static _Thread_local unsigned int seed;

static bool accept_convert_all = false;
static bool accept_convert_vsock = false;

static bool block_inet6 = false;

static in_addr_t covered_addr = 0x7faf0000;
static int covered_bitmask = 32;

static int32_t covered_port = -1; // -1 means "any"

static int32_t set_mode = -1; // -1 means "don't"

static bool checkEnvBool(char *key) {
    char *val = getenv(key);
    return (val && val[0] == '1' && val[1] == 0);
}

CK_VISIBILITY_INTERNAL char* getenv_unsock(char *key) {
    char *val = getenv(key);
    if(val && val[0] != 0) {
        return val;
    } else {
        return NULL;
    }
}

static bool is_addr_covered(in_addr_t addr, in_port_t port) {
    if(covered_port != -1 && port != covered_port) {
        return false;
    }
    if(covered_bitmask == 0) {
        return true;
    } else if (covered_bitmask == 32) {
        return addr == covered_addr;
    } else {
        in_addr_t mask = ~((((in_addr_t)1 << (32-covered_bitmask))-1));
        return (addr & mask) == (covered_addr & mask);
    }
}

static void __attribute__((constructor)) unsock_init(void) {
    char *sockDir = getenv_unsock("UNSOCK_DIR");
    if(!sockDir) {
        fprintf(stderr, "unsock: (fatal error) UNSOCK_DIR not set\n");
        exit(1);
    }
    if(sockDir[0] != '/') {
        fprintf(stderr, "unsock: (fatal error) UNSOCK_DIR must be an absolute path\n");
        exit(1);
    }
    mkdir(sockDir, 0755);

    const int maxLen =  SUN_PATH_LEN - FILE_LENGTH_MAX;
    strncpy((char*)&addrTemplate.sun_path, sockDir, maxLen);
    if(addrTemplate.sun_path[maxLen-1] != 0) {
        fprintf(stderr, "unsock: (fatal error) UNSOCK_DIR path too long\n");
        exit(1);
    }

    UNSOCK_WRAP_SYM(socket);
    UNSOCK_WRAP_SYM(bind);
    UNSOCK_WRAP_SYM(listen);
    UNSOCK_WRAP_SYM(accept);
    UNSOCK_WRAP_SYM(accept4);
    UNSOCK_WRAP_SYM(connect);
    UNSOCK_WRAP_SYM(getsockname);
    UNSOCK_WRAP_SYM(getpeername);
    UNSOCK_WRAP_SYM(getsockopt);
    UNSOCK_WRAP_SYM(setsockopt);
    UNSOCK_WRAP_SYM(recvfrom);
    UNSOCK_WRAP_SYM(sendto);
    UNSOCK_WRAP_SYM(shutdown);

    seed = (int)(long)(&unsock_init);

    char *coveredAddrStr = getenv_unsock("UNSOCK_ADDR");
    if(coveredAddrStr) {
        union {
            in_addr_t addr;
            char bytes[4];
        } ipaddr = {0};

        signed char bitmask = 32;
        int parts;
        if((parts = sscanf(coveredAddrStr, "%hhd.%hhd.%hhd.%hhd/%hhd",
                  &ipaddr.bytes[0], &ipaddr.bytes[1], &ipaddr.bytes[2], &ipaddr.bytes[3], &bitmask)) >= 4
           && (parts == 4 || (bitmask >= 0 && bitmask <= 32))) {
            covered_addr = ntohl(ipaddr.addr);
            if(parts == 5) {
                covered_bitmask = bitmask;
            } else {
                covered_bitmask = 32;
            }
        } else {
            fprintf(stderr, "unsock: Cannot parse UNSOCK_ADDR: %s\n", coveredAddrStr);
        }
    }

    char *coveredPortStr = getenv_unsock("UNSOCK_PORT");
    if(coveredPortStr) {
        int32_t port;
        if(sscanf(coveredPortStr, "%d", &port) == 1 && port >= -1 && port < 65536) {
            covered_port = port;
        } else {
            fprintf(stderr, "unsock: Cannot parse UNSOCK_PORT: %s\n", coveredPortStr);
        }
    }

    char *setModeStr = getenv_unsock("UNSOCK_MODE");
    if(setModeStr) {
        int32_t mode;
        if(sscanf(setModeStr, "%o", &mode) == 1 && mode >= 0 && mode < 01000) {
            set_mode = mode;
        } else {
            fprintf(stderr, "unsock: Cannot parse UNSOCK_MODE: %s\n", setModeStr);
        }
    }

    accept_convert_all = checkEnvBool("UNSOCK_ACCEPT_CONVERT_ALL");
    accept_convert_vsock = checkEnvBool("UNSOCK_ACCEPT_CONVERT_VSOCK");

    block_inet6 = checkEnvBool("UNSOCK_BLOCK_INET6");
}

int CK_VISIBILITY_DEFAULT socket(int domain, int type, int protocol) {
    if(unsock_socket == NULL) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if(domain == AF_INET6 && block_inet6) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    return unsock_socket(domain,type,protocol);
}

static _Bool isUnsockAddress(const struct sockaddr_un* addr_un) {
    if(addr_un->sun_family != AF_UNIX) {
        return false;
    }
    if(strncmp(addrTemplate.sun_path, addr_un->sun_path, strlen(addrTemplate.sun_path)) == 0) {
        // a socket in our directory -- good enough to delete upon shutdown
        // FIXME check filename
        return true;
    } else {
        return false;
    }
}

static _Bool isUnsockFd(int sockfd, struct sockaddr_un *addr, socklen_t *len) {
    if(unsock_getsockname(sockfd, (struct sockaddr*)addr, len) == 0
       && addr->sun_family == AF_UNIX) {
        return isUnsockAddress(addr);
    } else {
        return false;
    }
}

static void set_unsock_param(int fd, unsock_param_t *param) {
    if(param == NULL) {
        return;
    }

    switch(param->group) {
        case SOL_SOCKET:
            switch(param->key) {
                case SO_RCVTIMEO:
                case SO_SNDTIMEO:
                    setsockopt(fd, param->group, param->key,
                               &param->value.timeval, sizeof(struct timeval));

                    return;
            }
            break;
        case SOL_TIPC:
            switch(param->key) {
                case TIPC_GROUP_JOIN:
                    setsockopt(fd, param->group, param->key,
                               &param->value.tipc_group_req, sizeof(struct tipc_group_req));
                    return;
            }
            break;
    }

    // try 32-bit integer as fallback
    setsockopt(fd, param->group, param->key, &param->value.int32, sizeof(int32_t));
}

static int fixSockfd(int sockfd, sa_family_t desiredDomain, struct unsock_socket_info *si) {
    int ret;

    int domain = 0;
    socklen_t len;

    len = sizeof(domain);
    ret = unsock_getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &domain, &len);
    if(ret != 0) return -1;

    if(domain == desiredDomain) {
        // nothing to fix
        return 0;
    }

    switch(domain) {
        case AF_UNIX:
        case AF_INET:
            // see below;
            break;
        default:
            // don't fix
            return 0;
    }

    int type = 0;
    len = sizeof(type);
    ret = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &len);
    if(ret != 0) return -1;

    int protocol = 0;
    len = sizeof(protocol);
    ret = getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, &protocol, &len);
    if(ret != 0) return -1;

    int options = (protocol & (SOCK_NONBLOCK | SOCK_CLOEXEC));

    if(desiredDomain != AF_INET) {
        switch(protocol) {
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
            case IPPROTO_UDPLITE:
                protocol = 0;
                break;
        }
    }

    struct timeval rcvtimeo = {0};
    len = sizeof(rcvtimeo);
    ret = getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeo, &len);
    if(ret != 0) return -1;
    struct timeval sndtimeo = {0};
    len = sizeof(sndtimeo);
    ret = getsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo, &len);
    if(ret != 0) return -1;

    int oldfd = socket(desiredDomain, type, protocol | options);
    if(oldfd < 0) {
        return -1;
    }

    setsockopt(oldfd, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo));
    setsockopt(oldfd, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo, sizeof(sndtimeo));

    if(si != NULL) {
        for(int i=0;i<4;i++) {
            unsock_param_t *param = &si->parameters[i];
            if(param->group != 0 && param->key != 0) {
                set_unsock_param(oldfd, param);
            }
        }
    }

    ret = dup3(oldfd, sockfd, options & O_CLOEXEC);
    if(ret < 0) {
        return -1;
    }

    if(ret != sockfd) {
        close(sockfd);
        close(ret);
        errno = ENETDOWN;
        return -1;
    }

    return 0;
}

static int checkFixAddr(const struct sockaddr *addr, socklen_t addrlen) {
    if(addr->sa_family == AF_INET) {
        if(addrlen != sizeof(struct sockaddr_in)) {
#if DEBUG
            fprintf(stderr, "unexpected addrlen %i vs %li\n", addrlen, sizeof(struct sockaddr_in));
#endif
            return 1;
        }
        struct sockaddr_in *inAddr = (struct sockaddr_in *)addr;

        uint32_t addrNative = ntohl(inAddr->sin_addr.s_addr);
        in_port_t portNative = ntohs(inAddr->sin_port);

#if DEBUG
        fprintf(stderr ,"port %i addr %08x\n", portNative, addrNative);
        fflush(stderr);
#endif

        return is_addr_covered(addrNative, portNative) ? 0 : 1;
    }
    return 1;
}

static int fixAddr(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                   int (*fun)(int, const struct sockaddr *, socklen_t)) {
    if(addr->sa_family == AF_INET && checkFixAddr(addr, addrlen) == 0) {
        if(fixSockfd(sockfd, AF_UNIX, NULL) != 0) {
            return -1;
        }

        struct sockaddr_in *inAddr = (struct sockaddr_in *)addr;
        struct sockaddr_un unAddr = {
            .sun_family = AF_UNIX
        };
        strncpy(unAddr.sun_path, addrTemplate.sun_path, SUN_PATH_LEN);

        int offset = strlen(addrTemplate.sun_path);
        int ret = snprintf(unAddr.sun_path + offset,
                           SUN_PATH_LEN - offset, "/%i.sock", ntohs(inAddr->sin_port));

        if(ret < 0) {
            errno = EACCES;
            return -1;
        }

        if(fun != NULL) {
            return fun(sockfd, (struct sockaddr*)&unAddr, sizeof(unAddr));
        } else if(addrlen >= sizeof(unAddr)) {
            memcpy((void*)addr, &unAddr, sizeof(unAddr));
            return 0;
        } else {
            errno = EACCES;
            return -1;
        }
    } else {
        return fun == NULL ? 0 : fun(sockfd, addr, addrlen);
    }
}

static int unfixAddr(int sockfd, struct sockaddr * addr,
                     socklen_t * addrlen, int flags,
                     int (*fun)(int, const struct sockaddr *, socklen_t *,int)) {
    struct sockaddr *tmpBuf;
    struct sockaddr *buf;
    size_t addrMax = *addrlen;

    if(*addrlen < sizeof(struct sockaddr_un) && (fun != NULL
                                                 || flags < (signed)sizeof(struct sockaddr_un))) {
        tmpBuf = calloc(1, sizeof(struct sockaddr_un));
        *addrlen = sizeof(struct sockaddr_un);
        buf = tmpBuf;
    } else {
        tmpBuf = NULL;
        buf = addr;
    }

    int ret = fun == NULL ? 0 : fun(sockfd, buf, addrlen, flags);
    if(ret < 0) {
        goto end;
    }

    bool convert = accept_convert_all && buf->sa_family != AF_INET;
    if(!convert) {
        switch(buf->sa_family) {
            case AF_VSOCK:
                if(accept_convert_vsock) {
                    convert = true;
                }
                break;
            default:
                break;
        }
    }

    if(convert) {
        memset(buf, 0, sizeof(struct sockaddr_in));
        *addrlen = sizeof(struct sockaddr_in);
        buf->sa_family = AF_INET;

        struct sockaddr_in *in = (struct sockaddr_in *)buf;
        in->sin_addr.s_addr = htonl(covered_addr);
        if(covered_port != -1) {
            in->sin_port = htons(covered_port);
        }

        goto end;
    }

    if(buf->sa_family != AF_UNIX) {
        goto end;
    }

    struct sockaddr_un *addr_un = (struct sockaddr_un *)buf;
    int port = 0;

    if(!isUnsockAddress(addr_un)) {
        // some other AF_UNIX socket

        struct sockaddr_un addr = {0};
        socklen_t len = sizeof(addr);

#if DONT_FIX_RECEIVED_AF_UNIX_ADDRESSES
        goto end;
#else
        if(isUnsockFd(sockfd, &addr, &len)) {
            // one of our sockets -> the caller expects struct sockaddr_in
            // let's use port 0 for now
            // FIXME: we'd need to track this non-unsock AF_UNIX address by providing a fake port
            goto after_loop;
        } else {
            // some other Unix socket -> the caller expects struct sockaddr_un
            goto end;
        }
#endif
    }

    // handle our socket
    int offset = strlen(addrTemplate.sun_path);
    char *path = addr_un->sun_path + offset;
    if(path[0] != '/') {
        // unexpected
        errno = ENOBUFS;
        ret = -1;
        goto end;
    }
    ++path;
    char c;
    int numDigits = 0;
    while((c = *path) != 0) {
        ++path;
        switch(c) {
            case '.':
                // FIXME validate suffix
                goto after_loop;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                if(++numDigits > 5) {
                    // unexpected
                    errno = ENOBUFS;
                    ret = -1;
                    goto end;
                }
                port = port * 10 + (c-'0');
                break;
            default:
                // unexpected
                errno = ENOBUFS;
                ret = -1;
                goto end;
        }
    }

after_loop:
    *addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in *inAddr = (struct sockaddr_in *)buf;
    inAddr->sin_family = AF_INET;
    inAddr->sin_port = htons(port);
    inAddr->sin_addr.s_addr = htonl(covered_addr);

end:
    if(ret >= 0 && buf == tmpBuf) {
        size_t len = *addrlen;
        if(addrMax < len) {
            len = addrMax;
        }
        memcpy(addr, tmpBuf, len);
    }

    if(tmpBuf != NULL) {
        free(tmpBuf);
    }
    return ret;
}

static int better_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = unsock_bind(sockfd, addr, addrlen);
    if(ret == -1 && errno == EADDRINUSE && addr->sa_family == AF_UNIX
       && addrlen >= sizeof(struct sockaddr_un)) {
        struct sockaddr_un *addr_un = (struct sockaddr_un *)addr;
        if(isUnsockAddress(addr_un)) {
            // check if socket file is stale. if so, remove it and try again
            // FIXME: handle SOCK_DGRAM, etc.
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            int ret2 = connect(fd, addr, addrlen);
            if(ret2 == -1 && errno == ECONNREFUSED) {
                // FIXME ensure this is zero-terminated
                unlink(addr_un->sun_path);
                ret = unsock_bind(sockfd, addr, addrlen);
                if(ret == 0) {
                    close(fd);
                    goto success;
                }
            }
            close(fd);
            ret = -1;
            errno = EADDRINUSE;
        }
    }
    if(ret == 0) {
        goto success;
    }
    return ret;
success:
    struct sockaddr_un *addr_un = (struct sockaddr_un *)addr;
    if(set_mode != -1 && addr->sa_family == AF_UNIX && isUnsockAddress(addr_un)) {
        chmod(addr_un->sun_path, set_mode);
    }
    return 0;
}

static int bindRandomPort(int sockfd, struct sockaddr_in *addr, socklen_t addrlen) {
    int portBase = (rand_r(&seed) % 65536);
    int port = 0;

    char path[SUN_PATH_LEN + 1];
    memset(path, 0, SUN_PATH_LEN + 1);
    const int offset = strlen(addrTemplate.sun_path);
    strncpy(path, (char*)&addrTemplate.sun_path, SUN_PATH_LEN);

    int ret;
    for(int i=0;i<65536;i++) {
        port = (portBase + i) % 65536;
        if(port == 0) {
            memset(path + offset, 0, SUN_PATH_LEN - offset);
            continue;
        }

        ret = snprintf(path + offset, SUN_PATH_LEN - offset, "/%i.sock", port);
        if(ret < 0) {
            // unexpected
            errno = EACCES;
            return -1;
        }

        if(access(path, F_OK) == 0) {
            // file exists
            continue;
        }
        if(errno != ENOENT) {
            // some other error occurred
            return -1;
        }

        addr->sin_port = htons(port);

        ret = fixAddr(sockfd, (struct sockaddr*)addr, addrlen, better_bind);
        if(ret == 0) {
            // bind successful
            return 0;
        } else if(errno == EADDRINUSE) {
            // concurrent bind on desired port
            continue;
        } else {
            // some other error occurred
            return -1;
        }
    }

    errno = EADDRINUSE;
    return -1;
}

static struct unsock_socket_info* load_unsock_socket_info(const struct sockaddr *addr,
                                                          socklen_t addrlen) {
    if(addr == NULL || addrlen < sizeof(struct sockaddr_un) || addr->sa_family != AF_UNIX) {
        return NULL;
    }

    struct sockaddr_un *unaddr = (struct sockaddr_un *)addr;

    struct stat st;

    char *sockFile = unaddr->sun_path;

    size_t maxLen = sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path);
    size_t filenameLen = strnlen(unaddr->sun_path, maxLen);

    char *sockFileCopy;
    if(filenameLen == maxLen) {
        sockFileCopy = calloc(1, maxLen+1);
        memcpy(sockFileCopy, sockFile, filenameLen);
        sockFile = sockFileCopy;
    } else {
        sockFileCopy = NULL;
    }

    int ret = stat(sockFile, &st);
    if(ret == -1 || !S_ISREG(st.st_mode) || st.st_size != sizeof(struct unsock_socket_info)) {
        // not our business
        free(sockFileCopy);
        return NULL;
    }

    int fd = open(sockFile, O_RDONLY);
    free(sockFileCopy);
    if(fd == -1) {
        return NULL;
    }

    struct unsock_socket_info *si = malloc(sizeof(struct unsock_socket_info));

    ssize_t r = read(fd, si, sizeof(struct unsock_socket_info));
    if(r == -1 || r != sizeof(struct unsock_socket_info) ||
       si->magicHeader != UNSOCK_SOCKET_INFO_MAGIC) {
        free(si);
        return NULL;
    } else {
        return si;
    }
}

static int proxy_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct unsock_socket_info *si = load_unsock_socket_info(addr, addrlen);
    if(si == NULL) {
        int ret = better_bind(sockfd, addr, addrlen);
        free(si);
        return ret;
    } else if((si->options & UNSOCK_SOCKET_INFO_OPT_FIRECRACKER_PROXY) != 0) {
        // cannot bind here
        free(si);
        errno = EINVAL;
        return -1;
    } else if(si->proxyLen == 0 && si->options == 0) {
        int ret;
        ret = fixSockfd(sockfd, si->dest.addr.sa_family, si);
        if(ret == 0) {
            ret = better_bind(sockfd, &si->dest.addr, si->destLen);
        }
        free(si);
        return ret;
    } else {
        // unknown proxy forward
        free(si);
        errno = EINVAL;
        return -1;
    }
}

CK_VISIBILITY_DEFAULT int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(unsock_bind == NULL) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    struct sockaddr_in *inAddr = (struct sockaddr_in *)addr;

    if(addr->sa_family == AF_INET
       && addrlen >= sizeof(struct sockaddr_in) && inAddr->sin_port == 0) {

        int ret = fixSockfd(sockfd, AF_UNIX, NULL);
        if(ret < 0) {
            return -1;
        }

        ret = bindRandomPort(sockfd, inAddr, addrlen);
        return ret;
    } else {
        return fixAddr(sockfd, addr, addrlen, proxy_bind);
    }
}

static int firecracker_proxy_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                                     uint32_t svmPort) {
    int ret = unsock_connect(sockfd, addr, addrlen);
    if(ret < 0) {
        return ret;
    }

    char buf[20];
    ssize_t n = snprintf(buf, sizeof(buf), "CONNECT %i\n", svmPort);
    if(n < 0) {
        close(sockfd);
        errno = EINVAL;
        return -1;
    }

    ret = send(sockfd, buf, n, 0);
    if(ret == -1) {
        int err = errno;
        close(sockfd);
        errno = err;
        return -1;
    } else if(ret != n) {
        goto close_fail;
    }

    for(int i=0;i<15;i++) {
        ssize_t r = recv(sockfd, buf, 1, 0);
        if(r == -1) {
            int err = errno;
            close(sockfd);
            errno = err;
            return -1;
        } else if(r != 1) {
            goto close_fail;
        }
        bool ok = false;
        switch(i) {
            case 0:
                ok = (buf[0] == 'O');
                break;
            case 1:
                ok = (buf[0] == 'K');
                break;
            case 2:
                ok = (buf[0] == ' ');
                break;
            default:
                if(buf[0] == '\n') {
                    goto endloop;
                }
                ok = true;
        }
        if(!ok) {
            goto close_fail;
        }
    }
endloop:
    if(buf[0] != '\n') {
        goto close_fail;
    }

    return 0;
close_fail:
    close(sockfd);
    errno = EINVAL;
    return -1;
}

static int proxy_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct unsock_socket_info *si = load_unsock_socket_info(addr, addrlen);
    if(si == NULL) {
        return unsock_connect(sockfd, addr, addrlen);
    } else if(si->options == UNSOCK_SOCKET_INFO_OPT_FIRECRACKER_PROXY && si->proxy.un.sun_family == AF_UNIX && si->dest.vsock.svm_family == AF_VSOCK) {
        int ret = firecracker_proxy_connect(sockfd, &si->proxy.addr, (socklen_t)si->proxyLen, si->dest.vsock.svm_port);
        free(si);
        return ret;
    } else if(si->proxyLen == 0 && si->options == 0) {
        int ret;
        ret = fixSockfd(sockfd, si->dest.addr.sa_family, si);
        if(ret == 0) {
            ret = unsock_connect(sockfd, &si->dest.addr, si->destLen);
        }
        free(si);
        return ret;
    } else {
        free(si);
        errno = EINVAL;
        return -1;
    }
}

CK_VISIBILITY_DEFAULT int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(unsock_connect == NULL) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return fixAddr(sockfd, addr, addrlen, proxy_connect);
}

CK_VISIBILITY_DEFAULT int listen(int a, int b) {
    if(unsock_listen == NULL) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return unsock_listen(a,b);
}

CK_VISIBILITY_DEFAULT int accept(int sockfd, struct sockaddr * addr,
                                 socklen_t * addrlen) {
    if(unsock_accept == NULL) {
        errno = EPROTO;
        return -1;
    }
    CK_IGNORE_CAST_BEGIN
    return unfixAddr(sockfd, addr, addrlen, 0,
                     (int (*)(int, const struct sockaddr *, socklen_t *,int))unsock_accept);
    CK_IGNORE_CAST_END
}

CK_VISIBILITY_DEFAULT int accept4(int sockfd, struct sockaddr * addr,
                                  socklen_t * addrlen, int flags) {
    if(unsock_accept4 == NULL) {
        if(flags == 0) {
            return accept(sockfd, addr, addrlen);
        }
        errno = EPROTO;
        return -1;
    }
    return unfixAddr(sockfd, addr, addrlen, flags, unsock_accept4);
}

CK_VISIBILITY_DEFAULT int getsockname(int sockfd, struct sockaddr * addr,
                                      socklen_t * addrlen) {
    if(unsock_getsockname == NULL) {
        errno = ENOBUFS;
        return -1;
    }
    CK_IGNORE_CAST_BEGIN
    return unfixAddr(sockfd, addr, addrlen, 0,
                     (int (*)(int, const struct sockaddr *, socklen_t *,int))unsock_getsockname);
    CK_IGNORE_CAST_END
}

CK_VISIBILITY_DEFAULT int getpeername(int sockfd, struct sockaddr * addr,
                                      socklen_t * addrlen) {
    if(unsock_getpeername == NULL) {
        errno = ENOBUFS;
        return -1;
    }
    CK_IGNORE_CAST_BEGIN
    return unfixAddr(sockfd, addr, addrlen, 0,
                     (int (*)(int, const struct sockaddr *, socklen_t *,int))unsock_getpeername);
    CK_IGNORE_CAST_END
}

CK_VISIBILITY_DEFAULT int getsockopt(int sockfd, int level, int optname,
                                     void * optval, socklen_t * optlen) {
    if(unsock_getsockopt == NULL) {
        errno = EINVAL;
        return -1;
    }
    int ret = unsock_getsockopt(sockfd, level, optname, optval, optlen);
    if(optval == NULL || optlen == NULL || *optlen < sizeof(int)) {
        return ret;
    }

    if(ret == -1) {
        // not supported on UNIX sockets
        // FIXME handle other options
        switch(level) {
            case SOL_IP:
                switch(optname) {
                    case IP_MULTICAST_ALL:
                        *(int*)optval = 0;
                        *optlen = sizeof(int);
                        return 0;
                        // FIXME handle other options
                }
                break;
            case SOL_TCP:
                switch(optname) {
                    case TCP_NODELAY:
                        *(int*)optval = 0;
                        *optlen = sizeof(int);
                        return 0;
                    case TCP_KEEPIDLE:
                    case TCP_KEEPINTVL:
                    case TCP_KEEPCNT:
                        *(int*)optval = 1;
                        *optlen = sizeof(int);
                        return 0;
                }
                break;
        }
    } else if(ret == 0) {
        switch(level) {
            case SOL_IP:
                switch(optname) {
                    case SO_DOMAIN:
                        if((*(int*)optval) == AF_UNIX) {
                            struct sockaddr_un addr = {0};
                            socklen_t len = sizeof(addr);

                            if(isUnsockFd(sockfd, &addr, &len)) {
                                *(int*)optval = AF_INET;
                            }
                        }
                        break;
                }
                break;
        }
    }

#if DEBUG
    if(ret != 0) {
        fprintf(stderr, "unsock: getsockopt level:%i opt:%i: err:%i\n", level, optname, errno);
    }
#endif
    return ret;
}

CK_VISIBILITY_DEFAULT int setsockopt(int sockfd, int level, int optname,
                                     const void *optval, socklen_t optlen) {
    if(unsock_setsockopt == NULL) {
        errno = EINVAL;
        return -1;
    }
    int ret = unsock_setsockopt(sockfd, level, optname, optval, optlen);
    if(optval == NULL) {
        return ret;
    }

    if(ret == -1) {
        // not supported on UNIX sockets
        // FIXME handle other options
        switch(level) {
            case SOL_IP:
                switch(optname) {
                    case IP_MULTICAST_ALL:
                        return 0;
                }
                break;
            case SOL_TCP:
                switch(optname) {
                    case TCP_NODELAY:
                    case TCP_KEEPIDLE:
                    case TCP_KEEPINTVL:
                    case TCP_KEEPCNT:
                        return 0;
                }
                break;
        }
    }

#if DEBUG
    if(ret != 0) {
        fprintf(stderr, "unsock: setsockopt level:%i opt:%i val:%i: err:%i\n",
                level, optname, *((int*)optval), errno);
    }
#endif
    return ret;
}

CK_VISIBILITY_DEFAULT ssize_t recvfrom(int sockfd, void * buf, size_t len, int flags,
                                       struct sockaddr * src_addr,
                                       socklen_t * addrlen) {
    if(unsock_recvfrom == NULL) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if(src_addr == NULL || addrlen == NULL) {
        return unsock_recvfrom(sockfd, buf, len, flags, buf, addrlen);
    }

    struct sockaddr *addrBuf = NULL;
    socklen_t addrBufLen = *addrlen;
    if(addrBufLen < sizeof(struct sockaddr_un)) {
        addrBuf = calloc(1, sizeof(struct sockaddr_un));
        addrBufLen = sizeof(struct sockaddr_un);
    } else {
        addrBuf = src_addr;
    }

    int ret = unsock_recvfrom(sockfd, buf, len, flags, addrBuf, &addrBufLen);
    if(ret >= 0) {
        if(addrBuf->sa_family == AF_UNIX) {
            int ret2 = unfixAddr(sockfd, addrBuf, &addrBufLen, sizeof(struct sockaddr_un), NULL);
            if(ret2 != 0) {
                return -1;
            }
            size_t max = *addrlen;
            if(addrBufLen < max) {
                max = addrBufLen;
            }
            memcpy(src_addr, addrBuf, max);
            *addrlen = addrBufLen;
        }
    }

    if(addrBuf != src_addr) {
        free(addrBuf);
    }
    return ret;
}

CK_VISIBILITY_DEFAULT ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                                     const struct sockaddr *dest_addr, socklen_t addrlen) {
    if(unsock_sendto == NULL) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if(dest_addr == NULL || addrlen == 0 || dest_addr->sa_family != AF_INET) {
        return unsock_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    struct sockaddr_un dest = {0};
    memcpy(&dest, dest_addr, addrlen);

    int ret = fixAddr(sockfd, (struct sockaddr*)&dest, sizeof(dest), NULL);
    if(ret < 0) {
        return ret;
    }

    return unsock_sendto(sockfd, buf, len, flags, (struct sockaddr*)&dest, sizeof(dest));
}

CK_VISIBILITY_DEFAULT int shutdown(int sockfd, int how) {
    if(unsock_shutdown == NULL) {
        errno = EINVAL;
        return -1;
    }
    int val;
    socklen_t len = sizeof(val);
    
    if(getsockopt(sockfd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val != 0) {
        struct sockaddr_un addr = {0};
        socklen_t len = sizeof(addr);

        if(isUnsockFd(sockfd, &addr, &len)) {
            unlink(addr.sun_path);
        }
    }

    return unsock_shutdown(sockfd, how);
}
