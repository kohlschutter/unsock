//
//  unsock.h
//  unsock
//

#ifndef unsock_h
#define unsock_h

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/vm_sockets.h>
#include <linux/tipc.h>

#define UNSOCK_SOCKET_INFO_MAGIC 0x4b534e55
#define UNSOCK_SOCKET_INFO_OPT_FIRECRACKER_PROXY 1

typedef struct __attribute__((packed, aligned(4))) {
    uint32_t group;
    uint32_t key;
    union {
        int32_t int32;
        uint32_t uint32;
        int64_t int64;
        uint64_t uint64;
        struct timeval timeval;
        struct tipc_group_req tipc_group_req;
        char bytes[32];
    } value;
} unsock_param_t;

struct __attribute__((packed, aligned(4))) unsock_socket_info {
    uint64_t magicHeader;
    uint64_t options;
    uint32_t proxyLen;
    uint32_t destLen;
    uint32_t optionsCount;
    uint32_t reserved0;

    union {
        struct sockaddr addr;
        struct sockaddr_un un;
        char bytes[128];
    } proxy;

    union {
        struct sockaddr addr;
        struct sockaddr_un un;
        struct sockaddr_vm vsock;
        char bytes[128];
    } dest;

    unsock_param_t parameters[4];

    uint32_t reserved1;
};

#endif /* unsock_h */
