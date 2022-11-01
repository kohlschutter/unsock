# [unsock](../README.md) usage examples

## iperf

### iperf via `AF_VSOCK` between a Firecracker hypervisor and its guest, server running in guest

On the guest, run the following command to create a direct `AF_VSOCK` control file:

    mkdir -p /tmp/unsockets
    UNSOCK_FILE=/tmp/unsockets/3000.sock \
        UNSOCK_VSOCK_PORT=1234 \
        /path/to/libunsock.so

... and start the iperf server

     UNSOCK_ADDR=127.0.0.1/0 \
         UNSOCK_ACCEPT_CONVERT_VSOCK=1 \
         UNSOCK_DIR=/tmp/unsockets \
         LD_PRELOAD=/path/to/libunsock.so \
         iperf -s -B 127.0.0.1 -p 3000 -i 1    

On the host, run the following command to create a Firecracker-compatible control file:

    mkdir -p /tmp/unsockets
    UNSOCK_FILE=/tmp/unsockets/2000.sock \
        UNSOCK_FC_SOCK=/path/to/firecracker/vsock \
        UNSOCK_VSOCK_PORT=1234 \
        /path/to/libunsock.so 

... and start the iperf client

    UNSOCK_ADDR=127.175.0.0/32 \
        UNSOCK_DIR=/tmp/unsockets/ \
        LD_PRELOAD=/path/to/libunsock.so \
        iperf -c 127.175.0.0 -p 2000 -i 1
 

### iperf via `AF_VSOCK` between a Firecracker hypervisor and its guest, server running on host

On the host, run the following command to link  a Firecracker-compatible Unix domain socket

    mkdir -p /tmp/unsockets
    ln -s /tmp/unsockets/4000.sock /path/to/firecracker/vsock_5678 

... and start the iperf server

    UNSOCK_ADDR=127.0.0.1/0 \
        UNSOCK_DIR=/tmp/unsockets/ \
        LD_PRELOAD=/path/to/libunsock.so \
        iperf -s -B 127.0.0.1 -p 4000 -i 1
        
On the guest, run the following command to create a direct `AF_VSOCK` control file that points back
to the host (CID=2), port 5678.

    mkdir -p /tmp/unsockets
    UNSOCK_FILE=/tmp/unsockets/5000.sock \
        UNSOCK_VSOCK_PORT=5678 \
        UNSOCK_VSOCK_CID=2 \
        /path/to/libunsock.so 

... then start the iperf client

    UNSOCK_ADDR=127.175.0.0/32 \
        UNSOCK_DIR=/tmp/unsockets/ \
        LD_PRELOAD=/path/to/libunsock.so \
        iperf -c 127.175.0.0 -p 5000 -i 1
