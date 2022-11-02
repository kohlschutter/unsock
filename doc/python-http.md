# [unsock](../README.md) usage examples

## Python HTTP server

Python has a built-in HTTP server:

    python3 -m http.server

We can expose it via UNIX sockets, and, optionally, even via `AF_VSOCK`. This can be useful,
for example, to serve content from within a VM without having to configure networking.

### Local unix domain socket

This will launch the HTTP server, listening on `/tmp/unsockets/8000.sock`

    UNSOCK_PORT=8000 UNSOCK_ACCEPT_CONVERT_ALL=1 UNSOCK_ADDR=127.0.0.1/0 \
        UNSOCK_DIR=/tmp/unsockets LD_PRELOAD=/usr/local/lib/libunsock.so \
        python3 -m http.server

You can use `curl`, for example, to communicate with that HTTP server natively via `AF_UNIX`:

    curl --unix-socket /tmp/unsockets/8000.sock  http://localhost:8000/

You can of course also use `curl` via *unsock*:

    UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets LD_PRELOAD=/usr/local/lib/libunsock.so \
        curl http://localhost:8000/

### In a VM, via `AF_VSOCK`

`VSOCK` is a protocol that allows VM host&lt;-&gt;guest communication.

In order to export the socket via `AF_VSOCK`, we need to setup a control file first. This will
export the local TCP port 8000 as VSOCK port 8000: 

    UNSOCK_FILE=/tmp/unsockets/8000.sock UNSOCK_VSOCK_PORT=8000 /usr/local/lib/libunsock.so

Now we can run the server using the same command as above:

    UNSOCK_PORT=8000 UNSOCK_ACCEPT_CONVERT_ALL=1 UNSOCK_ADDR=127.0.0.1/0 \
        UNSOCK_DIR=/tmp/unsockets LD_PRELOAD=/usr/local/lib/libunsock.so \
        python3 -m http.server

#### From the host: Setup

Depending on how you access VSOCK sockets from your host machine, we need to configure our host-side
control file differently.

##### vhost-vsock 

This assumes that you can connect to your guest via `vhost-vsock`, and the guest CID is 3.

    UNSOCK_FILE=/tmp/unsockets/38000.sock UNSOCK_FC_SOCK=/path/to/firecracker/v.sock \
        UNSOCK_VSOCK_PORT=8000 UNSOCK_VSOCK_CID=3 /usr/local/lib/libunsock.so

##### Firecracker

This assumes that you're running Firecracker with a `vsock/uds_path` of
`/path/to/firecracker/v.sock`:

    UNSOCK_FILE=/tmp/unsockets/38000.sock UNSOCK_FC_SOCK=/path/to/firecracker/v.sock \
        UNSOCK_VSOCK_PORT=8000 /usr/local/lib/libunsock.so

#### From the host: Make the connection

Use curl (via unsock, which will take care of the entire socket setup):

    UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets LD_PRELOAD=/usr/local/lib/libunsock.so \
        curl http://localhost:38000/

### High-availability via `AF_TIPC`

[TIPC](http://tipc.io) is a protocol that enables high-availabilty communication in a cluster
environment.

You will run the following setup on several machines that are connected in the same Ethernet
network. Requests to the same TIPC service address may be answered by any of the participating
machines.

#### Set up TIPC

To actually use TIPC, make sure the `tipc` kernel module is loaded, and you have a bearer medium
set up, e.g.:

    sudo modprobe tipc
    sudo apk add iproute2-rdma
    sudo tipc bearer enable media eth device eth0

These commands must be run on each participating machine (client or server).

#### Create control files and launch servers

The following commands must be run on each participating server:

    rm -f /tmp/unsockets/8000.sock
    UNSOCK_FILE=/tmp/unsockets/8000.sock UNSOCK_TIPC_ADDRTYPE=2 UNSOCK_TIPC_SCOPE=2 \
        UNSOCK_TIPC_TYPE=180 UNSOCK_TIPC_LOWER=0 UNSOCK_TIPC_UPPER=0 /usr/local/lib/libunsock.so

    UNSOCK_PORT=8000 UNSOCK_ACCEPT_CONVERT_ALL=1 UNSOCK_ADDR=127.0.0.1/0 \
        UNSOCK_DIR=/tmp/unsockets LD_PRELOAD=/usr/local/lib/libunsock.so \
        python3 -m http.server

(watch the outputs of the Python server script on each server)

#### Make requests

From any machine connected to the same ethernet network

    UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets LD_PRELOAD=/usr/local/lib/libunsock.so \
        curl http://localhost:8000/

Note that the `GET` request may end up on either participating server.
