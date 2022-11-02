### unsock: shim to automatically change `AF_INET` sockets to `AF_UNIX`, etc.

[![Makefile CI](https://github.com/kohlschutter/unsock/actions/workflows/makefile.yml/badge.svg?branch=main)](https://github.com/kohlschutter/unsock/actions/workflows/makefile.yml)

# unsock

Unix domain sockets (`AF_UNIX`) are Berkeley (BSD-style) sockets that are accessible
as paths in the file system. Unlike `AF_INET` sockets, they may be given user and group
ownership and access rights, which makes them an excellent choice to connect services
that run on the same host. 

Unfortunately, not all programs support Unix domain sockets out of the box. This is
where *unsock* comes in:

*unsock* is a shim library that intercepts Berkeley socket calls that
use `AF_INET` sockets and automatically rewrites them such that they use `AF_UNIX` sockets instead,
without having to modify the target program's source code.

Moreover, with the help of a custom control file in place of a real `AF_UNIX` domain socket,
unsock allows communicating over all sorts of sockets, such as `AF_VSOCK` and `AF_TIPC`.

Using *unsock* not only makes systems more secure (by not having to expose internal communication
as `AF_INET` sockets), it also helps improve performance by removing inter-protocol proxies from
the equation — programs can now talk directly to each other. 

# Building and running

To create the shared library `libunsock.so`, on a Linux machine just run

	make

To run some tests on the created library use

    make test

To install the library on the system (by default to `/usr/local/lib/`) use

    sudo make install
 
To launch a target process with unsock, add *libunsock.so* to the environment variable
*LD_PRELOAD*, and set the environment variable *UNSOCK_DIR* to the absolute path of the directory
where unsock's `AF_UNIX` sockets are stored, for example as follows:

	UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so *some-process* *(some-args ...)*

This will ensure that all connections to `127.175.0.0` are intercepted and routed to unix domain
sockets in `/tmp/unsockets`. The socket files are named `(port).socket`, e.g., `1234.socket` for
port 1234.

Use `UNSOCK_ADDR` to configure which IP addresses are redirected. You can either specify a single
IP-address (e.g., 1.2.3.4), or an IP-range identified by a bitmask (e.g., 1.2.3.4/24). Specifying
a bitmask of 32 is identical to omitting the bitmask. Specifying a bitmask of 0 means "all" IPv4
addresses, whereas the IP address itself is used to flag incoming connections from other protocols:

	UNSOCK_ADDR=127.0.0.1/8 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so *some-process* *(some-args ...)*

If `UNSOCK_ADDR` is omitted, only connections/binds to `127.175.0.0/32` are intercepted and converted.

# Security and permissions

## Socket file permissions

By default, *unsock* does not modify permissions for created socket files. However, you may specify
an octal value for `UNSOCK_MODE` to run *chmod* whenver an *unsock* socket file is created, e.g.:

    # Make available to all
    UNSOCK_MODE=777 (...)
    
    # Make available only to user
    UNSOCK_MODE=700 (...)

Since you may not be able to change group ownership from any process, you can strategically move
`UNSOCK_DIR` to a directory that has a certain group ownership and still get some security even
with `UNSOCK_MODE=777`.

## Disabling `AF_INET6`

Some processes may try binding/connnecting via IPv6. *unsock* will not prevent that, unless you
specify the following environment variable setting, which will block any attempts to create
`AF_INET6` sockets:

    UNSOCK_BLOCK_INET6=1 (...)

# Usage Examples

## nc

Make `nc` listen on Unix domain socket /tmp/unsockets/7000.sock instead of using TCP port 7000:

    UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so nc -l 127.175.0.0 7000

Listen on all IPv4 addresses; connections are coming from `127.175.0.3`:

    UNSOCK_ADDR=127.175.0.3/0 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so nc 127.0.0.1 7000

Listen on all IP addresses between 127.1.0.0 and 127.1.0.255; connection to 127.0.0.1 is via TCP:

    UNSOCK_ADDR=127.1.0.3/24 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=./usr/local/lib/libunsock.so nc 127.0.0.1 7000

## java

Make Java connect to UNIX sockets even without special support. Obviously, this is no replacement
for proper libraries like [junixsocket](https://github.com/kohlschutter/junixsocket), but may
be useful sometimes.

    UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so java -jar ...

## noVNC

unsock + noVNC can be used to expose a VNC server to the Web via nginx, using Unix domain sockets
for all internal ports.

see [doc/novnc.md](doc/novnc.md) for details.

## iperf

unsock allows to run iperf over arbitrary sockets (e.g., `AF_VSOCK`), not just IP.

see [doc/iperf.md](doc/iperf.md) for details.

# Control files, other socket domains

unsock can also connect to other types of sockets. If the `*.sock` file in `UNSOCK_DIR` is not a
unix domain socket but a regular file with a magic header, the contents of the file control the
actual target of the connection.  See `struct unsock_socket_info` in [unsock.h](src/unsock.h) for
details of the file format.

Some control file configurations can be created by calling `libunsock.so` as an executable, along
with some environment variables being set, including `UNSOCK_FILE` pointing to the control file: 

## Create a control file to bind on an `AF_VSOCK` address. 

Create a control file under `/tmp/unsockets/1234.sock` that points to `AF_VSOCK` port 5678 with
CID "any" (`-1`).

    UNSOCK_FILE=/tmp/unsockets/1234.sock UNSOCK_VSOCK_PORT=5678 /usr/local/lib/libunsock.so  
 
The command will fail if the file already exists.

## Create a control file to connect to a `VSOCK` socket via a Firecracker-style Unix domain socket

The Firecracker hypervisor exposes a multiplexed Unix domain socket, over which one can connect to
VSOCK ports in the guest system. When using `libunsock.so` with such a control file, the connection
is transparent, so no manual `CONNECT port/OK` logic is necesssary.

Create a control file under `/tmp/unsockets/1024.sock` that points to the `AF_UNIX` socket at
`/path/to/firecracker/vsock` which is a Firecracker multiplexing server.  Connecting to
`/tmp/unsockets/1024.sock` will actually try to connect to the guest's VSOCK port 5678.

      UNSOCK_FILE=/tmp/unsockets/1024.sock UNSOCK_FC_SOCK=/path/to/firecracker/vsock \
          UNSOCK_VSOCK_PORT=5678 /usr/local/lib/libunsock.so  
 
The command will fail if the file already exists.  You should specify an absolute path for
`UNSOCK_FC_SOCK`.  If it's a relative path, it must actually exist since it is resolved to an
absolute path for the control file.

## Create a control file to connect `TIPC` sockets

TIPC knows several addressing types, but it comes down to specifying five values, address type and
scope, and then three integer values depending on address type.

unsock does not discern these values, so the naming may be a little off, but it works.

To create a TIPC service address (addrtype=2; service range would be 1, and node id would be 3)
at cluster scope (scope=2; node scope would be 3), with service type 128 (values less than 64 are
reserved), instance ID of 99 ("lower" address) and domain of 0 (= global lookup; the "upper" address
of a service range) accessible via `AF_INET` port 8000, run the following command:

    UNSOCK_FILE=/tmp/unsockets/8000.sock UNSOCK_TIPC_ADDRTYPE=2 UNSOCK_TIPC_SCOPE=2 \
        UNSOCK_TIPC_TYPE=128 UNSOCK_TIPC_LOWER=99 UNSOCK_TIPC_UPPER=0 /usr/local/lib/libunsock.so

To actually use TIPC, make sure the `tipc` kernel module is loaded, and you have a bearer medium
set up, e.g.:

    sudo modprobe tipc
    sudo apk add iproute2-rdma
    sudo tipc bearer enable media eth device eth0
    
# Fine tuning

## Lie to `accept`

Some programs expect `AF_INET` socket addresses to be returned upon `accept`. Set the following
environment variable to modify any non-`AF_INET` address to look like one:

    UNSOCK_ACCEPT_CONVERT_ALL=1 (...)

You can also selectively convert `AF_VSOCK` only (`UNSOCK_ACCEPT_CONVERT_VSOCK=1`).

# Debugging and Testing
 
To create a library for debugging (`libunsock-debug.so`), which outputs some error messages, use

    make DEBUG=1

and change `LD_PRELOAD` accordingly.

To run some built-in tests that exercise the library, run

    make test

or

    make DEBUG=1 test

# Limitations and Known Issues

This library is supported on Linux only, and just lightly tested with some scenarios.
However, it should already work for many real-world use cases. If it doesn't work for you, feel free
to [file a bug report](https://github.com/kohlschutter/unsock/issues), optionally with a pull
request.

Only `AF_INET` is intercepted; `AF_INET6` is not intercepted. Binding on `localhost` may attempt
binding on an IPv6 address and therefore may not give you the results you expect. You can block
`AF_INET6` by specifying `UNSOCK_BLOCK_INET6=1`.

Because *unsock* simply redirects libc calls, processes may technically work around the wrapper, for
example by using `syscall(2)` or other means of invoking kernel methods directly or via a helper
process.

Socket files are not removed upon `close(2)` (*unsock* tries to delete bound sockets upon
`shutdown(2)`). However, when binding, stale socket files are automatically removed to prevent an
"address in use" error.

The absolute path specified with `UNSOCK_DIR` must be of a certain maximum length (less than 108),
otherwise the process will terminate with an error message.

The abstract namespace for Unix domain sockets is not supported.

When using `recvfrom(2)`, data sent from other `AF_UNIX` sockets that are not under the control of
*unsock*, is treated as if it was received from `127.175.0.0` (or the address configured with
`UNSOCK_ADDR`), port *0*, which means that replying to that address is currently not possible.

`AF_INET`-based sockets have several socket options thay may not be supported by `AF_UNIX`.
While *unsock* already has several checks for common options, some are still missing. Use
the *debug* build to add some logging when debugging these cases.

Currently, only little-endian architectures are tested/supported.

# Changelog

### _(2022-XX-XX)_ **unsock 1.1.0**

 - Add support for non-`AF_UNIX` connections (via control files posing as unix domain socket files)
 - Add support for Firecracker-style `CONNECT` proxies for `AF_VSOCK` communication.
 - Add very basic tooling to create the corresponding control files for `VSOCK` and `TIPC` sockets
 - Allow unintercepted `AF_INET`/`AF_INET6` traffic; by default, only `127.175.0.0` is intercepted.
 - Add `UNSOCK_ADDR` environment variable to configure which IP address/address range is intercepted.
 - Add `UNSOCK_PORT`, `UNSOCK_MODE`, `UNSOCK_BLOCK_INET6`.
 - Update build scripts, examples

### _(2022-06-06)_ **unsock 1.0.0**

 - Initial release

# Legal Notices

Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>

SPDX-License-Identifier: Apache-2.0
See NOTICE and LICENSE for license details.
