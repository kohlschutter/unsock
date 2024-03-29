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

*unsock* specifically also simplifies communication between a virtual machine and its host, by
allowing communication to go through `AF_VSOCK` sockets even if the programs were designed for
IPv4-communication only. As a bonus feature, *unsock* simplifies communication with
[Firecracker-style](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
multiplexing sockets.

# Mode of operation

Being a shared library that is inserted into a process using `LD_PRELOAD`, *unsock* intercepts
standard C library calls like `connect(2)`, `bind(2)`, `accept(2)`, etc.  The calls are analyzed
and, if necessary, modified transparently such that the calling process does not notice (or at least
only minimally) that an exchange took place.

Since socket file descriptors are first created on a per-protocol bassis using `socket(2)`, should
an address family need to be changed, that socket file descriptor is _replaced_ transparently using
a correct one.  `dup3(2)` is used to re-assign the file descriptor number on the fly, so no
additional housekeeping is necessary.

`AF_INET` socket addresses are converted to a configurable path on the file system, under which
either `AF_UNIX` sockets reside, or special control files with instructions how to reach the desired
socket destination (for details see below).

*unsock*'s behavior can be modified using several environment parameters, which are outlined below.

The shared library binary doubles as a simple configuration tool to create the special control files
(for details see below).

# Building and running

In order to build, you need a working C compiler (available under `cc`), Linux headers, and for
tests an `nc` command that supports UNIX sockets. If you're on Alpine Linux, just run

    ./init

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

	UNSOCK_ADDR=127.0.0.1/8 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so some-process some-args ...

If `UNSOCK_ADDR` is omitted, only connections/binds to `127.175.0.0/32` are intercepted and converted.

# Security and permissions

## Choosing a directory for `UNSOCK_DIR`

In the examples, for simplicity, we use `/tmp/unsockets` for `UNSOCK_DIR`.

Note that you should use a different directory in production, preferably one that has read/write
permissions restricted to the user/group that uses the socket.

You also don't necessarily need one directory; you can have separate directories for different
processes.

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

## Disabling unintercepted `AF_INET`

You can also prevent unintercepted `AF_INET` connections (those that are not translated via
`unsock`), by specifying the following environment variable:

    UNSOCK_BLOCK_INET=1 (...)

# Usage Examples

## nc

Make `nc` listen on Unix domain socket /tmp/unsockets/7000.sock instead of using TCP port 7000:

    UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so nc -l 127.175.0.0 7000

Listen on all IPv4 addresses; connections are coming from `127.175.0.3`:

    UNSOCK_ADDR=127.175.0.3/0 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so nc 127.0.0.1 7000

Listen on all IP addresses between 127.1.0.0 and 127.1.0.255; connection to 127.0.0.1 is via TCP:

    UNSOCK_ADDR=127.1.0.3/24 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so nc 127.0.0.1 7000
    
**NOTE:** busybox nc is a bit picky when accepting connections. You may need to specify

	UNSOCK_BLOCK_INET6=1 UNSOCK_PORT=7000 UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets/ \
        LD_PRELOAD=/usr/local/lib/libunsock.so nc -l -p 7000

to fix the bound + incoming addresses and ports.

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

unsock allows to run iperf over arbitrary sockets (e.g., `AF_UNIX`, `AF_VSOCK` and `AF_TIPC`), not
just IP.

see [doc/iperf.md](doc/iperf.md) for details.

## Python HTTP server

unsock allows to run the HTTP server over arbitrary sockets (e.g., `AF_UNIX`, `AF_VSOCK` and
`AF_TIPC`), not just IP.

see [doc/python-http.md](doc/python-http.md) for details.


# Control files, other socket domains like `AF_VSOCK` and `AF_TIPC`.

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
    
# Fine-tuning

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

The absolute path specified with `UNSOCK_DIR` must be of a certain maximum length (less than 96),
otherwise the process will terminate with an error message.

When the directory specified with `UNSOCK_DIR` does not exist, it is created using a mode of `0755`,
unless umask dictates a stricter mode.

The abstract namespace for Unix domain sockets is not supported.

When using `recvfrom(2)`, data sent from other `AF_UNIX` sockets that are not under the control of
*unsock*, is treated as if it was received from `127.175.0.0` (or the address configured with
`UNSOCK_ADDR`), port *0*, which means that replying to that address is currently not possible.

`AF_INET`-based sockets have several socket options thay may not be supported by `AF_UNIX`.
While *unsock* already has several checks for common options, some are still missing. Use
the *debug* build to add some logging when debugging these cases.

In order to determine the socket file in `UNSOCK_DIR`, the address part of the `AF_INET` address
is currently not taken into consideration (only the port number is), which may lead to unexpected
results. Use a narrowly specified `UNSOCK_ADDR` to compensate. 

Currently, only little-endian architectures are tested/supported.

# Changelog

### _(2022-11-03)_ **unsock 1.1.0**

 - Add support for non-`AF_UNIX` connections (via control files posing as unix domain socket files)
 - Add support for Firecracker-style `CONNECT` proxies for `AF_VSOCK` communication.
 - Add very basic tooling to create the corresponding control files for `VSOCK` and `TIPC` sockets
 - Allow unintercepted `AF_INET`/`AF_INET6` traffic; by default, only `127.175.0.0` is intercepted.
 - Add `UNSOCK_ADDR` environment variable to configure which IP address/address range is intercepted.
 - Add `UNSOCK_PORT`, `UNSOCK_MODE`, `UNSOCK_BLOCK_INET6`, `UNSOCK_BLOCK_INET`.
 - Update build scripts, examples

### _(2022-06-06)_ **unsock 1.0.0**

 - Initial release

# Outlook

## Custom socket types

It would be relatively simple to intercept custom address families that are not yet supported
in the kernel. This could accelerate development of new protocols.  

## Custom proxies, routing

It would be relatively simple to add code that intercepts calls to certain IP address ranges
and employ a third-party routing software for such connections. For example, a library like
[BoringTun](https://github.com/cloudflare/boringtun) could provide WireGuard-compatible connections
for a specific process, without requiring additional configuration or kernel support.

## Logging

Traffic could be logged, similar to what `socket_wrapper` does (see below).

# Related software

## socket_wrapper

*Samba* has the [Socket Wrapper](https://git.samba.org/?p=socket_wrapper.git;a=summary), which
serves a similar purpose. It is limited to `AF_UNIX` sockets and does not use `dup3` to exchange
file descriptors, therefore it needs to intercept many unrelated function calls for housekeeping.

## ip2unix

[ip2unix](https://github.com/nixcloud/ip2unix) converts IPv4 and IPv6 sockets to AF_UNIX, on a
per-rule basis.  An internal mapping (instead of using dup3) is maintained.  Also has some systemd
integration for IP-based socket activation.

## TSI: Transparent Socket Impersonation

Containers [libkrun](https://github.com/containers/libkrunfw) has kernel patches that may
transparently turn `AF_INET` sockets into `AF_VSOCK`.

See patches [AF_TSI](https://github.com/containers/libkrunfw/blob/4b087ea7ac0b51516b21e6839a90a1051aec106c/patches/0010-Transparent-Socket-Impersonation-implementation.patch)
and [tsi_hijack](https://github.com/containers/libkrunfw/blob/4b087ea7ac0b51516b21e6839a90a1051aec106c/patches/0011-tsi-allow-hijacking-sockets-tsi_hijack.patch).

## junixsocket

A Java/JNI library that allows the use of Unix domain sockets (`AF_UNIX`) and others like `AF_TIPC`
and `AF_VSOCK`, from Java and other JVM languages. Works with GraalVM, too. 

[junixsocket on GitHub](https://github.com/kohlschutter/junixsocket);
[junixsocket project website](https://kohlschutter.github.io/junixsocket/)

# Legal Notices

Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>

SPDX-License-Identifier: Apache-2.0

See NOTICE and LICENSE for license details.
