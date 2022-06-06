### unsock: shim to automatically change `AF_INET` sockets to `AF_UNIX`, etc.

Copyright 2022 Christian Kohlschuetter <christian@kohlschutter.com>

SPDX-License-Identifier: Apache-2.0

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

# Building and running

To create the shared library `libunsock.so`, on a Linux machine just run

	make
 
To launch a target process with unsock, add *libunsock.so* to the environment variable
*LD_PRELOAD*, and set the environment variable *UNSOCK_DIR* to the absolute path of the directory
where unsock's `AF_UNIX` sockets are stored, for example as follows:

	UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=./libunsock.so *some-process* *(some-args ...)*

# Examples

## nc

Make `nc` listen on Unix domain socket /tmp/unsockets/7000.sock instead of using TCP port 7000:

    UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=./libunsock.so nc -l localhost 7000

## java

Make Java connect to UNIX sockets even without special support. Obviously, this is no replacement
for proper libraries like [junixsocket](https://github.com/kohlschutter/junixsocket), but may
be useful sometimes.

    UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=./libunsock.so java -jar ...

## noVNC

unsock + noVNC can be used to expose a VNC server to the Web via nginx, using Unix domain sockets
for all internal ports.

see [doc/novnc.md](doc/novnc.md) for details.
  

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

`AF_INET6` is not supported, and attempting to use IPv6 sockets in a shimmed process results in an
"access denied" error.

Since requests to create `AF_INET` sockets are intercepted and changed to `AF_UNIX`, programs that
still want to bind/connect to `AF_INET` sockets need to resort to receiving descriptors from another
process (via `AF_UNIX`). Alternatively, they may use helper processes that forward the `AF_UNIX`
sockets to `AF_INET` (e.g., *socat*).

Because *unsock* simply redirects libc calls, processes may technically work around the wrapper, for
example by using `syscall(2)` or other means of invoking kernel methods directly or via a helper
process.

Socket files are not removed upon `close(2)` (*unsock* tries to delete bound sockets upon
`shutdown(2)`). However, when binding, stale socket files are automatically removed to prevent an
"address in use" error.

The absolute path specified with `UNSOCK_DIR` must be of a certain maximum length, otherwise
the process will terminate with an error message.

The abstract namespace for Unix domain sockets is not supported.

The 32-bit host address of a `struct sockaddr_in` is currently not checked; this enables
binding to any IP address at the cost of increasing the chance of port number collisions. As
a consequence, when converting back to `struct sockaddr_in`, the IP address is hardcoded to
127.0.0.1.

When using `recvfrom(2)`, data sent from other `AF_UNIX` sockets that are not under the control of
*unsock*, is treated as if it was received from localhost, port *0*, which means that replying
to that address is currently not possible.

`AF_INET`-based sockets have several socket options thay may not be supported by `AF_UNIX`.
While *unsock* already has several checks for common options, some are still missing. Use
the *debug* build to add some logging when debugging these cases.
