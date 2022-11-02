# [unsock](../README.md) usage examples

## noVNC

[noVNC](https://novnc.com/) is a program that allows running a VNC connection in the browser.
Even though it's [not supported out of the box](https://github.com/novnc/noVNC/issues/1340): 
thanks to *unsock*, novnc_server can now serve HTTP via Unix domain sockets (so you don't have to
expose it via TCP, and instead hide it behind some other server like nginx).   

1. Launch your local VNC server (e.g., `qemu-system-x86_64`)

    We assume that the server is reachable at localhost:5900 (bonus points if exposed as a
    Unix socket instead, see below)

2. Launch novnc_server with unsock

    noVNC will launch a webserver on TCP port 6080, but unsock redirects this to
    UNIX domain socket `/tmp/unsockets/6080.sock`. 

    ```
    UNSOCK_MODE=777 UNSOCK_PORT=6080 UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets/ \
        LD_PRELOAD=/usr/local/lib/libunsock.so novnc_server
    ```

    By specifying `UNSOCK_PORT`, we allow connections on any other port to keep working via TCP.

    This is important for *novnc_server*, since it currently won't allow binding on a specific IP
    address, and we still need to be able to connect to our VNC server at localhost:5900.
    
    Alternatively, consider launching the original VNC server as a UNIX socket at
    `/tmp/unsockets/5900.sock`. QEMU for example supports that by specifying
    `-vnc unix:/tmp/unsockets/5900.sock`. Then you can omit `UNSOCK_PORT`, which instructs *unsock*
    to map all ports, including 6080 and 5900.

    **NOTE:** `UNSOCK_MODE=777` makes sure `/tmp/unsockets/6080.sock` is accessible from your nginx
    process without extra steps.  However, you're encouraged to properly secure your system, for
    example by using an `UNSOCK_DIR` with permissions for both *novnc_server* and *nginx* but noone
    else.

3. Add proxy rules to your nginx server config, similar to this, then restart nginx:

    ```
    server {
        (...)
        location ~ ^/(.*)$ {
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_pass http://novnc/$1;
        }
    }
    
    upstream novnc {
        server unix:///tmp/unsockets/6080.sock;
    }
    ```

    You can now access the VNC server via `http://your-nginx-server/vnc.html`.

    If you want to use a subdirectory location for the proxy (e.g., `/vnc/`), change `location` to

	    location ~ ^/novnc/(.*)$ {

    and open `vnc.html` with an additional parameter pointing to the correct websockify URL, like
    so:

        http://your-nginx-server/novnc/vnc.html?path=/novnc/websockify
