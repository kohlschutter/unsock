# [unsock](../README.md) usage examples

## noVNC

0. Launch your local VNC server (e.g., `qemu-system-x86_64`)

    We assume that the server is reachable at localhost:5900 (bonus points if exposed as a
    Unix socket instead, see below)

1. Launch novnc_server with unsock

    noVNC will launch a webserver on TCP port 6080, but unsock redirects this to
    UNIX domain socket `/tmp/unsockets/6080.sock`. 

    ```
    UNSOCK_ADDR=127.0.0.1/0 UNSOCK_DIR=/tmp/unsockets/ LD_PRELOAD=/usr/local/lib/libunsock.so novnc_server
    ```

2. Forward novnc's connection requests to the actual VNC server

    After connecting to noVNC's webserver, it will attempt to connect to the original VNC
    server at TCP port 5900. However, unsock rewrote that request to connect to 
    /tmp/unsockets/5900.sock instead. Thus, we have to forward requests to the actual port
    using another process, e.g., as follows:

    ```
    socat UNIX-LISTEN:/tmp/unsockets/5900.sock,fork TCP-CONNECT:localhost:5900
    ```
    
    Alternatively, consider launching the original VNC server as a UNIX socket at
    `/tmp/unsockets/5900.sock`. QEMU for example supports that by specifying
    `-vnc unix:/tmp/unsockets/5900.sock`.

3. Add proxy rules to your nginx server config, similar to this:

    Finally, we can expose noVNC's webserver via nginx (for example, to serve it over
    a secured and authorized channel only).

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
