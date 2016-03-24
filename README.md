46snihdnat
==========

```
     _____    ________             .__.__     
    /  |  |  /  _____/ ______ ____ |__|  |__  
   /   |  |_/   __  \ /  ___//    \|  |  |  \ 
  /    ^   /\  |__\  \\___ \|   |  \  |   Y  \
  \____   |  \_____  /____  >___|  /__|___|  /
       |__|        \/| _/_\/_ ___\/ _/  |_ \/ 
                  / __ |/    \\__  \\   __\   
                 / /_/ |   |  \/ __ \|  |     
                 \____ |___|  (____  /__|     
                      \/    \/     \/         
```

4 to 6 server name indication hybrid destination network address translation

```
AF_INET     :80         | http reverse proxy w/ host header
AF_INET     :443        | tls passthrough w/ sni hostname
AF_INET6    :80         | routed to destination
AF_INET6    :443        | routed to destination
*           :53         | dns zone from git repo
```

Secrecy
-------

tls connections are passed through based on the sni extension in ClientHello.  The connection isn't terminated at 46snihdnatd, but forwarded to the real destination. Secrecy isn't voided.

Let's encrypt
-------------

- http-01: supported, tested. Configure webroot plugin correctly.
- tls-sni-01: unsupported

License
-------

GPLv3
