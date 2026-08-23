#!/usr/bin/env python3
"""tiny_proxy.py <listen_port> [logfile] — a minimal HTTP proxy for tests.

Handles both proxy modes used by the brix clients:
  * CONNECT host:port   → 200, then bidirectionally tunnels (sock.c / TLS path)
  * GET http://h:p/path → forwards to the origin in origin-form (libcurl http path)
Logs each request so tests can assert the proxy was actually used.
"""
import socket, threading, select, sys

def _expression_1(method, target):
    return (
        method == "GET" and target.startswith("http://")
    )

def _expression_2(ps):
    return (
        int(ps) if ps else 80
    )


def _phase_handle_1(client):
    try: client.close()
    except OSError: pass


LOG = open(sys.argv[2], "a") if len(sys.argv) > 2 else sys.stderr
def log(m): LOG.write(m + "\n"); LOG.flush()

def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 30)
            if not r:
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass


def _request(client):
    stream = client.makefile("rb")
    line = stream.readline().decode("latin1").strip()
    if not line:
        return None
    fields = line.split()
    while stream.readline() not in (b"\r\n", b"\n", b""):
        pass
    return fields[0], fields[1]


def _connect(client, target):
    host, port_text = target.split(":")
    port = int(port_text)
    log("CONNECT %s:%d" % (host, port))
    try:
        upstream = socket.create_connection((host, port), 10)
    except OSError:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    pipe(client, upstream)
    upstream.close()


def _forward(client, target):
    hostport, _, path = target[7:].partition("/")
    host, _, port_text = hostport.partition(":")
    port = _expression_2(port_text)
    path = "/" + path
    log("GET-forward %s:%d %s" % (host, port, path))
    upstream = socket.create_connection((host, port), 10)
    upstream.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"
                      % (path, hostport)).encode())
    while True:
        data = upstream.recv(65536)
        if not data:
            break
        client.sendall(data)
    upstream.close()


def _dispatch(client, request):
    if request is None:
        return
    method, target = request
    if method == "CONNECT":
        _connect(client, target)
    elif _expression_1(method, target):
        _forward(client, target)


def handle(client):
    try:
        _dispatch(client, _request(client))
    except OSError:
        pass
    finally:
        _phase_handle_1(client)

def main():
    port = int(sys.argv[1])
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(64)  # net-literal-allow: standalone-spawned helper server (no tests/ on sys.path); loopback bind
    log("proxy listening %d" % port)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
