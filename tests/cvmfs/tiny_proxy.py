#!/usr/bin/env python3
"""tiny_proxy.py <listen_port> [logfile] — a minimal HTTP proxy for tests.

Handles both proxy modes used by the brix clients:
  * CONNECT host:port   → 200, then bidirectionally tunnels (sock.c / TLS path)
  * GET http://h:p/path → forwards to the origin in origin-form (libcurl http path)
Logs each request so tests can assert the proxy was actually used.
"""
import socket, threading, select, sys

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

def handle(client):
    try:
        f = client.makefile("rb")
        line = f.readline().decode("latin1").strip()
        if not line:
            client.close(); return
        method, target = line.split()[0], line.split()[1]
        while True:                                   # drain request headers
            h = f.readline()
            if h in (b"\r\n", b"\n", b""):
                break
        if method == "CONNECT":
            host, port = target.split(":"); port = int(port)
            log("CONNECT %s:%d" % (host, port))
            try:
                up = socket.create_connection((host, port), 10)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); client.close(); return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            pipe(client, up); up.close(); client.close()
        elif method == "GET" and target.startswith("http://"):
            rest = target[7:]
            hostport, _, path = rest.partition("/")
            path = "/" + path
            host, _, ps = hostport.partition(":")
            port = int(ps) if ps else 80
            log("GET-forward %s:%d %s" % (host, port, path))
            up = socket.create_connection((host, port), 10)
            up.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"
                        % (path, hostport)).encode())
            while True:
                d = up.recv(65536)
                if not d:
                    break
                client.sendall(d)
            up.close(); client.close()
        else:
            client.close()
    except OSError:
        try: client.close()
        except OSError: pass

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
