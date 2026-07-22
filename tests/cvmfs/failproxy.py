#!/usr/bin/env python3
"""failproxy.py — a fault-injecting forward HTTP proxy for the CVMFS benchmark.

usage: failproxy.py <listen_port> --mode loss|reorder|stall --rate P [--log FILE]

Forwards GET http://host/path (and CONNECT) to the real upstream, injecting a
fault with probability P (0..1) per response:
  loss    — truncate the response / reset the connection mid-stream (packet loss)
  reorder — flip/reorder bytes in the response body (reordered/corrupt delivery)
  stall   — trickle the body slowly with pauses (throttling middlebox)
Both CVMFS clients hash-verify content, so a faulted object is detected and the
client must recover (retry / failover). Counts requests + faults to stderr/log.
"""
import socket, threading, select, sys, random, time, argparse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("--mode", choices=["loss", "reorder", "stall", "none"], default="none")
    ap.add_argument("--rate", type=float, default=0.0)
    ap.add_argument("--log", default=None)
    a = ap.parse_args()
    log = open(a.log, "a") if a.log else sys.stderr
    stats = {"req": 0, "fault": 0}

    def logline(m): log.write(m + "\n"); log.flush()

    def relay_faulted(up, client):
        """Read the whole upstream response, then deliver it to the client with a
        possible fault. Small CVMFS objects fit comfortably in memory."""
        data = b""
        while True:
            d = up.recv(65536)
            if not d:
                break
            data += d
        stats["req"] += 1
        if a.mode == "none" or random.random() >= a.rate:
            client.sendall(data); return
        stats["fault"] += 1
        # split headers/body so we corrupt the body, keeping a plausible response
        sep = data.find(b"\r\n\r\n")
        head, body = (data[:sep+4], data[sep+4:]) if sep >= 0 else (b"", data)
        if a.mode == "loss":
            cut = len(head) + random.randint(0, max(1, len(body)//2))
            client.sendall(data[:cut])            # truncate → client sees reset/short
        elif a.mode == "reorder":
            b = bytearray(body)
            for _ in range(max(1, len(b)//64)):   # flip scattered bytes
                if b: i = random.randrange(len(b)); b[i] ^= 0xff
            client.sendall(head + bytes(b))        # corrupt → hash-verify fails
        elif a.mode == "stall":
            client.sendall(head)
            for i in range(0, len(body), 256):     # trickle with pauses
                client.sendall(body[i:i+256]); time.sleep(0.05)

    def handle(client):
        try:
            f = client.makefile("rb")
            line = f.readline().decode("latin1").strip()
            if not line:
                client.close(); return
            method, target = line.split()[0], line.split()[1]
            while True:
                h = f.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
            if method == "GET" and target.startswith("http://"):
                rest = target[7:]; hostport, _, path = rest.partition("/")
                host, _, ps = hostport.partition(":"); port = int(ps) if ps else 80
                up = socket.create_connection((host, port), 10)
                up.sendall(("GET /%s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"
                            % (path, hostport)).encode())
                relay_faulted(up, client); up.close()
            elif method == "CONNECT":
                host, port = target.split(":"); port = int(port)
                up = socket.create_connection((host, port), 10)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                # tunnel (no fault injection on CONNECT for simplicity)
                while True:
                    r, _, _ = select.select([client, up], [], [], 30)
                    if not r: break
                    done = False
                    for s in r:
                        d = s.recv(65536)
                        if not d: done = True; break
                        (up if s is client else client).sendall(d)
                    if done: break
                up.close()
            client.close()
        except OSError:
            try: client.close()
            except OSError: pass

    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", a.port)); s.listen(128)  # net-literal-allow: standalone-spawned helper server (no tests/ on sys.path); loopback bind
    logline("failproxy mode=%s rate=%.2f port=%d" % (a.mode, a.rate, a.port))
    def reaper():
        while True:
            time.sleep(3); logline("STATS req=%d fault=%d" % (stats["req"], stats["fault"]))
    threading.Thread(target=reaper, daemon=True).start()
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
