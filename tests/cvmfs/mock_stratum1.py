#!/usr/bin/env python3
# tests/cvmfs/mock_stratum1.py — synthetic CVMFS Stratum-1 with fault injection.
#
# Serves a real CVMFS URL layout (manifest, whitelist, SHA1-named CAS objects,
# geo API) plus a /ctl/ control plane for tests: request log, one-shot faults
# (stall / reset / corrupt / truncate / wrong_length / http500 / slowdrip),
# manifest bump. Two body sources: synthetic objects (default) or, with
# --webroot DIR, a forged repo tree served straight off disk (repo_forge.py).
# Single-threaded-safe state via a lock.
import argparse, hashlib, json, os, random, re, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"log": [], "heads": [], "fault": {"mode": "none", "count": 0},
         "objects": {}, "repo": "", "revision": 1, "connections": 0,
         "webroot": None, "lock": threading.Lock()}

def make_repo(repo, n_objects, seed):
    rng = random.Random(seed)
    objs = {}
    for i in range(n_objects):
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(4096, 262144)))
        hexd = hashlib.sha1(body).hexdigest()
        suffix = "C" if i == 0 else ""          # object 0 poses as a catalog
        objs[f"/cvmfs/{repo}/data/{hexd[:2]}/{hexd[2:]}{suffix}"] = body
    return objs

def manifest(repo, revision):
    root = hashlib.sha1(f"{repo}:{revision}".encode()).hexdigest()
    return (f"C{root}\nB4096\nRd41d8cd98f00b204e9800998ecf8427e\n"
            f"D240\nS{revision}\nN{repo}\nX{root}\nT{int(time.time())}\n"
            f"--\n{root}\n").encode()

def _webroot_body(path):
    # Map a URL path onto a file under the forged webroot, with a traversal guard.
    root = os.path.abspath(STATE["webroot"])
    full = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if full != root and not full.startswith(root + os.sep):
        return None
    if os.path.isfile(full):
        with open(full, "rb") as fh:
            return fh.read()
    return None

def resolve_body(path):
    repo = STATE["repo"]
    if STATE["webroot"] is not None:
        return _webroot_body(path)
    if path == f"/cvmfs/{repo}/.cvmfspublished":
        return manifest(repo, STATE["revision"])
    if path == f"/cvmfs/{repo}/.cvmfswhitelist":
        return b"mock-whitelist\n"
    return STATE["objects"].get(path)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # silence default stderr chatter
        pass

    def setup(self):                  # once per accepted TCP connection
        with STATE["lock"]:
            STATE["connections"] += 1
        super().setup()

    def _send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _take_fault(self, path):
        # Consume the one-shot fault only when it targets `path`. A path_re that
        # does not match leaves the fault armed for a later matching request.
        with STATE["lock"]:
            f = STATE["fault"]
            if f["count"] > 0:
                pr = f.get("path_re")
                if pr is None or re.search(pr, path):
                    f["count"] -= 1
                    return f["mode"]
        return "none"

    def do_POST(self):
        if self.path == "/ctl/fault":
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n))
            with STATE["lock"]:
                STATE["fault"] = {"mode": req["mode"], "count": int(req["count"]),
                                  "path_re": req.get("path_re")}
            return self._send(200, b"ok")
        if self.path == "/ctl/reset-log":
            with STATE["lock"]:
                STATE["log"].clear(); STATE["heads"].clear(); STATE["connections"] = 0
            return self._send(200, b"ok")
        self._send(404, b"")

    def do_HEAD(self):
        # Size probes (the cache fill HEADs before its Range GETs). Not written
        # to the request log: /ctl/log counts data FETCHES, and tests assert on
        # exact fetch counts (stampede coalescing).
        with STATE["lock"]:
            STATE["heads"].append({"path": self.path, "ts": time.time()})
        body = resolve_body(self.path)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def do_GET(self):
        repo = STATE["repo"]
        if self.path == "/ctl/log":
            with STATE["lock"]:
                body = json.dumps(STATE["log"]).encode()
            return self._send(200, body, "application/json")
        if self.path == "/ctl/heads":
            with STATE["lock"]:
                body = json.dumps(STATE["heads"]).encode()
            return self._send(200, body, "application/json")
        if self.path == "/ctl/objects":
            return self._send(200, json.dumps(sorted(STATE["objects"])).encode(),
                              "application/json")
        if self.path == "/ctl/connections":     # distinct TCP connections seen
            with STATE["lock"]:
                n = STATE["connections"]
            return self._send(200, json.dumps({"connections": n}).encode(),
                              "application/json")
        if self.path == "/ctl/manifest/bump":
            with STATE["lock"]:
                STATE["revision"] += 1
            return self._send(200, b"ok")

        with STATE["lock"]:
            STATE["log"].append({"path": self.path, "ts": time.time()})

        if self.path.startswith(f"/cvmfs/{repo}/api/v1.0/geo/"):
            servers = self.path.rsplit("/", 1)[-1].split(",")
            order = ",".join(str(i + 1) for i in range(len(servers)))
            return self._send(200, order.encode() + b"\n", "text/plain")

        body = resolve_body(self.path)
        if body is None:
            return self._send(404, b"not found")

        mode = self._take_fault(self.path)
        if mode == "reset":
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       b"\x01\x00\x00\x00\x00\x00\x00\x00")
            self.connection.close()
            return
        if mode == "http500":
            return self._send(500, b"origin error")
        if mode == "stall":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:64]); self.wfile.flush()
            time.sleep(30)                      # longer than any fill stall timeout
            return
        if mode == "truncate":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:len(body) // 2]); self.wfile.flush()
            self.connection.close()
            return
        if mode == "wrong_length":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body) + 7))
            self.end_headers()
            self.wfile.write(body); self.wfile.flush()
            self.connection.close()
            return
        if mode == "slowdrip":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for byte in body:
                self.wfile.write(bytes([byte])); self.wfile.flush()
                time.sleep(0.2)
            return
        if mode == "corrupt":
            body = bytes(b ^ 0xFF if i == len(body) // 2 else b
                         for i, b in enumerate(body))

        # single-range support (bytes=a-b / bytes=a-), like a real Stratum-1
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            try:
                a, _, b = rng[len("bytes="):].partition("-")
                start = int(a)
                end = int(b) if b else len(body) - 1
            except ValueError:
                start, end = 0, len(body) - 1
            if start >= len(body):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(body)}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            end = min(end, len(body) - 1)
            part = body[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Range",
                             f"bytes {start}-{end}/{len(body)}")
            self.send_header("Content-Length", str(len(part)))
            self.end_headers()
            self.wfile.write(part)
            return
        self._send(200, body)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--repo", default="test.cern.ch")
    ap.add_argument("--objects", type=int, default=16)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bind", default="127.0.0.1")  # net-literal-allow: standalone-spawned helper server (no tests/ on sys.path); loopback bind
    ap.add_argument("--webroot", default=None,
                    help="serve a forged repo tree from DIR instead of synthetic objects")
    ap.add_argument("--keepalive", action="store_true",
                    help="serve HTTP/1.1 persistent connections (default 1.0)")
    args = ap.parse_args()
    STATE["repo"] = args.repo
    STATE["webroot"] = args.webroot
    if args.webroot is None:
        STATE["objects"] = make_repo(args.repo, args.objects, args.seed)
    if args.keepalive:
        Handler.protocol_version = "HTTP/1.1"
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()

if __name__ == "__main__":
    main()
