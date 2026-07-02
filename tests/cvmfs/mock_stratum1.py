#!/usr/bin/env python3
# tests/cvmfs/mock_stratum1.py — synthetic CVMFS Stratum-1 with fault injection.
#
# Serves a real CVMFS URL layout (manifest, whitelist, SHA1-named CAS objects,
# geo API) plus a /ctl/ control plane for tests: request log, one-shot faults
# (stall / reset / corrupt), manifest bump. Single-threaded-safe state via a lock.
import argparse, hashlib, json, os, random, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"log": [], "fault": {"mode": "none", "count": 0},
         "objects": {}, "repo": "", "revision": 1, "lock": threading.Lock()}

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

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # silence default stderr chatter
        pass

    def _send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _take_fault(self):
        with STATE["lock"]:
            f = STATE["fault"]
            if f["count"] > 0:
                f["count"] -= 1
                return f["mode"]
        return "none"

    def do_POST(self):
        if self.path == "/ctl/fault":
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n))
            with STATE["lock"]:
                STATE["fault"] = {"mode": req["mode"], "count": int(req["count"])}
            return self._send(200, b"ok")
        self._send(404, b"")

    def do_GET(self):
        repo = STATE["repo"]
        if self.path == "/ctl/log":
            with STATE["lock"]:
                body = json.dumps(STATE["log"]).encode()
            return self._send(200, body, "application/json")
        if self.path == "/ctl/objects":
            return self._send(200, json.dumps(sorted(STATE["objects"])).encode(),
                              "application/json")
        if self.path == "/ctl/manifest/bump":
            with STATE["lock"]:
                STATE["revision"] += 1
            return self._send(200, b"ok")

        with STATE["lock"]:
            STATE["log"].append({"path": self.path, "ts": time.time()})

        if self.path == f"/cvmfs/{repo}/.cvmfspublished":
            return self._send(200, manifest(repo, STATE["revision"]))
        if self.path == f"/cvmfs/{repo}/.cvmfswhitelist":
            return self._send(200, b"mock-whitelist\n")
        if self.path.startswith(f"/cvmfs/{repo}/api/v1.0/geo/"):
            servers = self.path.rsplit("/", 1)[-1].split(",")
            order = ",".join(str(i + 1) for i in range(len(servers)))
            return self._send(200, order.encode() + b"\n", "text/plain")

        body = STATE["objects"].get(self.path)
        if body is None:
            return self._send(404, b"not found")
        mode = self._take_fault()
        if mode == "reset":
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       b"\x01\x00\x00\x00\x00\x00\x00\x00")
            self.connection.close()
            return
        if mode == "stall":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:64]); self.wfile.flush()
            time.sleep(30)                      # longer than any fill stall timeout
            return
        if mode == "corrupt":
            body = bytes(b ^ 0xFF if i == len(body) // 2 else b
                         for i, b in enumerate(body))
        self._send(200, body)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--repo", default="test.cern.ch")
    ap.add_argument("--objects", type=int, default=16)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    STATE["repo"] = args.repo
    STATE["objects"] = make_repo(args.repo, args.objects, args.seed)
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()

if __name__ == "__main__":
    main()
