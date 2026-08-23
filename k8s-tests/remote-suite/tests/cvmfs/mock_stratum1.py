#!/usr/bin/env python3
# tests/cvmfs/mock_stratum1.py — synthetic CVMFS Stratum-1 with fault injection.
#
# Serves a real CVMFS URL layout (manifest, whitelist, SHA1-named CAS objects,
# geo API) plus a /ctl/ control plane for tests: request log, one-shot faults
# (stall / reset / corrupt), manifest bump. Single-threaded-safe state via a lock.
import argparse, hashlib, json, os, random, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"log": [], "heads": [], "fault": {"mode": "none", "count": 0},
         "objects": {}, "repo": "", "revision": 1, "connections": 0,
         "lock": threading.Lock()}

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

    def do_HEAD(self):
        # Size probes (the cache fill HEADs before its Range GETs). Not written
        # to the request log: /ctl/log counts data FETCHES, and tests assert on
        # exact fetch counts (stampede coalescing).
        repo = STATE["repo"]
        with STATE["lock"]:
            STATE["heads"].append({"path": self.path, "ts": time.time()})
        if self.path == f"/cvmfs/{repo}/.cvmfspublished":
            body = manifest(repo, STATE["revision"])
        elif self.path == f"/cvmfs/{repo}/.cvmfswhitelist":
            body = b"mock-whitelist\n"
        else:
            body = STATE["objects"].get(self.path)
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
        if self._serve_control():
            return
        with STATE["lock"]:
            STATE["log"].append({"path": self.path, "ts": time.time()})
        if self._serve_metadata(repo):
            return
        body = STATE["objects"].get(self.path)
        if body is None:
            self._send(404, b"not found")
            return
        mode = self._take_fault()
        if self._apply_fault(mode, body):
            return
        body = self._fault_body(mode, body)
        if self._serve_range(body):
            return
        self._send(200, body)

    def _serve_control(self):
        if self.path == "/ctl/log":
            with STATE["lock"]:
                body = json.dumps(STATE["log"]).encode()
            self._send(200, body, "application/json")
            return True
        if self.path == "/ctl/heads":
            with STATE["lock"]:
                body = json.dumps(STATE["heads"]).encode()
            self._send(200, body, "application/json")
            return True
        if self.path == "/ctl/objects":
            body = json.dumps(sorted(STATE["objects"])).encode()
            self._send(200, body, "application/json")
            return True
        if self.path == "/ctl/connections":     # distinct TCP connections seen
            with STATE["lock"]:
                n = STATE["connections"]
            body = json.dumps({"connections": n}).encode()
            self._send(200, body, "application/json")
            return True
        if self.path == "/ctl/manifest/bump":
            with STATE["lock"]:
                STATE["revision"] += 1
            self._send(200, b"ok")
            return True
        return False

    def _serve_metadata(self, repo):
        if self.path == f"/cvmfs/{repo}/.cvmfspublished":
            self._send(200, manifest(repo, STATE["revision"]))
            return True
        if self.path == f"/cvmfs/{repo}/.cvmfswhitelist":
            self._send(200, b"mock-whitelist\n")
            return True
        if self.path.startswith(f"/cvmfs/{repo}/api/v1.0/geo/"):
            servers = self.path.rsplit("/", 1)[-1].split(",")
            order = ",".join(str(i + 1) for i in range(len(servers)))
            self._send(200, order.encode() + b"\n", "text/plain")
            return True
        return False

    def _apply_fault(self, mode, body):
        if mode == "reset":
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       b"\x01\x00\x00\x00\x00\x00\x00\x00")
            self.connection.close()
            return True
        if mode == "stall":
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:64]); self.wfile.flush()
            time.sleep(30)                      # longer than any fill stall timeout
            return True
        return False

    def _fault_body(self, mode, body):
        if mode == "corrupt":
            return bytes(byte ^ 0xFF if index == len(body) // 2 else byte
                         for index, byte in enumerate(body))
        return body

    def _serve_range(self, body):
        rng = self.headers.get("Range")
        if not rng or not rng.startswith("bytes="):
            return False
        start, end = self._range_bounds(rng, len(body))
        if start >= len(body):
            self._send_unsatisfied_range(len(body))
            return True
        self._send_range(body, start, min(end, len(body) - 1))
        return True

    @staticmethod
    def _range_bounds(header, length):
        try:
            first, _, last = header[len("bytes="):].partition("-")
            return int(first), int(last) if last else length - 1
        except ValueError:
            return 0, length - 1

    def _send_unsatisfied_range(self, length):
        self.send_response(416)
        self.send_header("Content-Range", f"bytes */{length}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_range(self, body, start, end):
        part = body[start:end + 1]
        self.send_response(206)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Range", f"bytes {start}-{end}/{len(body)}")
        self.send_header("Content-Length", str(len(part)))
        self.end_headers()
        self.wfile.write(part)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--repo", default="test.cern.ch")
    ap.add_argument("--objects", type=int, default=16)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--keepalive", action="store_true",
                    help="serve HTTP/1.1 persistent connections (default 1.0)")
    args = ap.parse_args()
    STATE["repo"] = args.repo
    STATE["objects"] = make_repo(args.repo, args.objects, args.seed)
    if args.keepalive:
        Handler.protocol_version = "HTTP/1.1"
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()

if __name__ == "__main__":
    main()
