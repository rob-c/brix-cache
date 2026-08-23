"""Tiny config-driven HTTP process used only to exercise BriXTest itself."""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> None:
    with Path(sys.argv[1]).open(encoding="utf-8") as handle:
        config = json.load(handle)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = config["message"].encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, pattern, *args):
            print(pattern % args, flush=True)

    ThreadingHTTPServer((config["host"], config["port"]), Handler).serve_forever()


if __name__ == "__main__":
    main()
