"""Small config-driven HTTP server used only by the executable examples."""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> None:
    with Path(sys.argv[1]).open(encoding="utf-8") as handle:
        config = json.load(handle)
    body = os.environ.get("BRIXTEST_EXAMPLE_BODY", config["message"]).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, pattern, *args):
            print(pattern % args, flush=True)

    ThreadingHTTPServer((config["host"], config["port"]), Handler).serve_forever()


if __name__ == "__main__":
    main()
