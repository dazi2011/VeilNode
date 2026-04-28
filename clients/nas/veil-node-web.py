#!/usr/bin/env python3
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            proc = subprocess.run([sys.executable, "-m", "veil_core", "doctor"], text=True, capture_output=True)
            body = proc.stdout.encode("utf-8")
            self.send_response(200 if proc.returncode == 0 else 500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"VeilNode NAS gateway. Use /health for doctor output.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("VeilNode NAS gateway on http://127.0.0.1:8765")
    server.serve_forever()


if __name__ == "__main__":
    main()
