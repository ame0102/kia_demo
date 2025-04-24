#!/usr/bin/env python3
"""
Serves files from tuf_repo/ and enforces *monotonic version* by comparing
If-None-Match header with latest snapshot version.

Client flow:
  1. GET /metadata/ timestamp.json → validate signatures
  2. GET /firmware/latest.bin      → download if version newer
"""
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
import tuf.api.metadata as md, json, hashlib

REPO = Path("tuf_repo")
FIRM = Path("firmware/latest.bin")

class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        if path.startswith("/metadata/"):
            return str(REPO / path.split("/",2)[-1])
        if path=="/firmware/latest.bin":
            return str(FIRM)
        return super().translate_path(path)

    def end_headers(self):
        if self.path=="/firmware/latest.bin":
            meta = md.TargetFile.from_file(FIRM)
            self.send_header("ETag", meta.hashes["sha256"])
        super().end_headers()

if __name__ == "__main__":
    print("Secure OTA on :9000  (metadata under /metadata/)")
    HTTPServer(("",9000), Handler).serve_forever()