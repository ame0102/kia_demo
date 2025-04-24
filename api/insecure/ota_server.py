#!/usr/bin/env python3
"""
Tiny HTTP file server that *pretends* to be Kia's OTA endpoint.
There is no signature, no version monotonicity, no TLS - totally unsafe.
"""

from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path

FIRMWARE_DIR = Path("firmware")      # put .bin files here
FIRMWARE_DIR.mkdir(exist_ok=True)

class OTAHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        """
        Map /firmware/latest.bin to ./firmware/latest.bin
        """
        return str(FIRMWARE_DIR / Path(path).name)

if __name__ == "__main__":
    print("[!] Unsigned OTA server on :9000 (GET /latest.bin)")
    HTTPServer(("",9000), OTAHandler).serve_forever()