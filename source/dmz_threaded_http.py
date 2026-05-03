#!/usr/bin/env python3
"""
HTTP server đa luồng cho host DMZ trong Mininet.
Tránh timeout khi bắn nhiều curl song song (python -m http.server xử lý tuần tự).
"""
from __future__ import annotations

import argparse
import os

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="Thư mục document root")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()
    os.chdir(args.dir)
    ThreadingHTTPServer((args.bind, args.port), SimpleHTTPRequestHandler).serve_forever()


if __name__ == "__main__":
    main()
