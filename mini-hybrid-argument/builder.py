#!/usr/bin/env python3
"""Build all source files for mini-hybrid-argument module."""
import os

BASE = os.path.dirname(os.path.abspath(__file__))

def w(relpath, content):
    path = os.path.join(BASE, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    lines = content.count("\n") + 1
    print(f"  WROTE {relpath}: {lines} lines, {len(content)} chars")

