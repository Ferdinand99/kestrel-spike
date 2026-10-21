#!/usr/bin/env python3
"""Compare two symbolication reports frame by frame (function, file, line, inlined).

Usage: compare.py <reference.symbolicated.json> <candidate.symbolicated.json>
"""

import json
import sys


def frames(path):
    r = json.load(open(path, encoding="utf-8"))
    return [
        (s["source"], f.get("function"), f.get("filename"), f.get("line"), f.get("inlined"))
        for s in r["stacktraces"]
        for f in s["frames"]
    ], r.get("frames_symbolicated")


ref, ref_n = frames(sys.argv[1])
cand, cand_n = frames(sys.argv[2])
if ref != cand:
    for a, b in zip(ref, cand):
        if a != b:
            print(f"  reference: {a}\n  candidate: {b}")
    print(f"MISMATCH ({len(ref)} vs {len(cand)} frames)")
    sys.exit(1)
print(f"identical: {len(ref)} frames, {ref_n} symbolicated")
