#!/usr/bin/env python3
"""Print an overview of everything the spike server captured (markdown, for the job summary).

Usage: summarize.py CAPTURE_DIR
"""

import glob
import json
import os
import sys


def main():
    captures = sys.argv[1]
    envelopes = sorted(glob.glob(os.path.join(captures, "*.envelope")))
    print(f"### Captured traffic\n\n{len(envelopes)} envelope request(s).\n")
    print("| event | level | exception | handled | frames symbolicated | crash_kind |")
    print("|---|---|---|---|---|---|")
    for path in sorted(glob.glob(os.path.join(captures, "*.event.json")), key=os.path.getmtime):
        event_id = os.path.basename(path)[: -len(".event.json")]
        event = json.load(open(path, encoding="utf-8"))
        exc = ((event.get("exception") or {}).get("values") or [{}])[0]
        handled = (exc.get("mechanism") or {}).get("handled")
        sym_path = os.path.join(captures, event_id + ".symbolicated.json")
        sym = "-"
        if os.path.exists(sym_path):
            r = json.load(open(sym_path, encoding="utf-8"))
            sym = f"{r.get('frames_symbolicated')}/{r.get('frames_total')}"
        tags = event.get("tags") or {}
        kind = tags.get("crash_kind", "") if isinstance(tags, dict) else ""
        print(
            f"| `{event_id}` | {event.get('level')} | {exc.get('type', '')} | {handled} | {sym} | {kind} |"
        )
    print()


if __name__ == "__main__":
    main()
