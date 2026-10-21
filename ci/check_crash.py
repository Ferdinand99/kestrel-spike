#!/usr/bin/env python3
"""Wait for a new crash event from the iOS app and assert it was symbolicated correctly.

Usage: check_crash.py --captures DIR --kind fatal|unwrap|nsexception --seen FILE
                      [--timeout 180] [--summary $GITHUB_STEP_SUMMARY]

A "new crash event" is an `<event_id>.event.json` in DIR whose exception is unhandled and
whose id is not listed in FILE (ids of events already checked). The id is appended to FILE.
"""

import argparse
import glob
import json
import os
import sys
import time

APP_IMAGE = "KestrelSpike"
APP_FILE = "CrashSite.swift"
# Each expected function: all substrings must occur in one demangled `function` of an app
# frame (generic specialization prefixes / generic parameters may vary).
EXPECTED = {
    "static CrashSite.crash(_:)": ["CrashSite", "crash("],
    "CrashPipeline.run(_:)": ["CrashPipeline", "run("],
    "CrashPipeline.Stage.detonate(_:)": ["Stage", "detonate("],
    "trigger(_:depth:)": ["trigger("],
}
RAW_FORBIDDEN = ["CrashSite", "CrashPipeline", "detonate", "trigger"]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def tags(event):
    t = event.get("tags") or {}
    return t if isinstance(t, dict) else dict(t)


def is_crash(event, kind):
    excs = (event.get("exception") or {}).get("values") or []
    if any(e.get("type") == "WatchdogTermination" for e in excs):
        return False
    tag = tags(event).get("crash_kind")
    if tag is not None and tag != kind:
        return False
    if any((e.get("mechanism") or {}).get("handled") is False for e in excs):
        return True
    return event.get("level") == "fatal"


def find_new_crash(captures, seen, kind):
    for path in sorted(glob.glob(os.path.join(captures, "*.event.json")), key=os.path.getmtime):
        event_id = os.path.basename(path)[: -len(".event.json")]
        if event_id in seen:
            continue
        sym = os.path.join(captures, event_id + ".symbolicated.json")
        try:
            event = load(path)
        except (OSError, ValueError):
            continue
        if is_crash(event, kind) and os.path.exists(sym):
            return event_id, event, load(sym)
    return None


def crashed_stack(report):
    stacks = report.get("stacktraces") or []
    for s in stacks:
        if s["source"].startswith("exception") and s["frames"]:
            return s
    for s in stacks:
        if s.get("crashed") and s["frames"]:
            return s
    return stacks[0] if stacks else {"source": "none", "frames": []}


def render(stack):
    lines = ["| # | image | function | file:line | inlined | from dSYM |", "|---|---|---|---|---|---|"]
    # Most recent call first, like a normal crash log.
    for i, f in enumerate(reversed(stack["frames"])):
        loc = f"{f.get('filename') or ''}:{f.get('line') or ''}" if f.get("filename") else ""
        fn = (f.get("function") or f.get("raw_function") or "?").replace("|", "\\|")
        lines.append(
            f"| {i} | {f.get('image') or ''} | `{fn}` | {loc} | {'yes' if f.get('inlined') else ''} | {'yes' if f.get('symbolicated') else ''} |"
        )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures", required=True)
    ap.add_argument("--kind", required=True)
    ap.add_argument("--seen", required=True)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    args = ap.parse_args()

    seen = set()
    if os.path.exists(args.seen):
        seen = set(open(args.seen).read().split())

    deadline = time.time() + args.timeout
    found = None
    while time.time() < deadline:
        found = find_new_crash(args.captures, seen, args.kind)
        if found:
            break
        time.sleep(3)
    if not found:
        print(f"::error::no new crash event for '{args.kind}' within {args.timeout}s")
        return 1

    event_id, event, report = found
    with open(args.seen, "a") as f:
        f.write(event_id + "\n")

    stack = crashed_stack(report)
    frames = stack["frames"]
    app = [f for f in frames if f.get("image") == APP_IMAGE]
    sym_app = [f for f in app if f.get("symbolicated")]
    failures = []

    if tags(event).get("crash_kind") != args.kind:
        print(f"::warning::{args.kind}: event has no crash_kind tag (scope not synced to crash report?)")

    if not sym_app:
        failures.append("no app frame was symbolicated from the dSYM")
    functions = [f.get("function") or "" for f in sym_app]
    for pretty, parts in EXPECTED.items():
        if not any(all(p in fn for p in parts) for fn in functions):
            failures.append(f"missing expected function {pretty!r}")
    in_file = [f for f in sym_app if f.get("filename") == APP_FILE]
    if not in_file:
        failures.append(f"no symbolicated frame in {APP_FILE}")
    bad_lines = [f for f in in_file if not (0 < (f.get("line") or 0) < 200)]
    if bad_lines:
        failures.append(f"implausible line numbers: {[f.get('line') for f in bad_lines]}")
    if not any(f.get("inlined") and f.get("filename") == APP_FILE for f in sym_app):
        failures.append("no inlined frame from CrashSite.swift")
    if not any(f.get("inlined") and "trigger" in (f.get("function") or "") for f in sym_app):
        failures.append("trigger(_:depth:) was not reported as an inlined frame")

    # The raw event (as sent by sentry-cocoa) must not already contain our Swift names.
    raw_names = [f.get("raw_function") for f in app if f.get("raw_function")]
    leaked = [n for n in raw_names if any(s in n for s in RAW_FORBIDDEN)]
    if leaked:
        failures.append(f"raw event already contained app function names: {leaked}")

    exc = report.get("exception") or {}
    header = (
        f"### Crash `{args.kind}`: event `{event_id}`\n\n"
        f"exception: `{exc.get('type')}` {exc.get('value') or ''} (mechanism `{exc.get('mechanism')}`)  \n"
        f"stack: `{stack['source']}`, frames symbolicated {report.get('frames_symbolicated')}/{report.get('frames_total')} "
        f"(all stacks), app frames {len(app)}, raw app function names: {raw_names or 'none'}\n\n"
    )
    result = ("**PASS**\n\n" if not failures else "**FAIL**\n\n" + "\n".join(f"- {x}" for x in failures) + "\n\n")
    text = header + result + render(stack) + "\n\n"
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(text)
    for x in failures:
        print(f"::error::{args.kind}: {x}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
