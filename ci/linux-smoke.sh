#!/usr/bin/env bash
# Protocol smoke test without iOS: real sentry-cli uploads an ELF with DWARF to the server,
# then a gzip envelope with a synthetic native event is symbolicated (incl. an inlined frame).
# Usage: ci/linux-smoke.sh <kestrel-spike binary> <sentry-cli binary>
set -euo pipefail
bin="$(realpath "$1")"
cli="$(realpath "$2")"
work="$(mktemp -d)"
cd "$work"
mkdir -p cap data

cat > prog.c <<'C'
#include <stdlib.h>
static inline __attribute__((always_inline)) int helper(int x) { if (x > 3) abort(); return x * 2; }
__attribute__((noinline)) int middle(int x) { return helper(x) + 1; }
int main(int argc, char **argv) { (void)argv; return middle(argc + 5) + 2; }
C
gcc -g -O2 -Wl,--build-id -o prog prog.c

CAPTURE_DIR="$work/cap" DATA_DIR="$work/data" BIND_ADDR=127.0.0.1:9100 "$bin" > server.log 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -sf http://127.0.0.1:9100/healthz >/dev/null && break; sleep 0.2; done

"$cli" --url http://127.0.0.1:9100 --auth-token x debug-files upload --org spike --project spike --wait prog
debug_id="$(basename "$(find data/difs -mindepth 1 -maxdepth 1 -type d | head -1)")"
test -s "data/difs/$debug_id/symcache"

dis="$(objdump -d --no-show-raw-insn prog)"
abort_call="$(awk '/<middle(\.cold)?>:/{f=1} f&&/call.*abort/{sub(":","",$1); print $1; exit}' <<<"$dis")"
main_ret="$(awk '/<main>:/{f=1} f&&/call.*middle/{getline; sub(":","",$1); print $1; exit}' <<<"$dis")"
python3 - "$debug_id" "$abort_call" "$main_ret" > env.txt <<'PY'
import json, sys
dbg, call, ret = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
base = 0x555555554000
event = {
  "event_id": "0123456789abcdef0123456789abcdef", "level": "fatal", "platform": "native",
  "exception": {"values": [{"type": "SIGABRT", "mechanism": {"type": "signal", "handled": False},
     "stacktrace": {"frames": [{"instruction_addr": hex(base + ret)}, {"instruction_addr": hex(base + call)}]}}]},
  "debug_meta": {"images": [{"type": "elf", "debug_id": dbg, "image_addr": hex(base), "image_size": 65536, "code_file": "/w/prog"}]},
}
print(json.dumps({"event_id": event["event_id"]}))
print(json.dumps({"type": "event"}))
print(json.dumps(event))
PY
gzip -c env.txt > env.gz
curl -sS -H 'Content-Encoding: gzip' -H 'X-Sentry-Auth: Sentry sentry_version=7, sentry_key=abc' \
  --data-binary @env.gz http://127.0.0.1:9100/api/1/envelope/
echo

python3 - "$work/cap/0123456789abcdef0123456789abcdef.symbolicated.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
frames = r["stacktraces"][0]["frames"]
got = [(f.get("function"), f.get("filename"), f.get("line"), f["inlined"]) for f in frames]
print(got)
names = [g[0] for g in got]
assert names[0] == "main" and names[-1] == "helper", names
assert any(n.startswith("middle") for n in names), names
assert frames[-1]["inlined"] and frames[-1]["filename"] == "prog.c" and frames[-1]["line"] == 2, frames[-1]
print("linux smoke: OK")
PY
cat server.log
