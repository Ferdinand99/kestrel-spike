#!/usr/bin/env bash
# Crash the app on the simulator with one crash kind, relaunch it so sentry-cocoa sends the
# stored crash report, then check the symbolicated result.
# Usage: ci/ios-crash.sh <fatal|unwrap|nsexception>
# Env: UDID, BUNDLE_ID, CAPTURE_DIR, LOG_DIR
set -euo pipefail
kind="$1"
here="$(cd "$(dirname "$0")" && pwd)"
proc="KestrelSpike.app/KestrelSpike"

xcrun simctl terminate "$UDID" "$BUNDLE_ID" 2>/dev/null || true
sleep 1

echo "::group::crash run ($kind)"
xcrun simctl launch --stdout="$LOG_DIR/$kind-crash.out" --stderr="$LOG_DIR/$kind-crash.err" \
  "$UDID" "$BUNDLE_ID" -crash "$kind"
# Simulator apps are ordinary host processes: wait for it to start and then die.
for _ in $(seq 1 60); do
  if ! pgrep -f "$proc" >/dev/null; then break; fi
  sleep 1
done
if pgrep -f "$proc" >/dev/null; then
  echo "::error::app did not crash within 60s ($kind)"
  exit 1
fi
echo "app is gone"
tail -n 20 "$LOG_DIR/$kind-crash.out" "$LOG_DIR/$kind-crash.err" || true
echo "::endgroup::"

echo "::group::relaunch to send the crash report ($kind)"
xcrun simctl launch --stdout="$LOG_DIR/$kind-relaunch.out" --stderr="$LOG_DIR/$kind-relaunch.err" \
  "$UDID" "$BUNDLE_ID"
echo "::endgroup::"

status=0
python3 "$here/check_crash.py" --captures "$CAPTURE_DIR" --kind "$kind" \
  --seen "$LOG_DIR/seen.txt" --timeout 180 || status=$?

xcrun simctl terminate "$UDID" "$BUNDLE_ID" 2>/dev/null || true
exit "$status"
