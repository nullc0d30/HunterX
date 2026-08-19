#!/usr/bin/env bash
# Capture a "screenshot" of a command's output into the final-rollout screenshots dir.
# Usage: capture.sh <milestone> <outfile>
set -uo pipefail
TS_DIR="$(cat /tmp/rollout_ts.txt 2>/dev/null || echo manual)"
SCREEN_DIR="$HOME/hunterx/HunterX/artifacts/final-rollout/$TS_DIR/screenshots"
mkdir -p "$SCREEN_DIR"
MILESTONE="$1"
OUTFILE="${2:-}"
if [ -z "$OUTFILE" ]; then
  echo "usage: capture.sh <milestone> <outfile>"
  exit 1
fi
DST="$SCREEN_DIR/${MILESTONE}"
if [ -f "$OUTFILE" ]; then
  cp "$OUTFILE" "$DST" 2>/dev/null
else
  echo "$OUTFILE" > "$DST"
fi
echo "captured $MILESTONE"
