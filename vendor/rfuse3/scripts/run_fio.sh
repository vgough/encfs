#!/usr/bin/env bash
set -euo pipefail

MOUNTPOINT=${1:-/tmp/rfuse-bench}
FILE_COUNT=${FILE_COUNT:-10000}
FILE_SIZE=${FILE_SIZE:-131072}  # 128KB per file
WORKERS=${WORKERS:-16}  # More workers for high concurrency
MAX_BG=${MAX_BG:-256}  # More in-flight requests

# Test mode: "sync" (multi-thread psync) or "async" (io_uring with depth)
MODE=${MODE:-sync}

if [[ "$MODE" == "async" ]]; then
  # Async mode: fewer threads, higher depth per thread
  IOENGINE=${IOENGINE:-io_uring}
  IODEPTH=${IODEPTH:-32}
  NUMJOBS=${NUMJOBS:-8}
else
  # Sync mode: more threads, depth=1 (RECOMMENDED for FUSE)
  IOENGINE=${IOENGINE:-psync}
  IODEPTH=${IODEPTH:-1}
  NUMJOBS=${NUMJOBS:-16}
fi

DIRECT=${DIRECT:-0}

mkdir -p "$MOUNTPOINT"

cleanup() {
  if mountpoint -q "$MOUNTPOINT"; then
    fusermount3 -u "$MOUNTPOINT" 2>/dev/null || true
  fi
  if [[ -n "${FUSE_PID:-}" ]] && kill -0 "$FUSE_PID" 2>/dev/null; then
    kill "$FUSE_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT

if [[ -n "$(ls -A "$MOUNTPOINT" 2>/dev/null)" ]]; then
  echo "Mount point is not empty: $MOUNTPOINT" >&2
  exit 1
fi

# Start benchmark FUSE in background
cargo run --example benchmark_filesystem -- \
  "$MOUNTPOINT" \
  --file-count "$FILE_COUNT" \
  --file-size "$FILE_SIZE" \
  --workers "$WORKERS" \
  --max-background "$MAX_BG" \
  &

FUSE_PID=$!

# Wait for mount to be ready
for _ in {1..100}; do
  if mountpoint -q "$MOUNTPOINT"; then
    break
  fi
  if ! kill -0 "$FUSE_PID" 2>/dev/null; then
    echo "FUSE process exited before mount succeeded." >&2
    exit 1
  fi
  sleep 0.2
done

if ! mountpoint -q "$MOUNTPOINT"; then
  echo "Mount failed or timed out for: $MOUNTPOINT" >&2
  exit 1
fi

echo "Running fio against $MOUNTPOINT ..."
echo "Configuration: numjobs=$NUMJOBS, iodepth=$IODEPTH, workers=$WORKERS, max_bg=$MAX_BG"

# Multi-threaded concurrent test
fio --name=rfuse-multithread \
  --directory="$MOUNTPOINT" \
  --rw=randrw \
  --rwmixread=70 \
  --bs=4k \
  --ioengine="$IOENGINE" \
  --iodepth="$IODEPTH" \
  --numjobs="$NUMJOBS" \
  --time_based \
  --runtime=30 \
  --group_reporting \
  --direct="$DIRECT" \
  --size=64m \
  --thread

echo "Done."
