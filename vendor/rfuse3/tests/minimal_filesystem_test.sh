#!/usr/bin/env bash
# Test script for minimal filesystem example
# This script tests the basic functionality of the minimal filesystem implementation

set -euo pipefail

MOUNTPOINT="/tmp/rfuse3_minimal_test"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CRATE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

echo "Testing minimal filesystem example..."

# Clean up any existing mount point
if mount | grep -q " on $MOUNTPOINT "; then
    echo "Unmounting existing mount point..."
    # Use platform-specific unmount logic
    if command -v fusermount3 >/dev/null 2>&1; then
        fusermount3 -u "$MOUNTPOINT" || fusermount -u "$MOUNTPOINT" || umount "$MOUNTPOINT" || true
    elif command -v fusermount >/dev/null 2>&1; then
        fusermount -u "$MOUNTPOINT" || umount "$MOUNTPOINT" || true
    else
        umount "$MOUNTPOINT" || true
    fi
fi

# Create mount point
mkdir -p "$MOUNTPOINT"

# Build the example
echo "Building minimal filesystem example..."
cargo build --example minimal_filesystem_example

# Start the filesystem
echo "Starting filesystem at $MOUNTPOINT..."
cargo run --example minimal_filesystem_example -- --mountpoint "$MOUNTPOINT" &
FS_PID=$!

# Set up cleanup trap with platform-specific unmount logic
trap "kill $FS_PID 2>/dev/null || true; \
if command -v fusermount3 >/dev/null 2>&1; then \
    fusermount3 -u $MOUNTPOINT 2>/dev/null || fusermount -u $MOUNTPOINT 2>/dev/null || umount $MOUNTPOINT 2>/dev/null || true; \
elif command -v fusermount >/dev/null 2>&1; then \
    fusermount -u $MOUNTPOINT 2>/dev/null || umount $MOUNTPOINT 2>/dev/null || true; \
else \
    umount $MOUNTPOINT 2>/dev/null || true; \
fi; \
rmdir $MOUNTPOINT 2>/dev/null || true" EXIT

# Wait for filesystem to be ready
sleep 2

# Test basic operations
echo "Testing directory listing..."
ls "$MOUNTPOINT"
ls -l "$MOUNTPOINT"
ls -al "$MOUNTPOINT"

echo "Testing file reading..."
cat "$MOUNTPOINT/hello.txt"

echo "Testing file statistics..."
stat "$MOUNTPOINT"

echo "Test completed successfully!"
