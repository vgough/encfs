#!/bin/bash -eu

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

# Failed tests can leave dangling mounts behind.
for i in $(mount | grep -e "/tmp/encfs-reverse-tests-\|/tmp/encfs-tests-" | cut -f3 -d" "); do
	echo "Warning: unmounting leftover filesystem: $i"
	fusermount -u $i || true
done

set -x

# This is very noisy so run it silently at first. Run it again with
# output if the first run fails.
./build/checkops &> /dev/null || ./build/checkops

perl -MTest::Harness -e '$$Test::Harness::debug=1; runtests @ARGV;' tests/*.t.pl
