#!/bin/bash -eu

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

# Failed tests can leave dangling mounts behind.
todel+=("")
for i in $(mount | grep "/tmp/encfs-tests-" | cut -f3 -d" "); do
	echo "Warning: unmounting leftover filesystem: $i"
	if which fusermount >/dev/null 2>&1
	then
		fusermount -u $i || true
	else
		umount -f $i || true
	fi
	parent=$(echo $i | grep "/tmp/encfs-tests-" | sed 's+\(/tmp/encfs-tests-[^/]*\).*+\1+')
	todel+=("$parent")
done
rm -rf ${todel[@]}

set -x

# This is very noisy so run it silently at first. Run it again with
# output if the first run fails.
./build/checkops >/dev/null 2>&1 || ./build/checkops

perl -MTest::Harness -e '$$Test::Harness::debug=1; runtests @ARGV;' tests/*.t.pl
