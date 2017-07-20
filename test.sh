#!/bin/bash -eu

./build/checkops &> /dev/null

for i in $(mount | grep -e "/tmp/encfs-reverse-tests-\|/tmp/encfs-tests-" | cut -f3 -d" "); do
	echo "Warning: unmounting leftover filesystem: $i"
	fusermount -u $i
done

perl -MTest::Harness -e '$$Test::Harness::debug=1; runtests @ARGV;' tests/*.t.pl
