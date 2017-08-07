#!/bin/bash -eux

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

# This is very noisy so run it silently at first. Run it again with
# output if the first run fails.
./build/checkops &> /dev/null || ./build/checkops

perl -MTest::Harness -e '$$Test::Harness::debug=1; runtests @ARGV;' tests/*.t.pl
