#!/bin/bash -eux

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

perl -I. -MTest::Harness -e '$$Test::Harness::debug=1; runtests @ARGV;' integration/*.t.pl
