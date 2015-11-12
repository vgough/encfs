#!/bin/bash

set -eux

if [ ! -d build ]
then
	./build.sh
fi

perl -MTest::Harness -e '$$Test::Harness::verbose=1; runtests @ARGV;' tests/*.t.pl
