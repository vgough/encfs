#!/bin/bash

# This is the wrapper script for all tests.
# It calls the unit tests and all integration tests.
#
# Functions that are useful in more than one integration test
# should be defined here.

set -eu

# Set up envrionment variables, cd to the correct directory
function init {

	# Make sure we are in the "tests" directory
	TESTDIR=$(dirname $(realpath "$0"))
	cd $TESTDIR

	# Full path to encfs binary
	ENCFS=$(realpath ../encfs/encfs)

	# Directory for temporary files (scratch)
	SCRATCH=$(realpath scratch)
	LOWER=$SCRATCH/lower
	UPPER=$SCRATCH/upper

	# Test number counter
	TESTNO=1

	trap 'echo -e "***\e[31m test(s) FAILED\e[0m"' ERR
}

# Run all test_*.sh files
function run_cli_tests {

	cd $TESTDIR
	for i in $(echo test_*.sh)
	do
		cleanup
		mkdir $SCRATCH
		echo "*** running $i"
		source $i
	done
}

# fresh_mount CONFIG
#
# Mount a fresh, empty encfs filesystem using the encfs config file
# CONFIG as .encfs6.xml. The password must be set to "a".
# The backing files will be at $LOWER, the mounted filesystem at $UPPER.
function fresh_mount {
	cd $TESTDIR
	fusermount -q -u $UPPER 2> /dev/null || true
	wait
	rm -Rf $LOWER $UPPER
	mkdir -p $LOWER $UPPER
	touch $UPPER/not_yet_mounted

	cp $TESTDIR/$1 $SCRATCH/lower/.encfs6.xml

	echo a | $ENCFS -f -S -o nonempty $LOWER $UPPER 2> /dev/null &
	while [ -e $UPPER/not_yet_mounted ]
	do
		sleep 0.1s
	done
}

# Clean up scratch directory
function cleanup {
	test -d $SCRATCH || return 0

	cd $SCRATCH/..
	fusermount -q -u $UPPER 2> /dev/null || true
	wait
	rm -Rf $SCRATCH
}

# Get the plain MD5 sum of a file, without the filename that is output
# by md5sum
# md5sum foo:    5f47bbbd6db883f93f5d00fd05f149ff  foo
# plain_md5 foo: 5f47bbbd6db883f93f5d00fd05f149ff
function md5 {
	OUTPUT=$(md5sum "$1") # Capture md5sum output
	ARRAY=($OUTPUT)       # Split into array
	echo ${ARRAY[0]}      # Return first element
}

# Indicate beginning of a test
# Prints test number and title
function test_begin {
	echo -n "$TESTNO $1: "
	let TESTNO++
}

# Indicate successful completion of a test
function test_ok {
	echo "OK"
}

init

test_begin "Running unit tests"
../encfs/test 2> /dev/null
test_ok

run_cli_tests

echo -e "***\e[32m All tests OK\e[0m"

cleanup
