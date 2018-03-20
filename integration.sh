#!/bin/bash -eux

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

perl -I. integration/reverse.t.pl
