#!/bin/sh

rm m4/[c-z]*.m4

echo Creating autoconf scripts...
sh ./reconfig.sh

echo Configuring...
./configure

sh ./makedist2.sh

