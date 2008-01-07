#!/bin/sh

echo Creating autoconf scripts...
sh ./reconfig.sh

echo Configuring...
./configure

sh ./makedist2.sh

