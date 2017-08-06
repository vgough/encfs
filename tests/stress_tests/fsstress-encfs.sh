#!/bin/bash -eu
#
# Mount an EncFS filesystem in /tmp and run fsstress against it
# in an infinite loop, only exiting on errors.
#
# You need to have https://github.com/rfjakob/fuse-xfstests or
# https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git
# (which fsstress) downloaded and compiled at $HOME/fuse-xfststs .

cd "$(dirname "$0")"
MYNAME=$(basename $0)

# fsstress binary
FSSTRESS=$HOME/fuse-xfstests/ltp/fsstress
if [ ! -x $FSSTRESS ]
then
	echo "$MYNAME: fsstress binary not found at $FSSTRESS"
	echo "Please clone and compile https://github.com/rfjakob/fuse-xfstests"
	exit 1
fi

# Backing directory
DIR=$(mktemp -d /tmp/fsstress-encfs.XXX)
# Mountpoint
MNT="$DIR.mnt"
mkdir $MNT

# Mount
../../build/encfs -f --extpass "echo test" --standard $DIR $MNT &
disown

sleep 0.5
echo -n "Waiting for mount: "
while ! grep "$MNT fuse" /proc/self/mounts > /dev/null
do
	sleep 1
	echo -n x
done
echo " ok"

# Cleanup trap
trap "kill %1 ; cd / ; fusermount -u -z $MNT ; rm -rf $DIR $MNT" EXIT

echo "Starting fsstress loop"
N=1
while true
do
	# Note: EncFS does not seem to support the FS_IOC_GETFLAGS ioctl that
	# fsstress is using. To get rid of the error messages we set "-f getattr=0"
	# in all fsstress calls.
	echo $N
	mkdir $MNT/fsstress.1
	echo -n "    fsstress.1 "
	$FSSTRESS -r -m 8 -n 1000 -d $MNT/fsstress.1 -f getattr=0 &
	wait

	mkdir $MNT/fsstress.2
	echo -n "    fsstress.2 "
	$FSSTRESS -p 20 -r -m 8 -n 1000 -d $MNT/fsstress.2 -f getattr=0 &
	wait

	mkdir $MNT/fsstress.3
	echo -n "    fsstress.3 "
	$FSSTRESS -p 4 -z -f rmdir=10 -f link=10 -f creat=10 -f mkdir=10 \
		-f rename=30 -f stat=30 -f unlink=30 -f truncate=20 -m 8 \
		-n 1000 -d $MNT/fsstress.3 -f getattr=0 &
	wait

	echo "    rm"
	rm -R $MNT/*

	let N=$N+1
done

