EncFS Performance
=================

EncFS runs in user-space while eCryptfs runs in the kernel.
This is why it is often assumed that eCryptfs is faster than EncFS.
To compare the actual performance of EncFS and eCryptfs on top of
different backing disks, the EncFS test suite contains an automated
performance test - [benchmark.pl](tests/benchmark.pl).

performance.pl takes care of setting up EncFS and eCryptfs mounts,
clearing caches and syncing disks between the tests, and also to unmount
and clean up everything in the end.

It performance the following tests:

* stream_write: Write 100MB of zeros in 4KB blocks
* extract: Extract the [linux-3.0.tar.gz archive](https://www.kernel.org/pub/linux/kernel/v3.x/)
* du: Disk space used after extraction, in megabytes
* rsync: Do an "rsync -an" of the extracted files.
  This simulates an rsync to a destination that is
  (almost) up-to-date. The workload consists mostly
  of stat() calls.
* delete: Recursively delete the extracted files

For EncFS, the [default options](tests/benchmark.pl#L47) are used.
This means:

* AES with 192 bit key
* Filename encryption

For eCryptfs, the [options used](tests/mount-ecryptfs.expect) are

* AES with 128 bit key
* Filename encryption

For all the details, take a look at [benchmark.pl](tests/benchmark.pl) .

Results
-------
The performance of an overlay filesystem depends a lot on the performance
of the backing disk. This is why I have tested three different kinds of
disk:

* Classic HDD: Seagate Barracuda 7200.9, model ST3250824AS
* Modern SSD: Samsung SSD 840 EVO 250GB
* Ramdisk: tmpfs mounted on /tmp

All tests are performed on kernel 3.16.3, 64 bit, on an Intel Pentium
G630 (Sandy Bridge, 2 x 2.7GHz).

If you want to replicate the test, just run

    sudo tests/benchmark.pl /path/to/test/directory

(the test must be run as root as normal users cannot mount ecryptfs or
clear the caches)

* HDD: Seagate Barracuda 7200.9

Test            | EncFS        | eCryptfs     | EncFS advantage
----------------|-------------:|-------------:|---------------:
stream_write    |     32 MiB/s |     38 MiB/s | 0.84
extract         |  28744 ms    |  30027 ms    | 1.04
du              |    495 MB    |    784 MB    | 1.58
rsync           |   3319 ms    |  62486 ms    | 18.83
delete          |   6462 ms    |  74652 ms    | 11.55


* SSD: Samsung SSD 840 EVO 250GB

Test            | EncFS        | eCryptfs     | EncFS advantage
----------------|-------------:|-------------:|---------------:
stream_write    |     53 MiB/s |     75 MiB/s | 0.71
extract         |  26129 ms    |   9692 ms    | 0.37
du              |    495 MB    |    784 MB    | 1.58
rsync           |   2725 ms    |   8210 ms    | 3.01
delete          |   5444 ms    |   9130 ms    | 1.68

* Ramdisk: tmpfs

Test            | EncFS        | eCryptfs     | EncFS advantage
----------------|-------------:|-------------:|---------------:
stream_write    |     82 MiB/s |    111 MiB/s | 0.74
extract         |  22393 ms    |   8117 ms    | 0.36
du              |    485 MB    |    773 MB    | 1.59
rsync           |   1931 ms    |    740 ms    | 0.38
delete          |   4346 ms    |    907 ms    | 0.21

Interpretation
--------------
eCryptfs uses a large per-file header (8 KB) which is a big disadvantage
on classic HDDs. For stat()-heavy operations on HDDs, EncFS is 18x faster.

EncFS stores small files much more efficiently, which is why it consitently
uses less space than eCryptfs: zero-size files take no space at all,
other files get a 8-byte header. Because the filesystem allocates space
in 4KB blocks, the actually used disk space must be rounded up to 4096.

plaintext size | EncFS raw | EncFS du | eCryptfs raw | eCryptfs du
--------------:|----------:|---------:|-------------:|------------:
   0           |    0      |    0     |  8192        |  8192
   1           |    9      | 4096     | 12288        | 12288
1024           | 1032      | 4096     | 12288        | 12288
