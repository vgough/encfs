
if BUILD_NLS
NLS_DIR = po
endif

SUBDIRS = encfs m4 $(NLS_DIR)


EXTRA_DIST = encfs.spec intl/gettext.h tests README.md

AUTOMAKE_OPTIONS = foreign 

MAINTAINERCLEANFILES = aclocal.m4 


ACLOCAL_AMFLAGS = -I m4

.PHONY: test
test:
	perl -MTest::Harness -e '$$Test::Harness::verbose=0; runtests @ARGV;' tests/*.t.pl

.PHONY: test-verbose
test-verbose:
	perl -MTest::Harness -e '$$Test::Harness::verbose=1; runtests @ARGV;' tests/*.t.pl

.PHONY: benchmark
benchmark:
	sudo tests/benchmark.pl /var/tmp

.PHONY: benchmark-reverse
benchmark-reverse:
	tests/benchmark-reverse.pl /var/tmp
	tests/benchmark-reverse.pl /var/tmp --nocache
