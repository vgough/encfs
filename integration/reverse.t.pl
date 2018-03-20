#!/usr/bin/perl -w

# Test EncFS --reverse mode

use warnings;
use File::Path;
use File::Temp;
use IO::Handle;
use Errno qw(EROFS);

require("integration/common.pl");

my $tempDir = $ENV{'TMPDIR'} || "/tmp";

if($^O eq "linux" and $tempDir eq "/tmp") {
   # On Linux, /tmp is often a tmpfs mount that does not support
   # extended attributes. Use /var/tmp instead.
   $tempDir = "/var/tmp";
}

# Find attr binary
# Linux
my @binattr = ("attr", "-l");
if(system("which xattr > /dev/null 2>&1") == 0)
{
    # Mac OS X
    @binattr = ("xattr", "-s");
}
if(system("which lsextattr > /dev/null 2>&1") == 0)
{
    # FreeBSD
    @binattr = ("lsextattr", "-h", "user");
}
# Do we support xattr ?
my $have_xattr = 1;
if(system("./build/encfs --verbose --version 2>&1 | grep -q HAVE_XATTR") != 0)
{
    $have_xattr = 0;
}

# Helper function
# Create a new empty working directory
sub newWorkingDir
{
    our $workingDir = mkdtemp("$tempDir/encfs-reverse-tests-XXXX")
        || BAIL_OUT("Could not create temporary directory");

    our $plain = "$workingDir/plain";
    mkdir($plain);
    our $ciphertext = "$workingDir/ciphertext";
    mkdir($ciphertext);
    our $decrypted = "$workingDir/decrypted";
    mkdir($decrypted);
}

# Helper function
# Unmount and delete mountpoint
sub cleanup
{
    portable_unmount($decrypted);
    portable_unmount($ciphertext);
    our $workingDir;
    rmtree($workingDir);
}

# Helper function
# Mount encryption-decryption chain
#
# Directory structure: plain -[encrypt]-> ciphertext -[decrypt]-> decrypted
sub mount
{
    delete $ENV{"ENCFS6_CONFIG"};
    system("./build/encfs --extpass=\"echo test\" --standard $plain $ciphertext --reverse --nocache");
    my $e = encName(".encfs6.xml");
    system("ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfs --nocache --extpass=\"echo test\" $ciphertext $decrypted");
}

# Helper function
#
# Get encrypted name for file
sub encName
{
	my $name = shift;
	my $enc = qx(ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfsctl encode --extpass="echo test" $ciphertext $name);
	chomp($enc);
	return $enc;
}


# Encfsctl cat test
sub encfsctl_cat_test
{
    my $contents = "hello world\n";
    open(OUT, "> $plain/hello.txt");
    print OUT $contents;
    close OUT;
    print "ENCFS6_CONFIG=$plain/.encfs6.xml catchsegv ./build/encfsctl cat --extpass=\"echo test\" $ciphertext hello.txt > $plain/hellodec.txt\n";
    print "ENCFS6_CONFIG=$plain/.encfs6.xml catchsegv ./build/encfsctl cat --extpass=\"echo test\" --reverse $plain hello.txt > $plain/helloenc.txt\n";
    print "JUST BEFORE ENCFSCTL\n";
    qx(ENCFS6_CONFIG=$plain/.encfs6.xml catchsegv ./build/encfsctl cat --extpass="echo test" $ciphertext hello.txt > $plain/hellodec.txt);
    qx(cat $plain/hellodec.txt >&2);
    print "JUST BETWEEN ENCFSCTL\n";
    qx(ENCFS6_CONFIG=$plain/.encfs6.xml catchsegv ./build/encfsctl cat --extpass="echo test" --reverse $plain hello.txt > $plain/helloenc.txt);
    qx(cat $plain/helloenc.txt >&2);
    print "JUST AFTER ENCFSCTL\n";
    print "JUST BEFORE ENCFSCTL\n";
    qx(ENCFS6_CONFIG=$plain/.encfs6.xml catchsegv ./build/encfsctl cat --extpass="echo test" $ciphertext hello.txt > $plain/hellodec.txt);
    qx(cat $plain/hellodec.txt >&2);
    print "JUST BETWEEN ENCFSCTL\n";
    qx(ENCFS6_CONFIG=$plain/.encfs6.xml catchsegv ./build/encfsctl cat --extpass="echo test" --reverse $plain hello.txt > $plain/helloenc.txt);
    qx(cat $plain/helloenc.txt >&2);
    print "JUST AFTER ENCFSCTL\n";
    my $cname = encName("hello.txt");
}



# Setup mounts
newWorkingDir();
mount();

# Actual tests
#grow();
#largeRead();
#copy_test();
encfsctl_cat_test();
#symlink_test("/"); # absolute
#symlink_test("foo"); # relative
#symlink_test("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/15/17/18"); # long
#symlink_test("!§\$%&/()\\<>#+="); # special characters
#symlink_test("$plain/foo");
#writesDenied();

# Umount and delete files
cleanup();
