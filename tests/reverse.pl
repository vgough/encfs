#!/usr/bin/perl -w

# Test EncFS --reverse mode

use warnings;
use Test::More qw( no_plan );
use File::Path;
use File::Temp;
use IO::Handle;

require("tests/common.inc");

my $tempDir = $ENV{'TMPDIR'} || "/tmp";

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
    system("fusermount -u $decrypted");
    system("fusermount -u $ciphertext");
    our $workingDir;
    rmtree($workingDir);
    ok( ! -d $workingDir, "working dir removed");
}

# Helper function
# Mount encryption-decryption chain
#
# Directory structure: plain -[encrypt]-> ciphertext -[decrypt]-> decrypted
sub mount
{
    system("./encfs/encfs --extpass=\"echo test\" --standard $plain $ciphertext --reverse");
    ok(waitForFile("$plain/.encfs6.xml"), "plain .encfs6.xml exists") or BAIL_OUT("'$plain/.encfs6.xml'");
    my $e = encName(".encfs6.xml");
    ok(waitForFile("$ciphertext/$e"), "encrypted .encfs6.xml exists") or BAIL_OUT("'$ciphertext/$e'");
    system("ENCFS6_CONFIG=$plain/.encfs6.xml ./encfs/encfs -o attr_timeout=0 --extpass=\"echo test\" $ciphertext $decrypted");
    ok(waitForFile("$decrypted/.encfs6.xml"), "decrypted .encfs6.xml exists") or BAIL_OUT("'$decrypted/.encfs6.xml'");
}

# Helper function
#
# Get encrypted name for file
sub encName
{
	my $name = shift;
	my $enc = qx(ENCFS6_CONFIG=$plain/.encfs6.xml ./encfs/encfsctl encode --extpass="echo test" $ciphertext $name);
	chomp($enc);
	return $enc;
}

# Copy a directory tree and verify that the decrypted data is identical
sub copy_test
{
    ok(system("cp -a encfs $plain")==0, "copying files to plain");
    ok(system("diff -r -q $plain $decrypted")==0, "decrypted files are identical");

    ok(-f "$plain/encfs/encfs.cpp", "file exists");
    unlink("$plain/encfs/encfs.cpp");
    ok(! -f "$decrypted/encfs.cpp", "file deleted");
}

# Create symlinks and verify they are correctly decrypted
# Parameter: symlink target
sub symlink_test
{
    my $target = shift(@_);
    symlink($target, "$plain/symlink");
    ok( readlink("$decrypted/symlink") eq "$target", "symlink to '$target'");
    unlink("$plain/symlink");
}

# Grow a file from 0 to x kB and
# * check the ciphertext length is correct (stat + read)
# * check that the decrypted length is correct (stat + read)
# * check that plaintext and decrypted are identical
sub grow {
	# pfh ... plaintext file handle
	open(my $pfh, ">", "$plain/grow");
	# vfh ... verification file handle
	open(my $vfh, "<", "$plain/grow");
	$pfh->autoflush;
	# ciphertext file name
	my $cname = encName("grow");
	# cfh ... ciphertext file handle
	ok(open(my $cfh, "<", "$ciphertext/$cname"), "open ciphertext grow file");
	# dfh ... decrypted file handle
	ok(open(my $dfh, "<", "$decrypted/grow"), "open decrypted grow file");

	# csz ... ciphertext size
	ok(sizeVerify($cfh, 0), "ciphertext of empty file is empty");
	ok(sizeVerify($dfh, 0), "decrypted empty file is empty");

	my $ok = 1;
	for($i=1; $i < 20; $i++)
	{
		print($pfh "w") or die("write failed");
		# autoflush should make sure the write goes to the kernel
		# immediately. Just to be sure, check it here.
		sizeVerify($vfh, $i) or die("unexpected plain file size");
		sizeVerify($cfh, $i) or $ok = 0;
        sizeVerify($dfh, $i) or $ok = 0;
	}
	ok($ok, "ciphertext and decrypted size of file grown to $i bytes");
}

newWorkingDir();
mount();

copy_test();
symlink_test("/"); # absolute
symlink_test("foo"); # relative
symlink_test("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/15/17/18"); # long
symlink_test("!§\$%&/()\\<>#+="); # special characters
grow();

cleanup();
