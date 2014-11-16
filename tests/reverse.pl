#!/usr/bin/perl -w

# Test EncFS --reverse mode

use Test::More qw( no_plan );
use File::Path;
use File::Temp;

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

    rmtree($workingDir);
    ok( ! -d $workingDir, "working dir removed");
}

# Helper function
# Mount encryption-decryption chain
#
# Directory structure: plain -[encrypt]-> ciphertext -[decrypt]-> decrypted
sub mount
{
    qx(./encfs/encfs --extpass="echo test" --standard $plain $ciphertext --reverse > /dev/null);
    ok(-f "$plain/.encfs6.xml", "plain .encfs6.xml exists") or BAIL_OUT("'$plain/.encfs6.xml'");
    $e = encName(".encfs6.xml");
    ok(-f "$ciphertext/$e", "encrypted .encfs6.xml exists") or BAIL_OUT("'$ciphertext/$e'");

    qx(ENCFS6_CONFIG=$plain/.encfs6.xml ./encfs/encfs --extpass="echo test" $ciphertext $decrypted);
    ok(-f "$decrypted/.encfs6.xml", "decrypted .encfs6.xml exists") or BAIL_OUT("'$decrypted/.encfs6.xml'");
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

newWorkingDir();
mount();

copy_test();
symlink_test("/"); # absolute
symlink_test("foo"); # relative
symlink_test("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/15/17/18"); # long
symlink_test("!§\$%&/()\\<>#+="); # special characters

cleanup();
