#!/usr/bin/perl -w

# Test EncFS --reverse mode

use Test::More qw( no_plan );
use File::Path;
use File::Temp;

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
    my $r=system("encfs --extpass=\"echo test\" --standard $plain $ciphertext --reverse > /dev/null");
    ok($r == 0, "mounted ciphertext file system");

    $r=system("ENCFS6_CONFIG=$plain/.encfs6.xml encfs --extpass=\"echo test\" $ciphertext $decrypted");
    ok($r == 0, "mounted decrypting file system");
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

newWorkingDir();
mount();

copy_test();

cleanup();
