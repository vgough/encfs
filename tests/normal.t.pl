#!/usr/bin/perl -w

# Test EncFS normal and paranoid mode

use Test::More tests => 116;
use File::Path;
use File::Copy;
use File::Temp;
use IO::Handle;

require("tests/common.pl");

my $tempDir = $ENV{'TMPDIR'} || "/tmp";

# test filesystem in standard config mode
&runTests('standard');

# test in paranoia mode
&runTests('paranoia');

# Wrapper function - runs all tests in the specified mode
sub runTests
{
    my $mode = shift;
    print STDERR "\nrunTests: mode=$mode\n";

    &newWorkingDir;

    my $hardlinks = 1;
    if($mode eq 'standard')
    {
        &mount("--standard");
    } elsif($mode eq 'paranoia')
    {
        &mount("--paranoia");
        $hardlinks = 0; # no hardlinks in paranoia mode
        &corruption;
    } else
    {
        die "invalid test mode";
    }

    # tests..
    &fileCreation;
    &links($hardlinks);
    &truncate;
    &renames;
    &internalModification;
    &grow;
    &umask0777;
    &create_unmount_remount;

    &configFromPipe;
    &cleanup;
}

# Helper function
# Create a new empty working directory
sub newWorkingDir
{
    our $workingDir = mkdtemp("$tempDir/encfs-tests-XXXX")
        || BAIL_OUT("Could not create temporary directory");

    our $raw = "$workingDir/raw";
    our $crypt = "$workingDir/crypt";
}

# Test Corruption
# Modify the encrypted file and verify that the MAC check detects it
sub corruption
{
    ok( open(OUT, "+> $crypt/corrupt") && print(OUT "12345678901234567890")
        && close(OUT), "create corruption-test file" );


    $e = encName("corrupt");
    ok( open(OUT, ">> $raw/$e") && print(OUT "garbage") && close(OUT),
        "corrupting raw file");

    ok( open(IN, "< $crypt/corrupt"), "open corrupted file");
    my $content;
    $result = read(IN, $content, 20);
    ok(! defined $result, "corrupted file with MAC returns read error: $!");
}

# Test internal modification
# Create a file of fixed size and overwrite data at different offsets
# (like a database would do)
sub internalModification
{
    $ofile = "$workingDir/crypt-internal-$$";
    writeZeroes($ofile, 2*1024);
    ok(copy($ofile, "$crypt/internal"), "copying crypt-internal file");

    open(my $out1, "+<", "$crypt/internal");
    open(my $out2, "+<", $ofile);

    @fhs = ($out1, $out2);

    $ori = md5fh($out1);
    $b = md5fh($out2);

    ok( $ori eq $b, "random file md5 matches");

    my @offsets = (10, 30, 1020, 1200);
    foreach my $o (@offsets)
    {
        foreach my $fh(@fhs) {
            seek($fh, $o, 0);
            print($fh "garbagegarbagegarbagegarbagegarbage");
        }
        $a=md5fh($out1);
        $b=md5fh($out2);
        ok( ($a eq $b) && ($a ne $ori), "internal modification at $o");
    }

    close($out1);
    close($out2);
}

# Test renames
sub renames
{
    ok( open(F, ">$crypt/orig-name") && close F, "create file for rename test");
    ok( -f "$crypt/orig-name", "file exists");

    ok( rename("$crypt/orig-name", "$crypt/2nd-name"), "rename");
    ok( ! -f "$crypt/orig-name", "file exists");
    ok( -f "$crypt/2nd-name", "file exists");

    # rename directory with contents
    ok( mkpath("$crypt/orig-dir/foo"), "mkdir for rename test");
    ok( open(F, ">$crypt/orig-dir/foo/bar") && close F, "make file");

    ok( rename("$crypt/orig-dir", "$crypt/new-dir"), "rename dir");
    ok( -f "$crypt/new-dir/foo/bar", "dir rename contents");

    # TODO: rename failure? (check undo works)

    # check time stamps of files on rename
    my $mtime = (stat "$crypt/2nd-name")[9];
    # change time to 60 seconds earlier
    my $olderTime = $mtime - 60;
    ok( utime($olderTime, $olderTime, "$crypt/2nd-name"), "change time");

    ok( rename("$crypt/2nd-name", "$crypt/3rd-name"), "rename");
    is( (stat "$crypt/3rd-name")[9], $olderTime, "time unchanged by rename");
}

# Test truncate and grow
sub truncate
{
    # write to file, then truncate it
    ok( open(OUT, "+> $crypt/trunc"), "create truncate-test file");
    autoflush OUT 1;
    print OUT "12345678901234567890";

    is( -s "$crypt/trunc", 20, "initial file size" );

    ok( truncate(OUT, 10), "truncate" );

    is( -s "$crypt/trunc", 10, "truncated file size");
    is( qx(cat "$crypt/trunc"), "1234567890", "truncated file contents");

    # try growing the file as well.
    ok( truncate(OUT, 30), "truncate extend");
    is( -s "$crypt/trunc", 30, "truncated file size");

    seek(OUT, 30, 0);
    print OUT "12345";
    is( -s "$crypt/trunc", 35, "truncated file size");

    is( md5fh(*OUT), "5f170cc34b1944d75d86cc01496292df",
        "content digest");

    # try crossing block boundaries
    seek(OUT, 10000,0);
    print OUT "abcde";

    is( md5fh(*OUT), "117a51c980b64dcd21df097d02206f98",
        "content digest");

    # then truncate back to 35 chars
    truncate(OUT, 35);
    is( md5fh(*OUT), "5f170cc34b1944d75d86cc01496292df",
        "content digest");

    close OUT;
}

# Test file creation and removal
sub fileCreation
{
    # create a file
    qx(date > "$crypt/df.txt");
    ok( -f "$crypt/df.txt", "file created" ) || BAIL_OUT("file create failed");

    # ensure there is an encrypted version.
    my $c = encName("df.txt");
    cmp_ok( length($c), '>', 8, "encrypted name ok" );
    ok( -f "$raw/$c", "encrypted file $raw/$c created" );

    # check contents
    my $count = qx(grep -c crypt-$$ "$crypt/df.txt");
    isnt(scalar($count), 0, "encrypted file readable");

    unlink "$crypt/df.txt";
    ok( ! -f "$crypt/df.txt", "file removal" );
    ok( ! -f "$raw/$c", "file removal" );
}

# Test file growth
sub grow
{
    open(my $fh_a, "+>$crypt/grow");
    open(my $fh_b, "+>$workingDir/grow");

    my $d = "1234567"; # Length 7 so we are not aligned to the block size
    my $len = 7;

    my $old = "";
    my $errs = 0;

    my $i;
    for($i=1; $i<1000; $i++)
    {
        print($fh_a $d);
        print($fh_b $d);

        my $a = md5fh($fh_a);
        my $b = md5fh($fh_b);

        my $size = $len * $i;

        # md5sums must be identical but must have changed
        if($a ne $b || $a eq $old)
        {
            $errs++;
        }

        $old = $a;
    }

    ok($errs == 0, "grow file by $len bytes, $i times");

    close($fh_a);
    close($fh_b);
}

# Helper function
# Check a file's content
sub checkContents
{
    my ($file, $expected, $testName) = @_;

    open(IN, "< $file");
    my $line = <IN>;
    is( $line, $expected, $testName );

    close IN;
}

# Helper function
# Convert plain-text filename to encrypted filename
sub encName
{
    my $plain = shift;
    my $enc = qx(./build/encfsctl encode --extpass="echo test" $raw $plain);
    chomp($enc);
    return $enc;
}

# Test symlinks & hardlinks
sub links
{
    my $hardlinkTests = shift;

    my $contents = "hello world\n";
    ok( open(OUT, "> $crypt/data"), "create file for link test" );
    print OUT $contents;
    close OUT;

    # symlinks
    ok( symlink("$crypt/data", "$crypt/data-fqn") , "fqn symlink");
    checkContents("$crypt/data-fqn", $contents, "fqn link traversal");
    is( readlink("$crypt/data-fqn"), "$crypt/data", "read fqn symlink");

    ok( symlink("data", "$crypt/data-rel"), "local symlink");
    checkContents("$crypt/data-rel", $contents, "rel link traversal");
    is( readlink("$crypt/data-rel"), "data", "read rel symlink");

    SKIP: {
        skip "No hardlink support", 2 unless $hardlinkTests;

        ok( link("$crypt/data", "$crypt/data.2"), "hard link");
        checkContents("$crypt/data.2", $contents, "hardlink read");
    };
}

# Test mount
# Leaves the filesystem mounted - also used as a helper function
sub mount
{
    my $args = shift;

    # When these fail, the rest of the tests makes no sense
    mkdir($raw) || BAIL_OUT("Could not create $raw: $!");
    mkdir($crypt)  || BAIL_OUT("Could not create $crypt: $!");

    delete $ENV{"ENCFS6_CONFIG"};
    remount($args);
    ok( $? == 0, "encfs command returns 0") || BAIL_OUT("");
    ok( -f "$raw/.encfs6.xml",  "created control file") || BAIL_OUT("");
}

# Helper function
# Mount without any prior checks
sub remount
{
    my $args = shift;
    my $cmdline = "./build/encfs --extpass=\"echo test\" $args $raw $crypt 2>&1";
    #                                  This makes sure we get to see stderr ^
    system($cmdline);
}

# Helper function
# Unmount and delete mountpoint
sub cleanup
{
    portable_unmount($crypt);

    rmdir $crypt;
    ok( ! -d $crypt, "unmount ok, mount point removed");

    rmtree($workingDir);
    ok( ! -d $workingDir, "working dir removed");
}

# Test that we can create and write to a a file even if umask is set to 0777
# Regression test for bug https://github.com/vgough/encfs/issues/181
sub umask0777
{
    my $old = umask(0777);
    ok(open(my $fh, "+>$crypt/umask0777"), "open with umask 0777");
    close($fh);
    umask($old);
}

# Test that we can read the configuration from a named pipe
# Regression test for https://github.com/vgough/encfs/issues/253
sub configFromPipe
{
    portable_unmount($crypt);
    rename("$raw/.encfs6.xml", "$raw/.encfs6.xml.orig");
    system("mkfifo $raw/.encfs6.xml");
    my $child = fork();
    unless ($child) {
        &remount("--standard");
        exit;
    }
    system("cat $raw/.encfs6.xml.orig > $raw/.encfs6.xml");
    waitpid($child, 0);
    ok( 0 == $?, "encfs mount with named pipe based config failed");
}

sub create_unmount_remount
{
    my $crypt = "$workingDir/create_remount.crypt";
    my $mnt = "$workingDir/create_remount.mnt";
    mkdir($crypt) || BAIL_OUT($!);
    mkdir($mnt)  || BAIL_OUT($!);

    system("./build/encfs --standard --extpass=\"echo test\" $crypt $mnt 2>&1");
    ok( $? == 0, "encfs command returns 0") || return;
    ok( -f "$crypt/.encfs6.xml",  "created control file") || return;

    # Write some text
    my $contents = "hello world\n";
    ok( open(OUT, "> $mnt/test_file_1"), "write content");
    print OUT $contents;
    close OUT;

    # Unmount
    portable_unmount($mnt);

    # Mount again
    system("./build/encfs --extpass=\"echo test\" $crypt $mnt 2>&1");
    ok( $? == 0, "encfs command returns 0") || return;

    # Check if content is still there
    checkContents("$mnt/test_file_1", $contents);

    portable_unmount($mnt);
}
