#!/usr/bin/perl -w

# Test EncFS standard and paranoid mode

use Test::More tests => 144;
use File::Path;
use File::Copy;
use File::Temp;
use IO::Handle;

require("integration/common.pl");

my $tempDir = $ENV{'TMPDIR'} || "/tmp";
if($^O eq "linux" and $tempDir eq "/tmp") {
   # On Linux, /tmp is often a tmpfs mount that does not
   # support extended attributes. Use /var/tmp instead.
   $tempDir = "/var/tmp";
}

# Find attr binary, Linux
my $setattr = "attr -s encfs -V hello";
my $getattr = "attr -g encfs";
if(system("which xattr >/dev/null 2>&1") == 0)
{
    # Mac OS X
    $setattr = "xattr -sw encfs hello";
    $getattr = "xattr -sp encfs";
}
if(system("which lsextattr >/dev/null 2>&1") == 0)
{
    # FreeBSD
    $setattr = "setextattr -h user encfs hello";
    $getattr = "getextattr -h user encfs";
}

# Do we support xattr ?
my $have_xattr = 1;
if(system("./build/encfs --verbose --version 2>&1 | grep -q HAVE_XATTR") != 0)
{
    $have_xattr = 0;
}

# Did we ask, or are we simply able to run "sudo" tests ?
my $sudo_cmd;
if ($> == 0)
{
    $sudo_cmd="";
}
elsif (defined($ENV{'SUDO_TESTS'}))
{
    $sudo_cmd="sudo";
}

# Test filesystem in standard config mode
my $mode="standard";
&runTests();

# Test filesystem in paranoia config mode
$mode="paranoia";
&runTests();

# Run all tests in the specified mode
sub runTests
{
    print STDERR "\nrunTests: mode=$mode xattr=$have_xattr sudo=";
    print STDERR (defined($sudo_cmd) ? "1" : "0")."\n";

    &newWorkingDir;
    &mount;
    &remount;
    &configFromPipe;

    &fileCreation;
    &renames;
    &links;
    &grow;
    &truncate;
    &internalModification;
    &umask0777;

    &corruption;
    &checkReadError;
    &checkWriteError;

    &cleanup;
}

# Helper to convert plain-text filename to encrypted filename
sub encName
{
    my $plain = shift;
    my $enc = qx(./build/encfsctl encode --extpass="echo test" $ciphertext $plain);
    chomp($enc);
    return $enc;
}

# Create a new empty working directory
sub newWorkingDir
{
    our $workingDir = mkdtemp("$tempDir/encfs-normal-tests-XXXX") || BAIL_OUT("Could not create temporary directory");

    our $ciphertext = "$workingDir/ciphertext";
    mkdir($ciphertext) || BAIL_OUT("Could not create $ciphertext: $!");

    our $decrypted = "$workingDir/decrypted";
    if ($^O eq "cygwin")
    {
        $decrypted = "/cygdrive/x";
    }
    else
    {
        mkdir($decrypted) || BAIL_OUT("Could not create $decrypted: $!");
    }
}

# Unmount and delete mountpoint
sub cleanup
{
    portable_unmount($decrypted);
    ok(waitForFile("$decrypted/mount", 5, 1), "mount test file gone") || BAIL_OUT("");

    rmdir $decrypted;
    ok(! -d $decrypted, "unmount ok, mount point removed");

    rmtree($workingDir);
    ok(! -d $workingDir, "working dir removed");
}

# Mount the filesystem
sub mount
{
    delete $ENV{"ENCFS6_CONFIG"};

    system("./build/encfs --extpass=\"echo test\" --$mode $ciphertext $decrypted");
    ok($? == 0, "encfs mount command returns 0") || BAIL_OUT("");
    ok(-f "$ciphertext/.encfs6.xml",  "created control file") || BAIL_OUT("");

    open(OUT, "> $ciphertext/" . encName("mount"));
    close OUT;
    ok(waitForFile("$decrypted/mount"), "mount test file exists") || BAIL_OUT("");
}

# Remount and verify content, testing -c option at the same time
sub remount
{
    my $contents = "hello world";
    open(OUT, "> $decrypted/remount");
    print OUT $contents;
    close OUT;

    portable_unmount($decrypted);
    ok(waitForFile("$decrypted/mount", 5, 1), "mount test file gone") || BAIL_OUT("");

    rename("$ciphertext/.encfs6.xml", "$ciphertext/.encfs6_moved.xml");
    system("./build/encfs -c $ciphertext/.encfs6_moved.xml --extpass=\"echo test\" $ciphertext $decrypted");
    ok($? == 0, "encfs remount command returns 0") || BAIL_OUT("");
    ok(waitForFile("$decrypted/mount"), "mount test file exists") || BAIL_OUT("");
    rename("$ciphertext/.encfs6_moved.xml", "$ciphertext/.encfs6.xml");

    checkContents("$decrypted/remount", $contents);
}

# Read the configuration from a named pipe (https://github.com/vgough/encfs/issues/253)
sub configFromPipe
{
    portable_unmount($decrypted);
    ok(waitForFile("$decrypted/mount", 5, 1), "mount test file gone") || BAIL_OUT("");

    rename("$ciphertext/.encfs6.xml", "$ciphertext/.encfs6_moved.xml");
    system("mkfifo $ciphertext/.encfs6.xml");
    my $child = fork();
    unless ($child) {
        system("./build/encfs --extpass=\"echo test\" $ciphertext $decrypted");
        exit($? >> 8);
    }
    system("cat $ciphertext/.encfs6_moved.xml > $ciphertext/.encfs6.xml");
    waitpid($child, 0);
    ok($? == 0, "encfs piped command returns 0") || BAIL_OUT("");
    ok(waitForFile("$decrypted/mount"), "mount test file exists") || BAIL_OUT("");
    unlink("$ciphertext/.encfs6.xml");
    rename("$ciphertext/.encfs6_moved.xml", "$ciphertext/.encfs6.xml");
}

# Test file creation and removal
sub fileCreation
{
    # first be sure .encfs6.xml does not show up
    my $f = encName(".encfs6.xml");
    cmp_ok(length($f), '>', 8, "encrypted name ok");
    ok(! -f "$ciphertext/$f", "configuration file .encfs6.xml not visible in $ciphertext");

    # create a file
    system("cat $0 > $decrypted/create");
    ok(-f "$decrypted/create", "file created" ) || BAIL_OUT("file create failed");

    # ensure there is an encrypted version.
    my $c = encName("create");
    cmp_ok(length($c), '>', 8, "encrypted name ok");
    ok(-f "$ciphertext/$c", "encrypted file $ciphertext/$c created");

    # check contents
    system("diff $0 $decrypted/create");
    ok($? == 0, "encrypted file readable");

    unlink "$decrypted/create";
    ok(! -f "$decrypted/create", "file removal");
    ok(! -f "$ciphertext/$c", "file removal");
}

# Test renames
sub renames
{
    ok(open(F, ">$decrypted/rename-orig") && close F, "create file for rename test");
    ok(-f "$decrypted/rename-orig", "file exists");

    ok(rename("$decrypted/rename-orig", "$decrypted/rename-new"), "rename");
    ok(! -f "$decrypted/rename-orig", "file exists");
    ok(-f "$decrypted/rename-new", "file exists");

    # rename directory with contents
    ok(mkpath("$decrypted/rename-dir-orig/foo"), "mkdir for rename test");
    ok(open(F, ">$decrypted/rename-dir-orig/foo/bar") && close F, "make file");

    ok(rename("$decrypted/rename-dir-orig", "$decrypted/rename-dir-new"), "rename dir");
    ok(-f "$decrypted/rename-dir-new/foo/bar", "dir rename contents");

    # TODO: rename failure? (check undo works)

    # check time stamps of files on rename
    my $mtime = (stat "$decrypted/rename-new")[9];
    # change time to 60 seconds earlier
    my $olderTime = $mtime - 60;
    ok(utime($olderTime, $olderTime, "$decrypted/rename-new"), "change time");

    ok(rename("$decrypted/rename-new", "$decrypted/rename-time"), "rename");
    is((stat "$decrypted/rename-time")[9], $olderTime, "time unchanged by rename");

    # TODO: # check time stamps of directories on rename (https://github.com/vgough/encfs/pull/541)
}

# Test symlinks & hardlinks, and extended attributes
sub links
{
    my $contents = "hello world";
    ok(open(OUT, "> $decrypted/link-data"), "create file for link test");
    print OUT $contents;
    close OUT;

    # symlinks
    ok(symlink("$decrypted/link-data", "$decrypted/link-data-fqn") , "fqn symlink");
    checkContents("$decrypted/link-data-fqn", $contents, "fqn link traversal");
    is(readlink("$decrypted/link-data-fqn"), "$decrypted/link-data", "read fqn symlink");

    ok(symlink("link-data", "$decrypted/link-data-rel"), "local symlink");
    checkContents("$decrypted/link-data-rel", $contents, "rel link traversal");
    is(readlink("$decrypted/link-data-rel"), "link-data", "read rel symlink");

    if ($mode eq "standard")
    {
        ok(link("$decrypted/link-data", "$decrypted/link-data-hard"), "hard link");
        checkContents("$decrypted/link-data-hard", $contents, "hardlink read");
    }

    # extended attributes
    SKIP: {
        skip "No xattr support", 3 unless ($have_xattr);

        system("$setattr $decrypted/link-data");
        my $rc = $?;
        is($rc, 0, "extended attributes can be set (return code was $rc)");
        system("$getattr $decrypted/link-data");
        $rc = $?;
        is($rc, 0, "extended attributes can be get (return code was $rc)");
        # this is suppused to fail, so get rid of the error message
        system("$getattr $decrypted/link-data-rel 2>/dev/null");
        $rc = $?;
        isnt($rc, 0, "extended attributes operations do not follow symlinks (return code was $rc)");
    };
}

# Test file growth
sub grow
{
    open(my $fh_a, "+>$decrypted/grow");
    open(my $fh_b, "+>$workingDir/grow");

    my $d = "1234567"; # Length 7 so we are not aligned to the block size
    my $len = 7;

    my $old = "";
    my $errs = 0;

    my $i;
    for ($i=1; $i<1000; $i++)
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

# Test truncate and grow
sub truncate
{
    # write to file, then truncate it
    ok(open(OUT, "+> $decrypted/truncate"), "create truncate-test file");
    autoflush OUT 1;
    print OUT "1234567890ABCDEFGHIJ";

    is(-s "$decrypted/truncate", 20, "initial file size");

    ok(truncate(OUT, 10), "truncate");

    is(-s "$decrypted/truncate", 10, "truncated file size");
    is(qx(cat "$decrypted/truncate"), "1234567890", "truncated file contents");

    # try growing the file as well.
    ok(truncate(OUT, 30), "truncate extend");
    is(-s "$decrypted/truncate", 30, "truncated file size");

    seek(OUT, 30, 0);
    print OUT "12345";
    is(-s "$decrypted/truncate", 35, "truncated file size");

    is(md5fh(*OUT), "5f170cc34b1944d75d86cc01496292df", "content digest");

    # try crossing block boundaries
    seek(OUT, 10000,0);
    print OUT "abcde";

    is(md5fh(*OUT), "117a51c980b64dcd21df097d02206f98", "content digest");

    # then truncate back to 35 chars
    truncate(OUT, 35);
    is(md5fh(*OUT), "5f170cc34b1944d75d86cc01496292df", "content digest");

    close OUT;
}

# Test internal modification
# Create a file of fixed size and overwrite data at different offsets
# (like a database would do)
sub internalModification
{
    $ofile = "$workingDir/internal";
    writeZeroes($ofile, 2*1024);
    ok(copy($ofile, "$decrypted/internal"), "copying crypt-internal file");

    open(my $out1, "+<", "$decrypted/internal");
    open(my $out2, "+<", $ofile);

    @fhs = ($out1, $out2);

    $ori = md5fh($out1);
    $b = md5fh($out2);

    ok($ori eq $b, "random file md5 matches");

    my @offsets = (10, 30, 1020, 1200);
    foreach my $o (@offsets)
    {
        foreach my $fh (@fhs)
        {
            seek($fh, $o, 0);
            print($fh "garbagegarbagegarbagegarbagegarbage");
        }
        $a = md5fh($out1);
        $b = md5fh($out2);
        ok(($a eq $b) && ($a ne $ori), "internal modification at $o");
    }

    close($out1);
    close($out2);
}

# Test that we can create and write to a a 0777 file (https://github.com/vgough/encfs/issues/181)
sub umask0777
{
    my $old = umask(0777);
    ok(open(my $fh, "+>$decrypted/umask0777"), "open with umask 0777");
    close($fh);
    umask($old);
}

# Test Corruption
# Modify the encrypted file and verify that the MAC check detects it
sub corruption
{
    if ($mode ne "paranoia")
    {
        return;
    }

    ok(open(OUT, "+> $decrypted/corruption") && print(OUT "12345678901234567890")
        && close(OUT), "create corruption-test file");


    $e = encName("corruption");
    ok(open(OUT, ">> $ciphertext/$e") && print(OUT "garbage") && close(OUT), "corrupting raw file");

    ok(open(IN, "< $decrypted/corruption"), "open corrupted file");
    my $content;
    $result = read(IN, $content, 20);
    # Cygwin returns EINVAL for now
    ok(($!{EBADMSG} || $!{EINVAL}) && (! defined $result), "corrupted file with MAC returns read error: $!");
}

# Test that read errors are correctly thrown up to us
sub checkReadError
{
    # Not sure how to implement this, so feel free !
    ok(1, "read error");
}

# Test that write errors are correctly thrown up to us
sub checkWriteError
{
    # No OSX impl (for now, feel free to find how to), and requires "sudo".
    SKIP: {
        skip "No tmpfs/sudo support", 6 unless ($^O ne "darwin" && defined($sudo_cmd));

        rename("$ciphertext/.encfs6.xml", "$workingDir/.encfs6.xml");
        $ENV{"ENCFS6_CONFIG"} = "$workingDir/.encfs6.xml";

        my $ciphertext = "$ciphertext.tmpfs";
        mkdir($ciphertext) || BAIL_OUT("Could not create $ciphertext: $!");
        my $decrypted = "$decrypted.tmpfs";
        if ($^O eq "cygwin")
        {
            $decrypted = "/cygdrive/y";
        }
        else
        {
            mkdir($decrypted) || BAIL_OUT("Could not create $decrypted: $!");
        }

        system("$sudo_cmd mount -t tmpfs -o size=1m tmpfs $ciphertext");
        ok($? == 0, "mount command returns 0") || BAIL_OUT("");

        system("./build/encfs --extpass=\"echo test\" $ciphertext $decrypted");
        ok($? == 0, "encfs tmpfs command returns 0") || BAIL_OUT("");

        open(OUT, "> $ciphertext/" . encName("mount"));
        close OUT;
        ok(waitForFile("$decrypted/mount"), "mount test file exists") || BAIL_OUT("");

        ok(open(OUT , "> $decrypted/file"), "write content");
        while (print OUT "0123456789") {}
        ok($!{ENOSPC}, "write returned $! instead of ENOSPC");
        close OUT;

        portable_unmount($decrypted);
        ok(waitForFile("$decrypted/mount", 5, 1), "mount test file gone") || BAIL_OUT("");
        system("$sudo_cmd umount $ciphertext");
    };
}
