#!/usr/bin/perl -w

# Test EncFS --reverse mode

use warnings;
use Test::More tests => 46;
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
    if ($^O ne "cygwin")
    {
        mkdir($ciphertext);
    }
    else
    {
        $ciphertext = "/cygdrive/x";
    }
    our $decrypted = "$workingDir/decrypted";
    if ($^O ne "cygwin")
    {
        mkdir($decrypted);
    }
    else
    {
        $decrypted = "/cygdrive/y";
    }
}

# Helper function
# Unmount and delete mountpoint
sub cleanup
{
    portable_unmount($decrypted);
    portable_unmount($ciphertext);
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
    delete $ENV{"ENCFS6_CONFIG"};
    system("./build/encfs --extpass=\"echo test\" --standard $plain $ciphertext --reverse --nocache");
    ok(waitForFile("$plain/.encfs6.xml"), "plain .encfs6.xml exists") or BAIL_OUT("'$plain/.encfs6.xml'");
    my $e = encName(".encfs6.xml");
    ok(waitForFile("$ciphertext/$e"), "encrypted .encfs6.xml exists") or BAIL_OUT("'$ciphertext/$e'");
    system("ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfs --noattrcache --nodatacache --extpass=\"echo test\" $ciphertext $decrypted");
    ok(waitForFile("$decrypted/.encfs6.xml"), "decrypted .encfs6.xml exists") or BAIL_OUT("'$decrypted/.encfs6.xml'");
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

# Copy a directory tree and verify that the decrypted data is identical, we also create a foo/.encfs6.xml file, to be sure it correctly shows-up
sub copy_test
{
    # first be sure .encfs6.xml does not show up
    # We does not use -f for this test, as it would succeed, .encfs6.xml is only hidden from readdir.
    my $f = encName(".encfs6.xml");
    cmp_ok( length($f), '>', 8, "encrypted name ok" );
    ok(system("ls -1 $ciphertext | grep -qwF -- $f") != 0, "configuration file .encfs6.xml not visible in $ciphertext");
    # copy test
    ok(system("cp -a encfs $plain && mkdir $plain/foo && touch $plain/foo/.encfs6.xml")==0, "copying files to plain");
    ok(system("diff -r -q --exclude='.encfs6.xml' $plain $decrypted")==0, "decrypted files are identical");
    ok(-f "$plain/encfs/encfs.cpp", "file exists");
    unlink("$plain/encfs/encfs.cpp");
    ok(! -f "$decrypted/encfs.cpp", "file deleted");
}

# Encfsctl cat test
sub encfsctl_cat_test
{
    my $contents = "hello world\n";
    ok(open(OUT, "> $plain/hello.txt"), "create file for encfsctl cat test");
    print OUT $contents;
    close OUT;
    qx(ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfsctl cat --extpass="echo test" $ciphertext hello.txt > $plain/hellodec.txt);
    qx(ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfsctl cat --extpass="echo test" --reverse $plain hello.txt > $plain/helloenc.txt);
    my $cname = encName("hello.txt");
    ok(system("diff -q $plain/helloenc.txt $ciphertext/$cname")==0, "encfsctl correctly encrypts");
    ok(system("diff -q $plain/hello.txt $plain/hellodec.txt")==0, "encfsctl correctly decrypts");
}

# Create symlinks and verify they are correctly decrypted
# Parameter: symlink target
sub symlink_test
{
    my $target = shift;
    ok(symlink($target, "$plain/symlink"), "Symlink create, $plain/symlink -> $target");
    ok(my $dec = readlink("$decrypted/symlink"), "Symlink read, $decrypted/symlink -> $target");
    $dec.="";
    ok($dec eq $target, "Symlink compare, '$target' != '$dec'");
    my $return_code = ($have_xattr) ? system(@binattr, "$decrypted/symlink") : 0;
    is($return_code, 0, "Symlink xattr, $plain/symlink -> $target, extended attributes can be read (return code was $return_code)");
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
    my $max = 9000;
    for($i=5; $i < $max; $i += 5)
    {
        print($pfh "abcde") or die("write failed");
        # autoflush should make sure the write goes to the kernel
        # immediately. Just to be sure, check it here.
        sizeVerify($vfh, $i) or die("unexpected plain file size");
        sizeVerify($cfh, $i) or $ok = 0;
        sizeVerify($dfh, $i) or $ok = 0;
        
        if(md5fh($vfh) ne md5fh($dfh))
        {
            $ok = 0;
            print("# content is different, unified diff:\n");
            system("diff -u $plain/grow $decrypted/grow");
        }

        last unless $ok;
    }
    ok($ok, "ciphertext and decrypted size of file grown to $i bytes");
    close($pfh);
    close($vfh);
    close($cfh);
    close($dfh);
    unlink("$plain/grow"); 
}

sub largeRead {
    writeZeroes("$plain/largeRead", 1024*1024);
    # ciphertext file name
    my $cname = encName("largeRead");
    # cfh ... ciphertext file handle
    ok(open(my $cfh, "<", "$ciphertext/$cname"), "open ciphertext largeRead file");
    ok(sizeVerify($cfh, 1024*1024), "1M file size");
}

# Check that the reverse mount is read-only
# (writing is not supported in reverse mode because of the added
#  complexity and the marginal use case)
sub writesDenied {
    $fn = "$plain/writesDenied";
    writeZeroes($fn, 1024);
    my $efn = $ciphertext . "/" . encName("writesDenied");
    open(my $fh, ">", $efn);
    if( ok( $! == EROFS, "open for write denied, EROFS")) {
        ok( 1, "writing denied, filehandle not open");
    }
    else {
        print($fh "foo");
        ok( $! == EROFS, "writing denied, EROFS");
    }
    $target = $ciphertext . "/" . encName("writesDenied2");
    rename($efn, $target);
    ok( $! == EROFS, "rename denied, EROFS") or die();
    unlink($efn);
    ok( $! == EROFS, "unlink denied, EROFS");
    utime(undef, undef, $efn) ;
    ok( $! == EROFS, "touch denied, EROFS");
    truncate($efn, 10);
    ok( $! == EROFS, "truncate denied, EROFS");
}

# Setup mounts
newWorkingDir();
mount();

# Actual tests
grow();
largeRead();
copy_test();
encfsctl_cat_test();
symlink_test("/"); # absolute
symlink_test("foo"); # relative
symlink_test("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/15/17/18"); # long
if ($^O ne "cygwin")
{
    symlink_test("!§\$%&/()\\<>#+="); # special characters
}
else
{
    symlink_test("!§\$%&/()//<>#+="); # special characters but without \ which is not Windows compliant
}                                     # Absolute symlinks may failed on Windows : https://github.com/billziss-gh/winfsp/issues/153
symlink_test("$plain/foo");
writesDenied();

# Umount and delete files
cleanup();
