#!/usr/bin/perl -w

# Test EncFS --reverse mode

use warnings;
use Test::More tests => 70;
use File::Path;
use File::Temp;
use IO::Handle;
use Errno qw(EROFS EIO);

require("tests/common.pl");

my $tempDir = $ENV{'TMPDIR'} || "/tmp";

sub calculateCiphertextSize
{
	my $psize = shift;
	my $mode = shift;

	if ($psize == 0) {
		return 0;
	}

	if ($mode eq 'standard') {
		#in standard mode, just add the 8 bytes header for the IV
		return $psize + 8;
	}

	if ($mode eq 'paranoia') {
		#in paranoia mode, calculate the number of plaintext blocks (1024 - 8 MAC bytes)
		$r = int(($psize + 1016 - 1) / 1016);
		
		#then add the 8 MAC bytes to each block
		$r = $psize + ($r * 8);

		#and finally, add the 8 bytes header for the IV
		return $r + 8;
	}
	
	#shall not happen
	return -1;
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
    our $copy_of_ciphertext = "$workingDir/copy_of_ciphertext";
    mkdir($copy_of_ciphertext);
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
    my $mode = shift;
    delete $ENV{"ENCFS6_CONFIG"};
    system("./build/encfs --extpass=\"echo test\" --$mode $plain $ciphertext --reverse --nocache");
    ok(waitForFile("$plain/.encfs6.xml"), "plain .encfs6.xml exists") or BAIL_OUT("'$plain/.encfs6.xml'");
    my $e = encName(".encfs6.xml");
    ok(waitForFile("$ciphertext/$e"), "encrypted .encfs6.xml exists") or BAIL_OUT("'$ciphertext/$e'");
    system("ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfs --nocache --extpass=\"echo test\" $ciphertext $decrypted");
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
    my $target = shift;
    symlink($target, "$plain/symlink");
    $dec = readlink("$decrypted/symlink");
    ok( $dec eq $target, "symlink to '$target'") or
        print("# (original) $target' != '$dec' (decrypted)\n");
    system("attr", "-l", "$decrypted/symlink");
    my $return_code = $?;
    is($return_code, 0, "symlink to '$target' extended attributes can be read (return code was $return_code)");
    unlink("$plain/symlink");
}

# Grow a file from 0 to x kB and
# * check the ciphertext length is correct (stat + read)
# * check that the decrypted length is correct (stat + read)
# * check that plaintext and decrypted are identical
sub grow {

    my $mode = shift;
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
        sizeVerify($cfh, calculateCiphertextSize($i, $mode)) or $ok = 0;
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
}

sub largeRead {

    my $mode = shift;

    writeZeroes("$plain/largeRead", 1024*1024);

    # ciphertext file name
    my $cname = encName("largeRead");
    # cfh ... ciphertext file handle
    ok(open(my $cfh, "<", "$ciphertext/$cname"), "open ciphertext largeRead file");
    ok(sizeVerify($cfh, calculateCiphertextSize(1024*1024, $mode)), "1M file size");


    # dfh ... decrypted file handle
    ok(open(my $dfh, "<", "$decrypted/largeRead"), "open decrypted largeRead file");
    ok(sizeVerify($dfh, 1024*1024), "1M file size");
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

# Check a file modification outside encfs
# is detected by MAC headers as an I/O error
sub checkMAC {

    #first, mount reverse paranoia
    delete $ENV{"ENCFS6_CONFIG"};
    system("./build/encfs --extpass=\"echo test\" --paranoia $plain $ciphertext --reverse --nocache");
    ok(waitForFile("$plain/.encfs6.xml"), "plain .encfs6.xml exists") or BAIL_OUT("'$plain/.encfs6.xml'");
    my $e = encName(".encfs6.xml");
    ok(waitForFile("$ciphertext/$e"), "encrypted .encfs6.xml exists") or BAIL_OUT("'$ciphertext/$e'");

    #second, copy an encrypted file out, and then modify it
    open(my $pfh, ">", "$plain/MAC_file");
    print($pfh "abcde") or die("write failed");
    $pfh->autoflush;
    my $mac = encName("MAC_file");
    ok(system("cp $ciphertext/$mac $copy_of_ciphertext")==0, "copying files to ciphertext");
    ok(waitForFile("$copy_of_ciphertext/$mac"), "copied MAC_file exists") or BAIL_OUT("'$copy_of_ciphertext/$mac'");
    open(my $cfh, "<", "$copy_of_ciphertext/$mac");
    ok(sizeVerify($cfh, calculateCiphertextSize(5, "paranoia")), "file size error in MAC test");
    ok(system("echo a >>  $copy_of_ciphertext/$mac")==0, "modifying ciphertext outside encfs");

    #third, mount in normal mode and try to read the modified file
    system("ENCFS6_CONFIG=$plain/.encfs6.xml ./build/encfs --nocache --extpass=\"echo test\" $copy_of_ciphertext $decrypted");
    ok(waitForFile("$decrypted/MAC_file"), "decrypted MAC_file exists") or BAIL_OUT("'$decrypted/MAC_file'");

    #fourth, do the read. Test is OK if we get EIO
    ok(open(my $dfh, "<", "$decrypted/MAC_file"), "open decrypted MAC file");
    my $data;
    read($dfh, $data, 1024);
    ok( $! == EIO, "read denied, EIO"); 

}

#First, run tests in standard mode
# Setup mounts
newWorkingDir();
mount("standard");

# Actual tests
grow("standard");
largeRead("standard");
copy_test();
symlink_test("/"); # absolute
symlink_test("foo"); # relative
symlink_test("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/15/17/18"); # long
symlink_test("!§\$%&/()\\<>#+="); # special characters
symlink_test("$plain/foo");
# writesDenied(); # disabled as writes are allowed when (uniqueIV == false), we would need a specific reverse conf with (uniqueIV == true).

# Umount and delete files
cleanup();



#Second, run tests in paranoia mode
# Setup mounts
newWorkingDir();
mount("paranoia");

# Actual tests
grow("paranoia");
largeRead("paranoia");
copy_test();
symlink_test("/"); # absolute
symlink_test("foo"); # relative
symlink_test("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/15/17/18"); # long
symlink_test("!§\$%&/()\\<>#+="); # special characters
symlink_test("$plain/foo");
writesDenied();


# Umount and delete files
cleanup();


#last, do the MAC header testing
#we cannot reuse the previous mounts
newWorkingDir();
checkMAC();
cleanup();

