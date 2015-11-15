# Portable FUSE unmount
# works on Linux AND OSX
sub portable_unmount {
    my $crypt = shift;
    my $fusermount = qx(which fusermount);
    chomp($fusermount);
    if(-f $fusermount) {
        qx($fusermount -u "$crypt");
    } else {
        qx(umount "$crypt");
    }
}

# Helper function
# Get the MD5 sum of the file open at the filehandle
use Digest::MD5 qw(md5_hex);
sub md5fh
{
    my $fh_orig = shift;
    open(my $fh, "<&", $fh_orig); # Duplicate the file handle so the seek
    seek($fh, 0, 0);              # does not affect the caller
    my $md5 = Digest::MD5->new->addfile($fh)->hexdigest;
    close($fh);
    return $md5;
}

# Get the file size from stat() (by file handle or name)
sub statSize
{
    my $f = shift;
    my @s = stat($f) or die("stat on '$f' failed");
    return $s[7];
}

# Get the file size by read()ing the whole file
sub readSize
{
   my $fh = shift;
   seek($fh, 0, 0);
   my $block = 4*1024;
   my $s;
   my $data;
   my $sum = read($fh, $data, $block);
   while ( $s = read($fh, $data, $block) )
   {
        $sum += $s;
   }
   $data = "";
   return $sum;
}

# Verify that the size of the file passed by filehandle matches the target size s0
# Checks both stat() and read()
sub sizeVerify
{
	my $ok = 1;
	my $fh = shift;
	my $s0 = shift;
	$ss = statSize($fh);
	if ($s0 != $ss) {
		$ok = 0;
		print("# stat size $ss, expected $s0\n");
	}
	$sr = readSize($fh);
	if ($s0 != $sr) {
		$ok = 0;
		print("# read size $sr, expected $s0\n");
	}
	return $ok;
}

# Wait for a file to appear
use Time::HiRes qw(usleep);
sub waitForFile
{
	my $file = shift;
	my $timeout;
	$timeout = shift or $timeout = 5;
	for(my $i = $timeout*10; $i > 0; $i--)
	{
		-f $file and return 1;
		usleep(100000); # 0.1 seconds
	}
	print "# timeout waiting for '$file' to appear\n";
	return 0;
}

# writeZeroes($filename, $size)
# Write zeroes of size $size to file $filename
sub writeZeroes
{
        my $filename = shift;
        my $size = shift;
        open(my $fh, ">", $filename);
        my $bs = 4096; # 4 KiB
        my $block = "\0" x $bs;
        my $remain;
        for($remain = $size; $remain >= $bs; $remain -= $bs)
        {
                print($fh $block) or BAIL_OUT("Could not write to $filename: $!");
        }
        if($remain > 0)
        {
                $block = "\0" x $remain;
                print($fh $block) or BAIL_OUT("Could not write to $filename: $!");
        }
}

# Returns integer $milliseconds from float $seconds
sub ms {
    my $seconds      = shift;
    my $milliseconds = int( $seconds * 1000 );
    return $milliseconds;
}

# stopwatch_start($name)
# start the stopwatch for test "$name"
sub stopwatch_start {
    stopwatch(1, shift);
}

# stopwatch_stop(\@results)
# stop the stopwatch, save time into @results
sub stopwatch_stop {
    stopwatch(0, shift);
}

# See stopwatch_{start,stop} above
use feature 'state';
use Time::HiRes qw( time );
sub stopwatch {
    state $start_time;
    state $name;
    my $start = shift;

    if($start) {
        $name = shift;
        print("* $name... ");
        $start_time = time();
    } else {
        my $delta = ms(time() - $start_time);
        print("$delta ms\n");
        my $results = shift;
        push( @$results, [ $name, $delta, 'ms' ] );
    }
}

# Download linux-3.0.tar.gz unless it already exists ("-c" flag)
sub dl_linuxgz {
    our $linuxgz = "/var/tmp/linux-3.0.tar.gz";
    if ( -e $linuxgz ) { return; }
    print "downloading linux-3.0.tar.gz (92MiB)... ";
    system("wget -nv -c https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.0.tar.gz -O $linuxgz");
    print "done\n";
}

# As this file will be require()'d, it needs to return true
return 1;
