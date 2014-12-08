#!/usr/bin/perl

# Benchmark EncFS against eCryptfs

use Time::HiRes qw( time );
use File::Temp;
use warnings;

require("tests/common.pl");

# Download linux-3.0.tar.gz unless it already exists ("-c" flag)
sub dl {
    our $linuxgz = "/tmp/linux-3.0.tar.gz";
    print "# downloading linux-3.0.tar.gz... ";
    system("wget -nv -c https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.0.tar.gz -O $linuxgz");
    print "done\n";
}

# Create a new empty working directory
sub newWorkingDir {
    my $prefix     = shift;
    my $workingDir = mkdtemp("$prefix/encfs-performance-XXXX")
      || die("Could not create temporary directory");

    return $workingDir;
}

sub cleanup {
    print "cleaning up...";
    my $workingDir = shift;
    system("umount $workingDir/ecryptfs_plaintext");
    system("fusermount -u $workingDir/encfs_plaintext");
    system("rm -Rf $workingDir");
    print "done\n";
}

sub mount_encfs {
    my $workingDir = shift;

    my $c = "$workingDir/encfs_ciphertext";
    my $p = "$workingDir/encfs_plaintext";

    mkdir($c);
    mkdir($p);

    delete $ENV{"ENCFS6_CONFIG"};
    system("./encfs/encfs --extpass=\"echo test\" --standard $c $p > /dev/null");
    waitForFile("$c/.encfs6.xml") or die("Control file not created");

    print "# encfs mounted on $p\n";

    return $p;
}

sub mount_ecryptfs {
    my $workingDir = shift;

    my $c = "$workingDir/ecryptfs_ciphertext";
    my $p = "$workingDir/ecryptfs_plaintext";

    mkdir($c);
    mkdir($p);

    system("expect -c \"spawn mount -t ecryptfs $c $p\" ./tests/mount-ecryptfs.expect > /dev/null") == 0
      or die("ecryptfs mount failed - are you root?");

    print "# ecryptfs mounted on $p\n";

    return $p;
}

# Returns integer $milliseconds from float $seconds
sub ms {
    my $seconds      = shift;
    my $milliseconds = int( $seconds * 1000 );
    return $milliseconds;
}

sub benchmark {
    my $dir = shift;
    my $start;
    our $linuxgz;
    my $delta;
    my $line;

    my @results = ();

    system("sync");
    print("# stream_write... ");
    $start = time();
    writeZeroes( "$dir/zero", 1024 * 1024 * 100 );
    system("sync");
    $delta = time() - $start;
    push( @results, [ 'stream_write', int( 100 / $delta ), "MiB/s" ] );
    printf("done\n");
    unlink("$dir/zero");

    system("sync");
    system("cat $linuxgz > /dev/null");
    print("# extract... ");
    $start = time();
    system("tar xzf $linuxgz -C $dir");
    system("sync");
    $delta = ms( time() - $start );
    push( @results, [ 'extract', $delta, "ms" ] );
    print("done\n");

    $du = qx(du -sm $dir | cut -f1);
    push( @results, [ 'du', $du, 'MB' ] );
    printf( "# disk space used: %d MB\n", $du );

    system("echo 3 > /proc/sys/vm/drop_caches");
    $start = time();
    system("rsync -an $dir /tmp");
    $delta = time() - $start;
    push( @results, [ 'rsync', ms($delta), 'ms' ] );
    printf( "# rsync took %d ms\n", ms($delta) );

    system("echo 3 > /proc/sys/vm/drop_caches");
    system("sync");
    $start = time();
    system("rm -Rf $dir/*");
    system("sync");
    $delta = time() - $start;
    push( @results, [ 'delete', ms($delta), 'ms' ] );
    printf( "# delete took %d ms\n", ms($delta) );

    return \@results;
}

sub tabulate {
    my $r;

    $r = shift;
    my @encfs = @{$r};
    $r = shift;
    my @ecryptfs = @{$r};

    print "Test            | EncFS        | eCryptfs     | EncFS advantage\n";
    print "----------------|--------------|--------------|----------------\n";

    for ( my $i = 0 ; $i <= $#encfs ; $i++ ) {
        my $test = $encfs[$i][0];
        my $unit = $encfs[$i][2];

        my $en = $encfs[$i][1];
        my $ec = $ecryptfs[$i][1];

        my $ratio = $ec / $en;
        if ( $unit =~ m!/s! ) {
            $ratio = $en / $ec;
        }
        printf( "%-15s | %6d %-5s | %6d %-5s | %2.2f\n",
            $test, $en, $unit, $ec, $unit, $ratio );
    }
}

sub main {
    if ( $#ARGV < 0 ) {
        print "Usage: test/benchmark.pl MOUNTPOINT [MOUNTPOINT] [...]\n";
        exit(1);
    }

    if ( $> != 0 ) {
        print("This test must be run as root!\n");
        exit(2);
    }

    dl();
    my $workingDir;
    my $mountpoint;
    my $prefix;

    while ( $prefix = shift(@ARGV) ) {
        $workingDir = newWorkingDir($prefix);

        print "# mounting encfs\n";
        $mountpoint = mount_encfs($workingDir);
        my $encfs_results = benchmark($mountpoint);

        print "# mounting ecryptfs\n";
        $mountpoint = mount_ecryptfs($workingDir);
        my $ecryptfs_results = benchmark($mountpoint);

        cleanup($workingDir);

        print "\nResults for $prefix\n";
        print "==============================\n\n";
        tabulate( $encfs_results, $ecryptfs_results );
        print "\n";
    }
}

main();
