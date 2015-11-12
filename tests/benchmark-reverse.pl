#!/usr/bin/perl

# Benchmark EncFS reverse mode

use File::Temp;
use warnings;

require("tests/common.pl");

sub mount_encfs_reverse {
    my $p = shift;
    my $c = shift;
    my $opts = shift;

    my $cmdline = "./build/encfs --extpass=\"echo test\" --standard $p $c --reverse $opts 2>&1 > /dev/null";
    # print "mounting encfs: $cmdline\n";
    my $status = system($cmdline);
    if ( $status != 0 ) { die("command returned error: $status"); }
    waitForFile("$p/.encfs6.xml") or die("Control file not created");

    # print "encfs --reverse mounted on $c\n";
}

sub cleanup {
    print "cleaning up... ";
    my $workingDir = shift;
    for(my $i=0; $i<2; $i++) {
      system("fusermount -u $workingDir/c") == 0 and last;
      system("lsof $workingDir/c");
      printf "retrying... ";
      sleep(1);
    }
    system("rm -Rf $workingDir 2> /dev/null");
    print "done\n";
}

sub main {

  my $prefix     = shift(@ARGV) or die("Missing DIR argument");
  my $workingDir = mkdtemp("$prefix/encfs-performance-XXXX")
      || die("Could not create temporary directory");

  my $c = "$workingDir/c";
  my $p = "$workingDir/p";

  my $opts = "";
  if ( @ARGV > 0 ) {
    $opts = shift(@ARGV)
  };
  
  mkdir($c);
  mkdir($p);

  dl_linuxgz();
  our $linuxgz;
  system("tar xzf $linuxgz -C $p");

  mount_encfs_reverse($p, $c, $opts);

  my @results = ();
  stopwatch_start("rsync 1 (initial copy)");
    system("rsync -a $c/ $workingDir/rsync-target");
  stopwatch_stop(\@results);
  
  stopwatch_start("rsync 2 (no changes)");
    system("rsync -a $c/ $workingDir/rsync-target");
  stopwatch_stop(\@results);
  
  cleanup($workingDir);
}

main();
