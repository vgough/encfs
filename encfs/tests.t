#!/usr/bin/perl -w

use Test::More qw( no_plan );
use File::Path;
use IO::Handle;
use Digest::MD5;

my $tempDir = $ENV{'TMPDIR'} || "/tmp";

my $raw = "$tempDir/crypt-raw-$$";
my $crypt = "$tempDir/crypt-$$";


# test filesystem in standard config mode
&runTests('standard');

# test in paranoia mode
&runTests('paranoia');



sub runTests
{
    my $mode = shift;

    my $hardlinks = 1;
    if($mode eq 'standard')
    {
        &mount("--standard");
    } elsif($mode eq 'paranoia')
    {
        &mount("--paranoia");
        $hardlinks = 0; # no hardlinks in paranoia mode
    } else
    {
        die "invalid test mode";
    }

    # tests..
    &fileCreation;
    &links($hardlinks);
    &truncate;
    &renames;

    &cleanup;
}

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

    seek(OUT, 0, 0);
    is( Digest::MD5->new->addfile(*OUT)->hexdigest, 
        "5f170cc34b1944d75d86cc01496292df", "content digest");

    # try crossing block boundaries
    seek(OUT, 10000,0);
    print OUT "abcde";
    seek(OUT, 0, 0);
    is( Digest::MD5->new->addfile(*OUT)->hexdigest, 
        "117a51c980b64dcd21df097d02206f98", "content digest");

    # then truncate back to 35 chars
    truncate(OUT, 35);
    seek(OUT, 0, 0);
    is( Digest::MD5->new->addfile(*OUT)->hexdigest, 
        "5f170cc34b1944d75d86cc01496292df", "content digest");

    close OUT;
}

sub fileCreation
{
    # create a file
    qx(df -ah > "$crypt/df.txt");
    ok( -f "$crypt/df.txt", "file created" );
    
    # ensure there is an encrypted version.
    my $c = qx(./encfsctl encode --extpass="echo test" $raw df.txt);
    chomp($c);
    cmp_ok( length($c), '>', 8, "encrypted name ok" );
    ok( -f "$raw/$c", "encrypted file created" );

    # check contents
    my $count = qx(grep -c crypt-$$ "$crypt/df.txt");
    isnt(scalar($count), 0, "encrypted file readable");

    unlink "$crypt/df.txt";
    ok( ! -f "$crypt/df.txt", "file removal" );
    ok( ! -f "$raw/$c", "file removal" );
}

sub checkContents
{
    my ($file, $expected, $testName) = @_;

    open(IN, "< $file");
    my $line = <IN>;
    is( $line, $expected, $testName );

    close IN;
}

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
        skip "No hardlink support" unless $hardlinkTests;
        
        ok( link("$crypt/data", "$crypt/data.2"), "hard link");
        checkContents("$crypt/data.2", $contents, "hardlink read");
    };
}

sub mount
{
    my $args = shift;

    ok( ! -d $raw, "no existing dir");
    ok( ! -d $crypt, "no existing dir");

    mkdir $raw;
    ok( -d $raw, "created dir" );
    mkdir $crypt;
    ok( -d $crypt, "created dir" );

    qx(./encfs --extpass="echo test" $args $raw $crypt);

    ok( -f "$raw/.encfs6.xml",  "created control file");
}

sub cleanup
{
    my $fusermount = qx(which fusermount);
    if(-f $fusermount)
    {
        qx($fusermount -u "$crypt");
    } else
    {
        qx(umount "$crypt");
    }

    rmdir $crypt;
    ok( ! -d $crypt, "unmount ok, mount point removed");

    if(-d $raw)
    {
        rmtree($raw);
    }
    ok( ! -d $raw, "encrypted directory removed");
}

