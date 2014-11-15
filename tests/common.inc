# Helper function
# Get the MD5 sum of the file open at the filehandle
sub md5fh
{
    my $fh_orig = shift;
    open(my $fh, "<&", $fh_orig); # Duplicate the file handle so the seek
    seek($fh, 0, 0);              # does not affect the caller
    my $md5 = Digest::MD5->new->addfile($fh)->hexdigest;
    close($fh);
    return $md5;
}

# As this file will be require()'d, it needs to return true
return 1;
