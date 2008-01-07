/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 */

#ifdef linux
#define _XOPEN_SOURCE 500 // pick up pread , pwrite
#endif
#include <unistd.h>

#include "RawFileIO.h"

#include <rlog/rlog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <errno.h>

using namespace std;

static rel::Interface RawFileIO_iface("FileIO/Raw", 1, 0, 0);

FileIO *NewRawFileIO( const rel::Interface &iface )
{
    (void)iface;
    return new RawFileIO();
}

inline void swap( int &x, int &y )
{
    int tmp = x;
    x = y;
    y = tmp;
}

RawFileIO::RawFileIO( )
    : knownSize( false )
    , fileSize(0)
    , fd( -1 )
    , oldfd( -1 )
    , canWrite( false )
{
}

RawFileIO::RawFileIO( const std::string &fileName )
    : name( fileName )
    , knownSize( false )
    , fileSize( 0 )
    , fd( -1 )
    , oldfd( -1 )
    , canWrite( false )
{
}

RawFileIO::~RawFileIO()
{
    int _fd = -1;
    int _oldfd = -1;

    swap( _fd, fd );
    swap( _oldfd, oldfd );

    if( _oldfd != -1 )
	close( _oldfd );
    
    if( _fd != -1 )
	close( _fd );
}

rel::Interface RawFileIO::interface() const
{
    return RawFileIO_iface;
}

/*
    Workaround for opening a file for write when permissions don't allow.
    Since the kernel has already checked permissions, we can assume it is ok to
    provide access.  So force it by changing permissions temporarily.  Should
    be called with a lock around it so that there won't be a race condition
    with calls to lstat picking up the wrong permissions.
*/
static int open_readonly_workaround(const char *path, int flags)
{
    int fd = -1;
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(struct stat));
    if(lstat( path, &stbuf ) != -1)
    {
	// make sure user has read/write permission..
	chmod( path , stbuf.st_mode | 0600 );
	fd = ::open( path , flags );
	chmod( path , stbuf.st_mode );
    } else
    {
	rInfo("can't stat file %s", path );
    }

    return fd;
}

/*
    We shouldn't have to support all possible open flags, so untaint the flags
    argument by only taking ones we understand and accept.
    -  Since the kernel has already done permission tests before calling us, we
       shouldn't have to worry about access control.
    -  Basically we just need to distinguish between read and write flags
    -  Also keep the O_LARGEFILE flag, in case the underlying filesystem needs
       it..
*/
int RawFileIO::open(int flags)
{
    bool requestWrite = ((flags & O_RDWR) || (flags & O_WRONLY));

    rDebug("open call for %s file", requestWrite ? "writable" : "read only");

    int result = 0;

    // if we have a descriptor and it is writable, or we don't need writable..
    if((fd >= 0) && (canWrite || !requestWrite))
    {
	rDebug("using existing file descriptor");
	result = fd; // success
    } else
    {
	int finalFlags = requestWrite ? O_RDWR : O_RDONLY;

#if defined(O_LARGEFILE)
	if( flags & O_LARGEFILE )
	    finalFlags |= O_LARGEFILE;
#else
#warning O_LARGEFILE not supported
#endif

	int newFd = ::open( name.c_str(), finalFlags );
	
	rDebug("open file with flags %i, result = %i", finalFlags, newFd);

	if((newFd == -1) && (errno == EACCES))
	{
	    rDebug("using readonly workaround for open");
	    newFd = open_readonly_workaround( name.c_str(), finalFlags );
	}

	if(newFd >= 0)
	{
	    if(oldfd >= 0)
	    {
		rError("leaking FD?: oldfd = %i, fd = %i, newfd = %i", 
			oldfd, fd, newFd);
	    }

	    // the old fd might still be in use, so just keep it around for
	    // now.
	    canWrite = requestWrite;
	    oldfd = fd;
	    result = fd = newFd;
	} else
	{
	    result = -errno;
	    rInfo("::open error: %s", strerror(errno));
	}
    }

    if(result < 0)
	rInfo("file %s open failure: %i", name.c_str(), -result);

    return result;
}

int RawFileIO::getAttr( struct stat *stbuf ) const
{
    int res = lstat( name.c_str(), stbuf );
    int eno = errno;

    if(res < 0)
	rInfo("getAttr error on %s: %s", name.c_str(), strerror( eno ));

    return ( res < 0 ) ? -eno : 0;
}

void RawFileIO::setFileName( const char *fileName )
{
    name = fileName;
}

const char *RawFileIO::getFileName() const
{
    return name.c_str();
}

off_t RawFileIO::getSize() const
{
    if(!knownSize)
    {
	struct stat stbuf;
	memset( &stbuf, 0, sizeof( struct stat ));
	int res = lstat( name.c_str(), &stbuf );

	if(res == 0)
	{
	    const_cast<RawFileIO*>(this)->fileSize = stbuf.st_size;
	    const_cast<RawFileIO*>(this)->knownSize = true;
	    return fileSize;
	} else
	    return -1;
    } else
    {
	return fileSize;
    }
}

ssize_t RawFileIO::read( const IORequest &req ) const
{
    rAssert( fd >= 0 );

    ssize_t readSize = pread( fd, req.data, req.dataLen, req.offset );

    if(readSize < 0)
    {
	rInfo("read failed at offset %" PRIi64 " for %i bytes: %s",
		req.offset, req.dataLen, strerror( errno ));
    }

    return readSize;
}

bool RawFileIO::write( const IORequest &req )
{
    rAssert( fd >= 0 );
    rAssert( true == canWrite );

    int retrys = 10;
    void *buf = req.data;
    ssize_t bytes = req.dataLen;
    off_t offset = req.offset;

    while( bytes && retrys > 0 )
    {
	ssize_t writeSize = ::pwrite( fd, buf, bytes, offset );

	if( writeSize < 0 )
	{
	    knownSize = false;
	    rInfo("write failed at offset %" PRIi64 " for %i bytes: %s",
		    offset, (int)bytes, strerror( errno ));
	    return false;
	}
	    
	bytes -= writeSize;
	offset += writeSize;
	buf = (void*)((char*)buf + writeSize);
	--retrys;
    }

    if(bytes != 0)
    {
	rError("Write error: wrote %i bytes of %i, max retries reached\n",
		(int)(req.dataLen - bytes), req.dataLen );
	knownSize = false;
	return false;
    } else
    {
	if(knownSize)
	{
	    off_t last = req.offset + req.dataLen;
	    if(last > fileSize)
		fileSize = last;
	}

	return true;
    }
}

int RawFileIO::truncate( off_t size )
{
    int res;

    if(fd >= 0 && canWrite)
    {
	res = ::ftruncate( fd, size );
#ifndef __FreeBSD__
	::fdatasync( fd );
#endif
    } else
	res = ::truncate( name.c_str(), size );

    if(res < 0)
    {
	int eno = errno;
	rInfo("truncate failed for %s (%i) size %" PRIi64 ", error %s",
		name.c_str(), fd, size, strerror(eno));
	res = -eno;
	knownSize = false;
    } else
    {
	res = 0;
	fileSize = size;
	knownSize = true;
    }

    return res;
}

bool RawFileIO::isWritable() const
{
    return canWrite;
}
