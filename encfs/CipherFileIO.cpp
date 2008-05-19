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

#include "CipherFileIO.h"

#include "Cipher.h"
#include "MemoryPool.h"

#include <rlog/rlog.h>

#include <fcntl.h>
#include <cerrno>

using boost::shared_ptr;

/*
    - Version 2:0 adds support for a per-file initialization vector with a
      fixed 8 byte header.  The headers are enabled globally within a
      filesystem at the filesystem configuration level.
      When headers are disabled, 2:0 is compatible with version 1:0.
*/
static rel::Interface CipherFileIO_iface("FileIO/Cipher", 2, 0, 1);

const int HEADER_SIZE = 8; // 64 bit initialization vector..

static bool checkSize( int fsBlockSize, int cipherBlockSize )
{
    int blockBoundary = fsBlockSize % cipherBlockSize ;
    if(blockBoundary != 0)
    {
	rError("CipherFileIO: blocks should be multiple of cipher block size");
	return true;
    } else
	return false;
}

CipherFileIO::CipherFileIO( const shared_ptr<FileIO> &_base, 
	const shared_ptr<Cipher> &_cipher,
	const CipherKey &_key, int fsBlockSize,
	bool uniqueIV, bool _reverseEncryption )
    : BlockFileIO( fsBlockSize )
    , base( _base )
    , cipher( _cipher )
    , key( _key )
    , haveHeader( uniqueIV )
    , externalIV( 0 )
    , fileIV( 0 )
    , lastFlags( 0 )
    , reverseEncryption( _reverseEncryption )
{
    static bool warnOnce = false;

    if(!warnOnce)
	warnOnce = checkSize( fsBlockSize, cipher->cipherBlockSize() );
}

CipherFileIO::~CipherFileIO()
{
}

rel::Interface CipherFileIO::interface() const
{
    return CipherFileIO_iface;
}

int CipherFileIO::open( int flags )
{
    int res = base->open( flags );
    
    if( res >= 0 )
	lastFlags = flags;

    return res;
}

void CipherFileIO::setFileName( const char *fileName )
{
    base->setFileName( fileName );
}

const char *CipherFileIO::getFileName() const
{
    return base->getFileName();
}

bool CipherFileIO::setIV( uint64_t iv )
{
    rDebug("in setIV, current IV = %" PRIu64 ", new IV = %" PRIu64 
	    ", fileIV = %" PRIu64, 
	    externalIV, iv, fileIV);
    if(externalIV == 0)
    {
	// we're just being told about which IV to use.  since we haven't
	// initialized the fileIV, there is no need to just yet..
	externalIV = iv;
	if(fileIV != 0)
	    rWarning("fileIV initialized before externalIV! (%" PRIu64 
		    ", %" PRIu64 ")", fileIV, externalIV);
    } else
    if(haveHeader)
    {
	// we have an old IV, and now a new IV, so we need to update the fileIV
	// on disk.
	if(fileIV == 0)
	{
	    // ensure the file is open for read/write..
	    int newFlags = lastFlags | O_RDWR;
	    int res = base->open( newFlags );
	    if(res < 0)
	    {
		if(res == -EISDIR)
		{
		    // duh -- there are no file headers for directories!
		    externalIV = iv;
		    return base->setIV( iv );
		} else
		{
		    rDebug("writeHeader failed to re-open for write");
		    return false;
		}
	    }
    	    initHeader();
	}

	uint64_t oldIV = externalIV;
	externalIV = iv;
	if(!writeHeader())
	{
	    externalIV = oldIV;
	    return false;
	}
    }

    return base->setIV( iv );
}

int CipherFileIO::getAttr( struct stat *stbuf ) const
{
    int res = base->getAttr( stbuf );
    // adjust size if we have a file header
    if((res == 0) && haveHeader && 
	    S_ISREG(stbuf->st_mode) && (stbuf->st_size > 0))
    {
	rAssert(stbuf->st_size >= HEADER_SIZE);
	stbuf->st_size -= HEADER_SIZE;
    }

    return res;
}

off_t CipherFileIO::getSize() const
{
    off_t size = base->getSize();
    // No check on S_ISREG here -- don't call getSize over getAttr unless this
    // is a normal file!
    if(haveHeader && size > 0)
    {
	rAssert(size >= HEADER_SIZE);
	size -= HEADER_SIZE;
    }
    return size;
}

void CipherFileIO::initHeader( )
{
    // check if the file has a header, and read it if it does..  Otherwise,
    // create one.
    off_t rawSize = base->getSize();
    if(rawSize >= HEADER_SIZE)
    {
	rDebug("reading existing header, rawSize = %" PRIi64, rawSize);
	// has a header.. read it
	unsigned char buf[8] = {0};

	IORequest req;
	req.offset = 0;
	req.data = buf;
	req.dataLen = 8;
	base->read( req );

	cipher->streamDecode( buf, sizeof(buf), externalIV, key );

	fileIV = 0;
	for(int i=0; i<8; ++i)
	    fileIV = (fileIV << 8) | (uint64_t)buf[i];

	rAssert(fileIV != 0); // 0 is never used..
    } else
    {
	rDebug("creating new file IV header");

	unsigned char buf[8] = {0};
	do
	{
	    cipher->randomize( buf, 8 );

	    fileIV = 0;
	    for(int i=0; i<8; ++i)
		fileIV = (fileIV << 8) | (uint64_t)buf[i];

	    if(fileIV == 0)
		rWarning("Unexpected result: randomize returned 8 null bytes!");
	} while(fileIV == 0); // don't accept 0 as an option..

	if( base->isWritable() )
	{
	    cipher->streamEncode( buf, sizeof(buf), externalIV, key );

	    IORequest req;
	    req.offset = 0;
	    req.data = buf;
	    req.dataLen = 8;

	    base->write( req );
	} else
	    rDebug("base not writable, IV not written..");
    }
    rDebug("initHeader finished, fileIV = %" PRIu64 , fileIV);
}

bool CipherFileIO::writeHeader( )
{
    if( !base->isWritable() )
    {
	// open for write..
	int newFlags = lastFlags | O_RDWR;
	if( base->open( newFlags ) < 0 )
	{
	    rDebug("writeHeader failed to re-open for write");
	    return false;
	}
    } 

    if(fileIV == 0)
	rError("Internal error: fileIV == 0 in writeHeader!!!");
    rDebug("writing fileIV %" PRIu64 , fileIV);

    unsigned char buf[8] = {0};
    for(int i=0; i<8; ++i)
    {
	buf[sizeof(buf)-1-i] = (unsigned char)(fileIV & 0xff);
	fileIV >>= 8;
    }

    cipher->streamEncode( buf, sizeof(buf), externalIV, key );

    IORequest req;
    req.offset = 0;
    req.data = buf;
    req.dataLen = 8;

    base->write( req );

    return true;
}

ssize_t CipherFileIO::readOneBlock( const IORequest &req ) const
{
    // read raw data, then decipher it..
    int bs = blockSize();
    off_t blockNum = req.offset / bs;
    
    ssize_t readSize = 0;
    if(haveHeader)
    {
	IORequest tmpReq = req;
	tmpReq.offset += HEADER_SIZE;
	readSize = base->read( tmpReq );
    } else
	readSize = base->read( req );

    bool ok;
    if(readSize > 0)
    {
	if(haveHeader && fileIV == 0)
    	    const_cast<CipherFileIO*>(this)->initHeader();

	if(readSize != bs)
	{
	    ok = streamRead( req.data, (int)readSize, blockNum ^ fileIV); 
	} else
	{
	    ok = blockRead( req.data, (int)readSize, blockNum ^ fileIV); 
	}

	if(!ok)
	{
	    rDebug("decodeBlock failed for block %" PRIi64 ", size %i",
		    blockNum, (int)readSize );
	    readSize = -1;
	}
    } else
	rDebug("readSize zero for offset %" PRIi64, req.offset);

    return readSize;
}


bool CipherFileIO::writeOneBlock( const IORequest &req )
{
    int bs = blockSize();
    off_t blockNum = req.offset / bs;

    if(haveHeader && fileIV == 0)
	initHeader();

    bool ok;
    if( req.dataLen != bs )
    {
	ok = streamWrite( req.data, (int)req.dataLen, 
		blockNum ^ fileIV );
    } else
    {
	ok = blockWrite( req.data, (int)req.dataLen, 
		blockNum ^ fileIV );
    }

    if( ok )
    {
	if(haveHeader)
	{
	    IORequest tmpReq = req;
	    tmpReq.offset += HEADER_SIZE;
	    ok = base->write( tmpReq );
	} else
	    ok = base->write( req );
    } else
    {
	rDebug("encodeBlock failed for block %" PRIi64 ", size %i",
		blockNum, req.dataLen);
	ok = false;
    }
    return ok;
}

bool CipherFileIO::blockWrite( unsigned char *buf, int size, 
	             uint64_t _iv64 ) const
{
    if (!reverseEncryption)
	return cipher->blockEncode( buf, size, _iv64, key );
    else
	return cipher->blockDecode( buf, size, _iv64, key );
} 

bool CipherFileIO::streamWrite( unsigned char *buf, int size, 
	             uint64_t _iv64 ) const
{
    if (!reverseEncryption)
	return cipher->streamEncode( buf, size, _iv64, key );
    else
	return cipher->streamDecode( buf, size, _iv64, key );
} 


bool CipherFileIO::blockRead( unsigned char *buf, int size, 
	             uint64_t _iv64 ) const
{
    if (reverseEncryption)
	return cipher->blockEncode( buf, size, _iv64, key );
    else
    {
        if(_allowHoles)
        {
            // special case - leave all 0's alone
            for(int i=0; i<size; ++i)
                if(buf[i] != 0)
                    return cipher->blockDecode( buf, size, _iv64, key );

            return true;
        } else
            return cipher->blockDecode( buf, size, _iv64, key );
    }
} 

bool CipherFileIO::streamRead( unsigned char *buf, int size, 
	             uint64_t _iv64 ) const
{
    if (reverseEncryption)
	return cipher->streamEncode( buf, size, _iv64, key );
    else
	return cipher->streamDecode( buf, size, _iv64, key );
} 



int CipherFileIO::truncate( off_t size )
{
    int res = 0;
    if(!haveHeader)
    {
	res = BlockFileIO::truncate( size, base.get() );
    } else
    {
	if(0 == fileIV)
	{
	    // empty file.. create the header..
	    if( !base->isWritable() )
	    {
		// open for write..
		int newFlags = lastFlags | O_RDWR;
		if( base->open( newFlags ) < 0 )
		    rDebug("writeHeader failed to re-open for write");
	    }
	    initHeader();
	}

	// can't let BlockFileIO call base->truncate(), since it would be using
	// the wrong size..
	res = BlockFileIO::truncate( size, 0 );

	if(res == 0)
	    base->truncate( size + HEADER_SIZE );
    }
    return res;
}

bool CipherFileIO::isWritable() const
{
    return base->isWritable();
}

