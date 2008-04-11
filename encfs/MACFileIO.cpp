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

#include "MACFileIO.h"

#include "MemoryPool.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>

#include <string.h>

#include "i18n.h"

using namespace rlog;
using namespace rel;
using namespace std;
using boost::shared_ptr;
using boost::dynamic_pointer_cast;

static RLogChannel *Info = DEF_CHANNEL("info/MACFileIO", Log_Info);
//
// Version 1.0 worked on blocks of size (blockSize + headerSize).
//   That is, it took [blockSize] worth of user data and added headers.
// Version 2.0 takes [blockSize - headerSize] worth of user data and writes
//   [blockSize] bytes.  That way the size going into the crypto engine is
//   valid from what was selected based on the crypto module allowed ranges!
//
// The information about MACFileIO currently does not make its way into the
// configuration file, so there is no easy way to make this backward
// compatible, except at a high level by checking a revision number for the
// filesystem...
//
static rel::Interface MACFileIO_iface("FileIO/MAC", 2, 0, 0);

MACFileIO::MACFileIO( const shared_ptr<FileIO> &_base,
	const shared_ptr<Cipher> &_cipher,
	const CipherKey &_key, int fsBlockSize,
	int _macBytes, int _randBytes,
	bool warnOnlyMode )
   : BlockFileIO( fsBlockSize - _macBytes - _randBytes )
   , base( _base )
   , cipher( _cipher )
   , key( _key )
   , macBytes( _macBytes )
   , randBytes( _randBytes )
   , warnOnly( warnOnlyMode )
{
    rAssert( macBytes > 0 && macBytes <= 8 );
    rAssert( randBytes >= 0 );
    rLog(Info, "fs block size = %i, macBytes = %i, randBytes = %i",
	    fsBlockSize, macBytes, randBytes);
}

MACFileIO::~MACFileIO()
{
}

rel::Interface MACFileIO::interface() const
{
    return MACFileIO_iface;
}

int MACFileIO::open( int flags )
{
    return base->open( flags );
}

void MACFileIO::setFileName( const char *fileName )
{
    base->setFileName( fileName );
}

const char *MACFileIO::getFileName() const
{
    return base->getFileName();
}

bool MACFileIO::setIV( uint64_t iv )
{
    return base->setIV( iv );
}

inline static off_t roundUpDivide( off_t numerator, int denominator )
{
    // integer arithmetic always rounds down, so we can round up by adding
    // enough so that any value other then a multiple of denominator gets
    // rouned to the next highest value.
    return ( numerator + denominator - 1 ) / denominator;
}

// Convert from a location in the raw file to a location when MAC headers are
// interleved with the data.
// So, if the filesystem stores/encrypts [blockSize] bytes per block, then
//  [blockSize - headerSize] of those bytes will contain user-supplied data,
//  and the rest ([headerSize]) will contain the MAC header for this block.
// Example, offset points to second block (of user-data)
//   offset = blockSize - headerSize
//   ... blockNum = 1
//   ... partialBlock = 0
//   ... adjLoc = 1 * blockSize
static off_t locWithHeader( off_t offset, int blockSize, int headerSize )
{
    off_t blockNum = roundUpDivide( offset , blockSize - headerSize );
    return offset + blockNum * headerSize;
}

// convert from a given location in the stream containing headers, and return a
// location in the user-data stream (which doesn't contain MAC headers)..
// The output value will always be less then the input value, because the
// headers are stored at the beginning of the block, so even the first data is
// offset by the size of the header.
static off_t locWithoutHeader( off_t offset, int blockSize, int headerSize )
{
    off_t blockNum = roundUpDivide( offset , blockSize );
    return offset - blockNum * headerSize;
}

int MACFileIO::getAttr( struct stat *stbuf ) const
{
    int res = base->getAttr( stbuf );

    if(res == 0 && S_ISREG(stbuf->st_mode))
    {
	// have to adjust size field..
	int headerSize = macBytes + randBytes;
	int bs = blockSize() + headerSize;
	stbuf->st_size = locWithoutHeader( stbuf->st_size, bs, headerSize );
    }

    return res;
}

off_t MACFileIO::getSize() const
{
    // adjust the size to hide the header overhead we tack on..
    int headerSize = macBytes + randBytes;
    int bs = blockSize() + headerSize;

    off_t size = base->getSize();
    if(size > 0)
	size = locWithoutHeader( size, bs, headerSize );

    return size;
}

void MACFileIO::allowHoles( bool allow )
{
    BlockFileIO::allowHoles( allow );
    shared_ptr<BlockFileIO> bf = dynamic_pointer_cast<BlockFileIO>( base );
    if(bf)
        bf->allowHoles( allow );
}

ssize_t MACFileIO::readOneBlock( const IORequest &req ) const
{
    int headerSize = macBytes + randBytes;

    int bs = blockSize() + headerSize;

    MemBlock mb = MemoryPool::allocate( bs );

    IORequest tmp;
    tmp.offset = locWithHeader( req.offset, bs, headerSize );
    tmp.data = mb.data;
    tmp.dataLen = headerSize + req.dataLen;

    // get the data from the base FileIO layer
    ssize_t readSize = base->read( tmp );

    // don't store zeros if configured for zero-block pass-through
    bool skipBlock;
    if( _allowHoles )
    {
        skipBlock = true;
        for(int i=0; i<readSize; ++i)
            if(tmp.data[i] != 0)
            {
                skipBlock = false;
                break;
            }
    } else
       skipBlock = false; 

    if(readSize > headerSize)
    {
        if(!skipBlock)
        {
            // At this point the data has been decoded.  So, compute the MAC of
            // the block and check against the checksum stored in the header..
            uint64_t mac = cipher->MAC_64( tmp.data + macBytes, 
                    readSize - macBytes, key );

            for(int i=0; i<macBytes; ++i, mac >>= 8)
            {
                int test = mac & 0xff;
                int stored = tmp.data[i];
                if(test != stored)
                {
                    // uh oh.. 
                    long blockNum = req.offset / bs;
                    rWarning(_("MAC comparison failure in block %li"), 
                            blockNum);
                    if( !warnOnly )
                    {
                        MemoryPool::release( mb );
                        throw ERROR(
                                _("MAC comparison failure, refusing to read"));
                    }
                    break;
                }
            }
        }

	// now copy the data to the output buffer
	readSize -= headerSize;
	memcpy( req.data, tmp.data + headerSize, readSize );
    } else
    {
	rDebug("readSize %i at offset %" PRIi64, (int)readSize, req.offset);
	if(readSize > 0)
	    readSize = 0;
    }

    MemoryPool::release( mb );

    return readSize;
}

bool MACFileIO::writeOneBlock( const IORequest &req )
{
    int headerSize = macBytes + randBytes;

    int bs = blockSize() + headerSize;

    // we have the unencrypted data, so we need to attach a header to it.
    MemBlock mb = MemoryPool::allocate( bs );

    IORequest newReq;
    newReq.offset = locWithHeader( req.offset, bs, headerSize );
    newReq.data = mb.data;
    newReq.dataLen = headerSize + req.dataLen;

    memset( newReq.data, 0, headerSize );
    memcpy( newReq.data + headerSize, req.data, req.dataLen );
    if(randBytes)
	cipher->randomize( newReq.data+macBytes, randBytes );

    // compute the mac (which includes the random data) and fill it in
    uint64_t mac = cipher->MAC_64( newReq.data+macBytes, 
	                           req.dataLen + randBytes, key );

    for(int i=0; i<macBytes; ++i)
    {
	newReq.data[i] = mac & 0xff;
	mac >>= 8;
    }

    // now, we can let the next level have it..
    bool ok = base->write( newReq );

    MemoryPool::release( mb );

    return ok;
}

int MACFileIO::truncate( off_t size )
{
    int headerSize = macBytes + randBytes;
    int bs = blockSize() + headerSize;

    int res =  BlockFileIO::truncate( size, 0 );

    if(res == 0)
	base->truncate( locWithHeader( size, bs, headerSize ) );

    return res;
}

bool MACFileIO::isWritable() const
{
    return base->isWritable();
}
