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

#ifndef _BlockFileIO_incl_
#define _BlockFileIO_incl_

#include "FileIO.h"

/*
    Implements block scatter / gather interface.  Requires derived classes to
    implement readOneBlock() / writeOneBlock() at a minimum.  

    When a partial block write is requested it will be turned into a read of
    the existing block, merge with the write request, and a write of the full
    block.
*/
class BlockFileIO : public FileIO
{
public:
    BlockFileIO(int blockDataSize);
    virtual ~BlockFileIO();

    // implemented in terms of blocks.
    virtual ssize_t read( const IORequest &req ) const;
    virtual bool write( const IORequest &req );

    virtual int blockSize() const;

protected:

    // default is false, but setting this to true will allow holes to be stored
    // in the file.  Only works if supported by the underlying FileIO
    // implementation..
    void allowHoles( bool allow );

    int truncate( off_t size, FileIO *base );
    void padFile( off_t oldSize, off_t newSize, bool forceWrite );

    // same as read(), except that the request.offset field is guarenteed to be
    // block aligned, and the request size will not be larger then 1 block.
    virtual ssize_t readOneBlock( const IORequest &req ) const =0;
    virtual bool writeOneBlock( const IORequest &req ) =0;
    
    ssize_t cacheReadOneBlock( const IORequest &req ) const;
    bool cacheWriteOneBlock( const IORequest &req );

    int _blockSize;
    bool _allowHoles;

    // cache last block for speed...
    mutable IORequest _cache;
};

#endif

