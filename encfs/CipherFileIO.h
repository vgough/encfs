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

#ifndef _CipherFileIO_incl_
#define _CipherFileIO_incl_

#include "BlockFileIO.h"
#include "CipherKey.h"

#include <inttypes.h>

class Cipher;

/*
    Implement the FileIO interface encrypting data in blocks. 
    
    Uses BlockFileIO to handle the block scatter / gather issues.
*/
class CipherFileIO : public BlockFileIO
{
public:
    CipherFileIO( const boost::shared_ptr<FileIO> &base, 
	    const boost::shared_ptr<Cipher> &cipher, 
	    const CipherKey &key, int blockSize,
	    bool uniqueIV, bool reverseEncryption );
    virtual ~CipherFileIO();

    virtual rel::Interface interface() const;

    virtual void setFileName( const char *fileName );
    virtual const char *getFileName() const;
    virtual bool setIV( uint64_t iv );

    virtual int open( int flags );

    virtual int getAttr( struct stat *stbuf ) const;
    virtual off_t getSize() const;

    virtual int truncate( off_t size );

    virtual bool isWritable() const;

private:
    virtual ssize_t readOneBlock( const IORequest &req ) const;
    virtual bool writeOneBlock( const IORequest &req );

    void initHeader();
    bool writeHeader();
    bool blockRead( unsigned char *buf, int size, 
	             uint64_t iv64 ) const;
    bool streamRead( unsigned char *buf, int size, 
	             uint64_t iv64 ) const;
    bool blockWrite( unsigned char *buf, int size, 
	             uint64_t iv64 ) const;
    bool streamWrite( unsigned char *buf, int size, 
	             uint64_t iv64 ) const;

    boost::shared_ptr<FileIO> base;
    boost::shared_ptr<Cipher> cipher;
    CipherKey key;
    // if haveHeader is true, then we have a transparent file header which
    // contains a 64 bit initialization vector.
    bool haveHeader;
    bool externalIVChaining;
    uint64_t externalIV;
    uint64_t fileIV;
    int lastFlags;
    bool reverseEncryption;
};

#endif
