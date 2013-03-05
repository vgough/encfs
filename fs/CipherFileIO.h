/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.  
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CipherFileIO_incl_
#define _CipherFileIO_incl_

#include "cipher/CipherKey.h"
#include "fs/BlockFileIO.h"
#include "fs/FileUtils.h"

#include <inttypes.h>

namespace encfs {

class CipherV1;

/*
    Implement the FileIO interface encrypting data in blocks. 
    
    Uses BlockFileIO to handle the block scatter / gather issues.
*/
class CipherFileIO : public BlockFileIO
{
public:
    CipherFileIO( const shared_ptr<FileIO> &base, 
                  const FSConfigPtr &cfg);
    virtual ~CipherFileIO();

    virtual Interface interface() const;

    virtual void setFileName( const char *fileName );
    virtual const char *getFileName() const;
    virtual bool setIV( uint64_t iv );

    virtual int open( int flags );

    virtual int getAttr( struct stat *stbuf ) const;
    virtual off_t getSize() const;

    // NOTE: if truncate is used to extend the file, the extended plaintext is
    // not 0.  The extended ciphertext may be 0, resulting in non-zero
    // plaintext.
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

    off_t adjustedSize(off_t size) const;

    shared_ptr<FileIO> base;

    FSConfigPtr fsConfig;

    // if haveHeader is true, then we have a transparent file header which
    int headerLen;

    bool perFileIV;
    bool externalIVChaining;
    uint64_t externalIV;
    uint64_t fileIV;
    int lastFlags;

    shared_ptr<CipherV1> cipher;
};

}  // namespace encfs

#endif
