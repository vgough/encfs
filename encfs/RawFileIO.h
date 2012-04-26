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

#ifndef _RawFileIO_incl_
#define _RawFileIO_incl_

#include "FileIO.h"

#include <string>

class RawFileIO : public FileIO
{
public:
    RawFileIO();
    RawFileIO( const std::string &fileName );
    virtual ~RawFileIO();

    virtual Interface interface() const;

    virtual void setFileName( const char *fileName );
    virtual const char *getFileName() const;

    virtual int open( int flags );
    
    virtual int getAttr( struct stat *stbuf ) const;
    virtual off_t getSize() const;

    virtual ssize_t read( const IORequest & req ) const;
    virtual bool write( const IORequest &req );

    virtual int truncate( off_t size );

    virtual bool isWritable() const;
protected:

    std::string name;

    bool knownSize;
    off_t fileSize;

    int fd;
    int oldfd;
    bool canWrite;
};

#endif

