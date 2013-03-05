/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004-2013, Valient Gough
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

#include "fs/CipherFileIO.h"

#include "base/Error.h"
#include "cipher/Cipher.h"
#include "cipher/MemoryPool.h"
#include "fs/fsconfig.pb.h"

#include <glog/logging.h>

#include <fcntl.h>
#include <cerrno>

namespace encfs {

/*
   Version 3:0 adds support for block-only encryption by adding space for
   a full block to the file header.

   Version 2:0 adds support for a per-file initialization vector with a
   fixed 8 byte header.  The headers are enabled globally within a
   filesystem at the filesystem configuration level.
   When headers are disabled, 2:0 is compatible with version 1:0.
*/
static Interface CipherFileIO_iface = makeInterface("FileIO/Cipher", 3, 0, 2);

CipherFileIO::CipherFileIO( const shared_ptr<FileIO> &_base, 
                            const FSConfigPtr &cfg)
    : BlockFileIO( cfg->config->block_size(), cfg )
    , base( _base )
    , headerLen( 0 )
    , blockOnlyMode( cfg->config->block_mode_only() )
    , perFileIV( cfg->config->unique_iv() )
    , externalIV( 0 )
    , fileIV( 0 )
    , lastFlags( 0 )
{
  fsConfig = cfg;
  cipher = cfg->cipher;
  key = cfg->key;

  if ( blockOnlyMode )
  {
    headerLen += blockSize();
    if ( perFileIV )
      headerLen += cipher->cipherBlockSize();
  } else
  {
    if ( perFileIV )
      headerLen += sizeof(uint64_t); // 64bit IV per file
  }

  int blockBoundary = fsConfig->config->block_size() % 
    fsConfig->cipher->cipherBlockSize();
  if(blockBoundary != 0)
  {
    LOG_FIRST_N(ERROR, 1) 
      << "CipherFileIO: blocks should be multiple of cipher block size";
  }
}

CipherFileIO::~CipherFileIO()
{
}

Interface CipherFileIO::interface() const
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
  VLOG(1) << "in setIV, current IV = " << externalIV
    << ", new IV = " << iv << ", fileIV = " << fileIV;
  if(externalIV == 0)
  {
    // we're just being told about which IV to use.  since we haven't
    // initialized the fileIV, there is no need to just yet..
    externalIV = iv;
    LOG_IF(WARNING, fileIV != 0) 
      << "fileIV initialized before externalIV! (" << fileIV
      << ", " << externalIV << ")";
  } else if(perFileIV)
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
          VLOG(1) << "writeHeader failed to re-open for write";
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

off_t CipherFileIO::adjustedSize(off_t rawSize) const
{
  off_t size = rawSize;

  if (rawSize >= headerLen) 
    size -= headerLen;

  return size;
}

int CipherFileIO::getAttr( struct stat *stbuf ) const
{
  int res = base->getAttr( stbuf );

  // adjust size if we have a file header
  if((res == 0) && S_ISREG(stbuf->st_mode))
    stbuf->st_size = adjustedSize(stbuf->st_size);

  return res;
}

off_t CipherFileIO::getSize() const
{
  // No check on S_ISREG here -- getSize only for normal files!
  off_t size = base->getSize();
  return adjustedSize(size);
}

void CipherFileIO::initHeader( )
{
  int cbs = cipher->cipherBlockSize();

  MemBlock mb;
  mb.allocate(cbs);

  // check if the file has a header, and read it if it does..  Otherwise,
  // create one.
  off_t rawSize = base->getSize();
  if(rawSize >= headerLen)
  {
    VLOG(1) << "reading existing header, rawSize = " << rawSize;

    IORequest req;
    req.offset = 0;
    if (blockOnlyMode)
      req.offset += blockSize();

    req.data = mb.data;
    req.dataLen = blockOnlyMode ? cbs : sizeof(uint64_t);
    base->read( req );

    if (perFileIV)
    {
      if (blockOnlyMode)
        cipher->blockDecode( mb.data, cbs, externalIV, key );
      else
        cipher->streamDecode( mb.data, sizeof(uint64_t), externalIV, key );

      fileIV = 0;
      for(unsigned int i=0; i<sizeof(uint64_t); ++i)
        fileIV = (fileIV << 8) | (uint64_t)mb.data[i];

      rAssert(fileIV != 0); // 0 is never used..
    }
  } else if (perFileIV)
  {
    VLOG(1) << "creating new file IV header";

    do
    {
      if(!cipher->randomize( mb.data, 8, false ))
        throw Error("Unable to generate a random file IV");

      fileIV = 0;
      for(unsigned int i=0; i<sizeof(uint64_t); ++i)
        fileIV = (fileIV << 8) | (uint64_t)mb.data[i];

      LOG_IF(WARNING, fileIV == 0)
        << "Unexpected result: randomize returned 8 null bytes!";
    } while(fileIV == 0); // don't accept 0 as an option..
   
    if (blockOnlyMode)
      cipher->blockEncode( mb.data, cbs, externalIV, key );
    else
      cipher->streamEncode( mb.data, sizeof(uint64_t), externalIV, key );

    if( base->isWritable() )
    {
      IORequest req;
      req.offset = 0;
      if (blockOnlyMode)
        req.offset += blockSize();

      req.data = mb.data;
      req.dataLen = blockOnlyMode ? cbs : sizeof(uint64_t);

      base->write( req );
    } else
      VLOG(1) << "base not writable, IV not written..";
  }
  VLOG(1) << "initHeader finished, fileIV = " << fileIV;
}

bool CipherFileIO::writeHeader( )
{
  if( !base->isWritable() )
  {
    // open for write..
    int newFlags = lastFlags | O_RDWR;
    if( base->open( newFlags ) < 0 )
    {
      VLOG(1) << "writeHeader failed to re-open for write";
      return false;
    }
  } 

  LOG_IF(ERROR, fileIV == 0)
    << "Internal error: fileIV == 0 in writeHeader!!!";
  VLOG(1) << "writing fileIV " << fileIV;

  MemBlock mb;
  mb.allocate(headerLen);

  if (perFileIV)
  {
    int cbs = cipher->cipherBlockSize();
    unsigned char *buf = mb.data + (blockOnlyMode ? blockSize() : 0);

    for(int i=sizeof(buf)-1; i>=0; --i)
    {
      buf[i] = (unsigned char)(fileIV & 0xff);
      fileIV >>= 8;
    }

    if (blockOnlyMode)
      cipher->blockEncode( buf, cbs, externalIV, key );
    else
      cipher->streamEncode( buf, sizeof(uint64_t), externalIV, key);
  }

  IORequest req;
  req.offset = 0;
  req.data = mb.data;
  req.dataLen = headerLen;

  base->write( req );

  return true;
}

ssize_t CipherFileIO::readOneBlock( const IORequest &req ) const
{
  // read raw data, then decipher it..
  int bs = blockSize();
  rAssert(req.dataLen <= bs);

  off_t blockNum = req.offset / bs;

  ssize_t readSize = 0;
  IORequest tmpReq = req;

  MemBlock mb;
  if (headerLen != 0)
    tmpReq.offset += headerLen;

  int maxReadSize = req.dataLen;
  if (blockOnlyMode)
  {
    off_t size = getSize();
    if (req.offset + req.dataLen > size)
    {
      // Last block written as full block at front of the file header.
      mb.allocate(bs);

      tmpReq.offset = 0;
      tmpReq.dataLen = bs;
      tmpReq.data = mb.data;
 
      // TODO: what is the expected behavior if req.offset >= size?
      maxReadSize = size - req.offset;
      if (maxReadSize <= 0)
        return 0;
    }
  }

  readSize = base->read( tmpReq );

  bool ok;
  if(readSize > 0)
  {
    if(headerLen != 0 && fileIV == 0)
      const_cast<CipherFileIO*>(this)->initHeader();

    if(blockOnlyMode || readSize == bs)
    {
      ok = blockRead( tmpReq.data, bs, blockNum ^ fileIV);
    } else 
    {
      ok = streamRead( tmpReq.data, (int)readSize, blockNum ^ fileIV);
    }

    if(!ok)
    {
      VLOG(1) << "decodeBlock failed for block " << blockNum
        << ", size " << readSize;
      readSize = -1;
    } else if (tmpReq.data != req.data) 
    {
      if (readSize > maxReadSize)
        readSize = maxReadSize;
      memcpy(req.data, tmpReq.data, readSize);
    }
  } else
    VLOG(1) << "readSize zero for offset " << req.offset;

  return readSize;
}


bool CipherFileIO::writeOneBlock( const IORequest &req )
{
  int bs = blockSize();
  int cbs = cipher->cipherBlockSize();
  off_t blockNum = req.offset / bs;

  if(headerLen != 0 && fileIV == 0)
    initHeader();

  MemBlock mb;

  bool ok;
  if (req.dataLen == bs)
  {
    ok = blockWrite( req.data, bs, blockNum ^ fileIV );
  } else if (blockOnlyMode)
  {
    mb.allocate(bs);
    cipher->randomize(mb.data + bs - cbs, cbs, false);
    memcpy(mb.data, req.data, req.dataLen);

    ok = blockWrite( mb.data, bs, blockNum ^ fileIV );
  } else
  {
    ok = streamWrite( req.data, (int)req.dataLen, 
                     blockNum ^ fileIV );
  }

  if( ok )
  {
    if(headerLen != 0)
    {
      IORequest nreq = req;

      if (mb.data == NULL)
      {
        nreq.offset += headerLen;
      } else
      {
        // Partial block is stored at front of file.
        nreq.offset = 0;
        nreq.data = mb.data;
        nreq.dataLen = bs;
        base->truncate(req.offset + req.dataLen + headerLen);
      }

      ok = base->write( nreq );
    } else
      ok = base->write( req );
  } else
  {
    VLOG(1) << "encodeBlock failed for block " << blockNum
      << ", size " << req.dataLen;
    ok = false;
  }
  return ok;
}

bool CipherFileIO::blockWrite( unsigned char *buf, int size, 
                              uint64_t _iv64 ) const
{
  if (!fsConfig->reverseEncryption)
    return cipher->blockEncode( buf, size, _iv64, key );
  else
    return cipher->blockDecode( buf, size, _iv64, key );
} 

bool CipherFileIO::streamWrite( unsigned char *buf, int size, 
                               uint64_t _iv64 ) const
{
  if (!fsConfig->reverseEncryption)
    return cipher->streamEncode( buf, size, _iv64, key );
  else
    return cipher->streamDecode( buf, size, _iv64, key );
} 


bool CipherFileIO::blockRead( unsigned char *buf, int size, 
                             uint64_t _iv64 ) const
{
  if (fsConfig->reverseEncryption)
    return cipher->blockEncode( buf, size, _iv64, key );
  else if(_allowHoles)
  {
    // special case - leave all 0's alone
    for(int i=0; i<size; ++i)
      if(buf[i] != 0)
        return cipher->blockDecode( buf, size, _iv64, key );

    return true;
  } else
    return cipher->blockDecode( buf, size, _iv64, key );
} 

bool CipherFileIO::streamRead( unsigned char *buf, int size, 
                              uint64_t _iv64 ) const
{
  if (fsConfig->reverseEncryption)
    return cipher->streamEncode( buf, size, _iv64, key );
  else
    return cipher->streamDecode( buf, size, _iv64, key );
} 

int CipherFileIO::truncate( off_t size )
{
  rAssert(size >= 0);

  if(headerLen == 0)
  {
    return blockTruncate( size, base.get() );
  } else if(0 == fileIV)
  {
    // empty file.. create the header..
    if( !base->isWritable() )
    {
      // open for write..
      int newFlags = lastFlags | O_RDWR;
      if( base->open( newFlags ) < 0 )
        VLOG(1) << "writeHeader failed to re-open for write";
    }
    initHeader();
  }

  // can't let BlockFileIO call base->truncate(), since it would be using
  // the wrong size..
  int res = blockTruncate( size, 0 );

  if(res == 0)
    base->truncate( size + headerLen );

  return res;
}

bool CipherFileIO::isWritable() const
{
  return base->isWritable();
}

}  // namespace encfs
