/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
 * 
 * This program is free software; you can distribute it and/or modify it under 
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
                             
#ifndef _FileNode_incl_
#define _FileNode_incl_

#include "encfs.h"
#include "CipherKey.h"

#include <inttypes.h>
#include <sys/types.h>
#include <string>

class Cipher;
class FileIO;
class DirNode;
using boost::shared_ptr;

class FileNode
{
public:
    FileNode(DirNode *parent, 
	    int fsSubVersion,  // version number for the filesystem
	    const char *plaintextName,
	    const char *cipherName, 
	    const shared_ptr<Cipher> &cipher, const CipherKey &key, int blockSize,
	    int blockMACBytes, // per-block random bytes in header
	    int blockMACRandBytes, // per-block random bytes in header
	    bool uniqueIV, // enable per-file initialization vectors
	    bool externalIVChaining,
	    bool forceDecode, // decode, even if decoding errors are detected
	    bool reverseEncryption,
            bool allowHoles );
    ~FileNode();

    const char *plaintextName() const;
    const char *cipherName() const;

    // directory portion of plaintextName
    std::string plaintextParent() const;

    // if setIVFirst is true, then the IV is changed before the name is changed
    // (default).  The reverse is also supported for special cases..
    bool setName( const char *plaintextName, const char *cipherName,
	    uint64_t iv, bool setIVFirst = true);

    // create node
    // If uid/gid are not 0, then chown is used change ownership as specified
    int mknod(mode_t mode, dev_t rdev, uid_t uid = 0, gid_t gid = 0);

    // Returns < 0 on error (-errno), file descriptor on success.
    int open(int flags) const;

    // getAttr returns 0 on success, -errno on failure
    int getAttr(struct stat *stbuf) const;
    off_t getSize() const;

    ssize_t read(off_t offset, unsigned char *data, ssize_t size) const;
    bool write(off_t offset, unsigned char *data, ssize_t size);

    // truncate the file to a particular size
    int truncate( off_t size );

    // datasync or full sync
    int sync(bool dataSync);
private:

    // doing locking at the FileNode level isn't as efficient as at the
    // lowest level of RawFileIO, since that means locks are held longer
    // (held during CPU intensive crypto operations!).  However it makes it
    // easier to avoid any race conditions with operations such as
    // truncate() which may result in multiple calls down to the FileIO
    // level.
    mutable pthread_mutex_t mutex;
    bool externalIVChaining;
    bool reverseEncryption;

    shared_ptr<FileIO> io;
    std::string _pname; // plaintext name
    std::string _cname; // encrypted name
    DirNode *parent;

private:
    FileNode(const FileNode &src);
    FileNode &operator = (const FileNode &src);

};


#endif

