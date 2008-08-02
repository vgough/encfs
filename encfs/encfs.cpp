/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2007, Valient Gough
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

#include "encfs.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <cerrno>
#include <sys/statvfs.h>
#include <sys/time.h>

#include <sys/types.h>
#ifdef linux
#include <sys/fsuid.h>
#endif

#ifdef HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#elif HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif


#include <string>
#include <map>

#include <boost/tuple/tuple.hpp>
#include <boost/scoped_array.hpp>

#include "DirNode.h"
#include "MemoryPool.h"
#include "FileUtils.h"
#include "Mutex.h"
#include "Context.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>

#ifndef MIN
#define MIN(a,b) (((a)<(b)) ? (a): (b))
#endif

#define ESUCCESS 0

using namespace std;
using namespace rlog;
using rel::Lock;
using namespace boost;

#define GET_FN(ctx, finfo) ctx->getNode((void*)(uintptr_t)finfo->fh)

static RLogChannel *Info = DEF_CHANNEL("info", Log_Info);

static EncFS_Context * context()
{
    return (EncFS_Context*)fuse_get_context()->private_data;
}

// helper function -- apply a functor to a cipher path, given the plain path
template<typename T>
static int withCipherPath( const char *opName, const char *path,
	int (*op)(EncFS_Context *, const string &name, T data ), T data,
        bool passReturnCode = false )
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	string cyName = FSRoot->cipherPath( path );
	rLog(Info, "%s %s", opName, cyName.c_str());

	res = op( ctx, cyName, data );
	
	if(res == -1)
	{
	    int eno = errno;
	    rInfo("%s error: %s", opName, strerror(eno));
	    res = -eno;
	} else if(!passReturnCode)
	    res = ESUCCESS;
    } catch( rlog::Error &err )
    {
	rError("error caught in %s", opName);
	err.log( _RLWarningChannel );
    }
    return res;
}

// helper function -- apply a functor to a node
template<typename T>
static int withFileNode( const char *opName,
	const char *path, struct fuse_file_info *fi, 
	int (*op)(FileNode *, T data ), T data )
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	shared_ptr<FileNode> fnode;

	if(fi != NULL)
	    fnode = GET_FN(ctx, fi);
	else
	    fnode = FSRoot->lookupNode( path, opName );

	rAssert(fnode != NULL);
	rLog(Info, "%s %s", opName, fnode->cipherName());
	res = op( fnode.get(), data );

	if(res < 0)
	    rInfo("%s error: %s", opName, strerror(-res));
    } catch( rlog::Error &err )
    {
	rError("error caught in %s", opName);
	err.log( _RLWarningChannel );
    }
    return res;
}

/*
    The rLog messages below always print out encrypted filenames, not
    plaintext.  The reason is so that it isn't possible to leak information
    about the encrypted data through rlog interfaces.


    The purpose of this layer of code is to take the FUSE request and dispatch
    to the internal interfaces.  Any marshaling of arguments and return types
    can be done here.
*/

int _do_getattr(FileNode *fnode, struct stat *stbuf)
{
    int res = fnode->getAttr(stbuf);
    if(res == ESUCCESS && S_ISLNK(stbuf->st_mode))
    {
	EncFS_Context *ctx = context();
	shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
	if(FSRoot)
	{
	    // determine plaintext link size..  Easiest to read and decrypt..
	    scoped_array<char> buf(new char[stbuf->st_size+1]);

	    res = ::readlink( fnode->cipherName(), buf.get(), stbuf->st_size );
            if(res >= 0)
            {
                // other functions expect c-strings to be null-terminated, which
                // readlink doesn't provide
                buf[res] = '\0';

                stbuf->st_size = FSRoot->plainPath( buf.get() ).length();

                res = ESUCCESS;
            } else
                res = -errno;
	}
    }

    return res;
}

int encfs_getattr(const char *path, struct stat *stbuf)
{
    return withFileNode( "getattr", path, NULL, _do_getattr, stbuf );
}

int encfs_fgetattr(const char *path, struct stat *stbuf,
	struct fuse_file_info *fi)
{
    return withFileNode( "fgetattr", path, fi, _do_getattr, stbuf );
}

int encfs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    EncFS_Context *ctx = context();

    int res = ESUCCESS;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {

	DirTraverse dt = FSRoot->openDir( path );

	rLog(Info, "getdir on %s", FSRoot->cipherPath(path).c_str());

	if(dt.valid())
	{
	    int fileType = 0;
	    ino_t inode = 0;

	    std::string name = dt.nextPlaintextName( &fileType, &inode );
	    while( !name.empty() )
	    {
		res = filler( h, name.c_str(), fileType, inode );

		if(res != ESUCCESS)
		    break;

		name = dt.nextPlaintextName( &fileType, &inode );
	    } 
	} else
	{
	    rInfo("getdir request invalid, path: '%s'", path);
	}

	return res;
    } catch( rlog::Error &err )
    {
	rError("Error caught in getdir");
	err.log( _RLWarningChannel );
	return -EIO;
    }
}

int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	shared_ptr<FileNode> fnode = FSRoot->lookupNode( path, "mknod" );

	rLog(Info, "mknod on %s, mode %i, dev %" PRIi64,
		fnode->cipherName(), mode, (int64_t)rdev);

	uid_t uid = 0;
	gid_t gid = 0;
	if(ctx->publicFilesystem)
	{
	    fuse_context *context = fuse_get_context();
	    uid = context->uid;
	    gid = context->gid;
	}
	res = fnode->mknod( mode, rdev, uid, gid );
	// Is this error due to access problems?
	if(ctx->publicFilesystem && -res == EACCES)
	{
	    // try again using the parent dir's group
	    string parent = fnode->plaintextParent();
	    rInfo("trying public filesystem workaround for %s", parent.c_str());
	    shared_ptr<FileNode> dnode = 
		FSRoot->lookupNode( parent.c_str(), "mknod" );

	    struct stat st;
	    if(dnode->getAttr( &st ) == 0)
		res = fnode->mknod( mode, rdev, uid, st.st_gid );
	}
    } catch( rlog::Error &err )
    {
	rError("error caught in mknod");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_mkdir(const char *path, mode_t mode)
{
    fuse_context *fctx = fuse_get_context();
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	uid_t uid = 0;
	gid_t gid = 0;
	if(ctx->publicFilesystem)
	{
	    uid = fctx->uid;
	    gid = fctx->gid;
	}
	res = FSRoot->mkdir( path, mode, uid, gid );
	// Is this error due to access problems?
	if(ctx->publicFilesystem && -res == EACCES)
	{
	    // try again using the parent dir's group
	    string parent = parentDirectory( path );
	    shared_ptr<FileNode> dnode = 
		FSRoot->lookupNode( parent.c_str(), "mkdir" );

	    struct stat st;
	    if(dnode->getAttr( &st ) == 0)
		res = FSRoot->mkdir( path, mode, uid, st.st_gid );
	}
    } catch( rlog::Error &err )
    {
	rError("error caught in mkdir");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_unlink(const char *path)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	// let DirNode handle it atomically so that it can handle race
	// conditions
	res = FSRoot->unlink( path );
    } catch( rlog::Error &err )
    {
	rError("error caught in unlink");
	err.log( _RLWarningChannel );
    }
    return res;
}


int _do_rmdir(EncFS_Context *, const string &cipherPath, int )
{
    return rmdir( cipherPath.c_str() );
}

int encfs_rmdir(const char *path)
{
    return withCipherPath( "rmdir", path, _do_rmdir, 0 );
}

int _do_readlink(EncFS_Context *ctx, const string &cyName,
	tuple<char *, size_t> data )
{
    char *buf = data.get<0>();
    size_t size = data.get<1>();

    int res = ESUCCESS;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    res = ::readlink( cyName.c_str(), buf, size-1 );

    if(res == -1)
	return -errno;

    buf[res] = '\0'; // ensure null termination
    string decodedName;
    try
    {
	decodedName = FSRoot->plainPath( buf );
    } catch(...) { }

    if(!decodedName.empty())
    {
	strncpy(buf, decodedName.c_str(), size-1);
	buf[size-1] = '\0';

	return ESUCCESS;
    } else
    {
	rWarning("Error decoding link");
	return -1;
    }
}

int encfs_readlink(const char *path, char *buf, size_t size)
{
    return withCipherPath( "readlink", path, _do_readlink, 
	    make_tuple(buf, size) );
}

int encfs_symlink(const char *from, const char *to)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	// allow fully qualified names in symbolic links.
	string fromCName = FSRoot->relativeCipherPath( from );
	string toCName = FSRoot->cipherPath( to );
	
	rLog(Info, "symlink %s -> %s", fromCName.c_str(), toCName.c_str());

	// use setfsuid / setfsgid so that the new link will be owned by the
	// uid/gid provided by the fuse_context.
	int olduid = -1;
	int oldgid = -1;
	if(ctx->publicFilesystem)
	{
	    fuse_context *context = fuse_get_context();
	    olduid = setfsuid( context->uid );
	    oldgid = setfsgid( context->gid );
	}
	res = ::symlink( fromCName.c_str(), toCName.c_str() );
	if(olduid >= 0)
	    setfsuid( olduid );
	if(oldgid >= 0)
	    setfsgid( oldgid );

	if(res == -1)
	    res = -errno;
	else
	    res = ESUCCESS;
    } catch( rlog::Error &err )
    {
	rError("error caught in symlink");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_link(const char *from, const char *to)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	res = FSRoot->link( from, to );
    } catch( rlog::Error &err )
    {
	rError("error caught in link");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_rename(const char *from, const char *to)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	res = FSRoot->rename( from, to );
    } catch( rlog::Error &err )
    {
	rError("error caught in rename");
	err.log( _RLWarningChannel );
    }
    return res;
}

int _do_chmod(EncFS_Context *, const string &cipherPath, mode_t mode)
{
    return chmod( cipherPath.c_str(), mode );
}

int encfs_chmod(const char *path, mode_t mode)
{
    return withCipherPath( "chmod", path, _do_chmod, mode );
}

int _do_chown(EncFS_Context *, const string &cyName, 
	tuple<uid_t, gid_t> data)
{
    int res = lchown( cyName.c_str(), data.get<0>(), data.get<1>() );
    return (res == -1) ? -errno : ESUCCESS;
}

int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
    return withCipherPath( "chown", path, _do_chown, make_tuple(uid, gid));
}

int _do_truncate( FileNode *fnode, off_t size )
{
    return fnode->truncate( size );
}

int encfs_truncate(const char *path, off_t size)
{
    return withFileNode( "truncate", path, NULL, _do_truncate, size );
}

int encfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    return withFileNode( "ftruncate", path, fi, _do_truncate, size );
}

int _do_utime(EncFS_Context *, const string &cyName, struct utimbuf *buf)
{
    int res = utime( cyName.c_str(), buf);
    return (res == -1) ? -errno : ESUCCESS;
}

int encfs_utime(const char *path, struct utimbuf *buf)
{
    return withCipherPath( "utime", path, _do_utime, buf );
}

int _do_utimens(EncFS_Context *, const string &cyName, 
	const struct timespec ts[2])
{
    struct timeval tv[2];
    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    int res = utimes( cyName.c_str(), tv);
    return (res == -1) ? -errno : ESUCCESS;
}

int encfs_utimens(const char *path, const struct timespec ts[2] )
{
    return withCipherPath( "utimens", path, _do_utimens, ts );
}

int encfs_open(const char *path, struct fuse_file_info *file)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if(!FSRoot)
	return res;

    try
    {
	shared_ptr<FileNode> fnode = 
	    FSRoot->openNode( path, "open", file->flags, &res );

	if(fnode)
	{
	    rLog(Info, "encfs_open for %s, flags %i", fnode->cipherName(), 
		    file->flags);

	    if( res >= 0 )
	    {
		file->fh = (uintptr_t)ctx->putNode(path, fnode);
		res = ESUCCESS;
	    }
	}
    } catch( rlog::Error &err )
    {
	rError("error caught in open");
	err.log( _RLWarningChannel );
    }

    return res;
}

int _do_flush(FileNode *fnode, int )
{
    /* Flush can be called multiple times for an open file, so it doesn't
       close the file.  However it is important to call close() for some
       underlying filesystems (like NFS).
    */
    int res = fnode->open( O_RDONLY );
    if(res >= 0)
    {
	int fh = res;
	res = close(dup(fh));
	if(res == -1)
	    res = -errno;
    }

    return res;
}

int encfs_flush(const char *path, struct fuse_file_info *fi)
{
    return withFileNode( "flush", path, fi, _do_flush, 0 );
}

/*
Note: This is advisory -- it might benefit us to keep file nodes around for a
bit after they are released just in case they are reopened soon.  But that
requires a cache layer.
 */
int encfs_release(const char *path, struct fuse_file_info *finfo)
{
    EncFS_Context *ctx = context();

    try
    {
	ctx->eraseNode( path, (void*)(uintptr_t)finfo->fh );
	return ESUCCESS;
    } catch( rlog::Error &err )
    {
	rError("error caught in release");
	err.log( _RLWarningChannel );
	return -EIO;
    }
}

int _do_read(FileNode *fnode, tuple<unsigned char *, size_t, off_t> data)
{
    return fnode->read( data.get<2>(), data.get<0>(), data.get<1>());
}

int encfs_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *file)
{
    return withFileNode( "read", path, file, _do_read,
	    make_tuple((unsigned char *)buf, size, offset));
}

int _do_fsync(FileNode *fnode, int dataSync)
{
    return fnode->sync( dataSync != 0 );
}

int encfs_fsync(const char *path, int dataSync,
	struct fuse_file_info *file)
{
    return withFileNode( "fsync", path, file, _do_fsync, dataSync );
}

int _do_write(FileNode *fnode, tuple<const char *, size_t, off_t> data)
{
    size_t size = data.get<1>();
    if(fnode->write( data.get<2>(), (unsigned char *)data.get<0>(), size ))
	return size;
    else
	return -EIO;
}

int encfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *file)
{
    return withFileNode("write", path, file, _do_write,
	    make_tuple(buf, size, offset));
}

// statfs works even if encfs is detached..
int encfs_statfs(const char *path, struct statvfs *st)
{
    EncFS_Context *ctx = context();

    int res = -EIO;
    try
    {
	(void)path; // path should always be '/' for now..
	rAssert( st != NULL );
	string cyName = ctx->rootCipherDir;

	rLog(Info, "doing statfs of %s", cyName.c_str());
	res = statvfs( cyName.c_str(), st );
	if(!res) 
	{
	    // adjust maximum name length..
	    st->f_namemax     = 6 * (st->f_namemax - 2) / 8; // approx..
	}
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in statfs");
	err.log( _RLWarningChannel );
    }
    return res;
}

#ifdef HAVE_XATTR


#ifdef XATTR_ADD_OPT
int _do_setxattr(EncFS_Context *, const string &cyName, 
	tuple<const char *, const char *, size_t, uint32_t> data)
{
    int options = 0;
    return ::setxattr( cyName.c_str(), data.get<0>(), data.get<1>(), 
	    data.get<2>(), data.get<3>(), options );
}
int encfs_setxattr( const char *path, const char *name,
	const char *value, size_t size, int flags, uint32_t position )
{
    (void)flags;
    return withCipherPath( "setxattr", path, _do_setxattr, 
	    make_tuple(name, value, size, position) );
}
#else
int _do_setxattr(EncFS_Context *, const string &cyName, 
	tuple<const char *, const char *, size_t, int> data)
{
    return ::setxattr( cyName.c_str(), data.get<0>(), data.get<1>(), 
	    data.get<2>(), data.get<3>() );
}
int encfs_setxattr( const char *path, const char *name,
	const char *value, size_t size, int flags )
{
    return withCipherPath( "setxattr", path, _do_setxattr, 
	    make_tuple(name, value, size, flags) );
}
#endif


#ifdef XATTR_ADD_OPT
int _do_getxattr(EncFS_Context *, const string &cyName,
	tuple<const char *, void *, size_t, uint32_t> data)
{
    int options = 0;
    return ::getxattr( cyName.c_str(), data.get<0>(), 
	    data.get<1>(), data.get<2>(), data.get<3>(), options );
}
int encfs_getxattr( const char *path, const char *name,
	char *value, size_t size, uint32_t position )
{
    return withCipherPath( "getxattr", path, _do_getxattr, 
	    make_tuple(name, (void *)value, size, position), true );
}
#else
int _do_getxattr(EncFS_Context *, const string &cyName,
	tuple<const char *, void *, size_t> data)
{
    return ::getxattr( cyName.c_str(), data.get<0>(), 
	    data.get<1>(), data.get<2>());
}
int encfs_getxattr( const char *path, const char *name,
	char *value, size_t size )
{
    return withCipherPath( "getxattr", path, _do_getxattr, 
	    make_tuple(name, (void *)value, size), true );
}
#endif


int _do_listxattr(EncFS_Context *, const string &cyName,
	tuple<char *, size_t> data)
{
#ifdef XATTR_ADD_OPT
    int options = 0;
    int res = ::listxattr( cyName.c_str(), data.get<0>(), data.get<1>(),
            options );
#else
    int res = ::listxattr( cyName.c_str(), data.get<0>(), data.get<1>() );
#endif
    return (res == -1) ? -errno : res;
}

int encfs_listxattr( const char *path, char *list, size_t size )
{
    return withCipherPath( "listxattr", path, _do_listxattr, 
	    make_tuple(list, size), true );
}

int _do_removexattr(EncFS_Context *, const string &cyName, const char *name)
{
#ifdef XATTR_ADD_OPT
    int options = 0;
    int res = ::removexattr( cyName.c_str(), name, options );
#else
    int res = ::removexattr( cyName.c_str(), name );
#endif
    return (res == -1) ? -errno : res;
}

int encfs_removexattr( const char *path, const char *name )
{
    return withCipherPath( "removexattr", path, _do_removexattr, name );
}

#endif // HAVE_XATTR

