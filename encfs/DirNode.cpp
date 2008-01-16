/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2004, Valient Gough
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

#include "DirNode.h"
#include "FileUtils.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#ifdef linux
#include <sys/fsuid.h>
#endif

#include "Context.h"
#include "Cipher.h"
#include "Mutex.h"
#include <rlog/rlog.h>
#include <rlog/Error.h>

#include <iostream>

using namespace std;
using namespace rel;
using namespace rlog;

static RLogChannel *Info = DEF_CHANNEL( "info/DirNode", Log_Info );

class DirDeleter
{
public:
    void operator () ( DIR *d )
    {
	::closedir( d );
    }
};


DirTraverse::DirTraverse(const shared_ptr<DIR> &_dirPtr, 
	uint64_t _iv, const shared_ptr<NameIO> &_naming)
    : dir( _dirPtr )
    , iv( _iv )
    , naming( _naming )
{
}

DirTraverse::DirTraverse(const DirTraverse &src)
    : dir( src.dir )
    , iv( src.iv )
    , naming( src.naming )
{
}

DirTraverse &DirTraverse::operator = (const DirTraverse &src)
{
    dir = src.dir;
    iv = src.iv;
    naming = src.naming;
    
    return *this;
}

DirTraverse::~DirTraverse()
{
    dir.reset();
    iv = 0;
    naming.reset();
}

static
bool _nextName(struct dirent *&de, const shared_ptr<DIR> &dir, 
	int *fileType, ino_t *inode)
{
    de = ::readdir( dir.get() );

    if(de)
    {
	if(fileType)
	{
#if defined(_DIRENT_HAVE_D_TYPE) || defined(__FreeBSD__)
	    *fileType = de->d_type;
#else
#warning "struct dirent.d_type not supported"
	    *fileType = 0;
#endif
	}
	if(inode)
	    *inode = de->d_ino;
	return true;
    } else
    {
	if(fileType)
	    *fileType = 0;
	return false;
    }
}


std::string DirTraverse::nextPlaintextName(int *fileType, ino_t *inode)
{
    struct dirent *de=0;
    while(_nextName(de, dir, fileType, inode))
    {
	try
	{
	    uint64_t localIv = iv;
	    return naming->decodePath( de->d_name, &localIv );
	} catch ( rlog::Error &ex )
	{
	    // .. .problem decoding, ignore it and continue on to next name..
	    rDebug("error decoding filename: %s", de->d_name);
	}
    }

    return string();
}

std::string DirTraverse::nextInvalid()
{
    struct dirent *de=0;
    // find the first name which produces a decoding error...
    while(_nextName(de, dir, (int*)0, (ino_t*)0))
    {
	try
	{
	    uint64_t localIv = iv;
	    naming->decodePath( de->d_name, &localIv );
	    continue;
	} catch( rlog::Error &ex )
	{
	    return string( de->d_name );
	}
    }

    return string();
}

struct RenameEl
{
    // ciphertext names
    string oldCName;
    string newCName; // intermediate name (not final cname)

    // plaintext names
    string oldPName;
    string newPName;

    bool isDirectory;
};

class RenameOp
{
private:
    DirNode *dn;
    shared_ptr< list<RenameEl> > renameList;
    list<RenameEl>::const_iterator last;

public:
    RenameOp( DirNode *_dn, const shared_ptr< list<RenameEl> > &_renameList )
	: dn(_dn), renameList(_renameList)
    {
	last = renameList->begin();
    }

    RenameOp(const RenameOp &src)
	: dn(src.dn)
	, renameList(src.renameList)
	, last(src.last)
    {
    }

    ~RenameOp()
    {
	if(renameList)
	{
	    // got a bunch of decoded filenames sitting in memory..  do a little
	    // cleanup before leaving..
	    list<RenameEl>::iterator it;
	    for(it = renameList->begin(); it != renameList->end(); ++it)
	    {
		it->oldPName.assign( it->oldPName.size(), ' ' );
		it->newPName.assign( it->newPName.size(), ' ' );
	    }
	}
    }

    operator bool () const
    {
	return renameList;
    }

    bool apply()
    {
	try
	{
	    while(last != renameList->end())
	    {
		// backing store rename.
		rDebug("renaming %s -> %s",
			last->oldCName.c_str(), last->newCName.c_str());

		// internal node rename..
		dn->renameNode( last->oldPName.c_str(), 
			        last->newPName.c_str() );

		// rename on disk..
		if(::rename( last->oldCName.c_str(), 
			     last->newCName.c_str() ) == -1)
		{
		    rWarning("Error renaming %s: %s",
			    last->oldCName.c_str(), strerror( errno ));
		    dn->renameNode( last->newPName.c_str(), 
			    last->oldPName.c_str(), false );
		    return false;
		}

		++last;
	    }

	    return true;
	} catch( rlog::Error &err )
	{
	    err.log( _RLWarningChannel );
	    return false;
	}
    }

    void undo()
    {
	rDebug("in undoRename");

	if(last == renameList->begin())
	{
	    rDebug("nothing to undo");
	    return; // nothing to undo
	}

	// list has to be processed backwards, otherwise we may rename
	// directories and directory contents in the wrong order!
	int undoCount = 0;
	list<RenameEl>::const_iterator it = last;

	while( it != renameList->begin() )
	{
	    --it;

	    rDebug("undo: renaming %s -> %s", 
		    it->newCName.c_str(), it->oldCName.c_str());

	    ::rename( it->newCName.c_str(), it->oldCName.c_str() );
	    try
	    {
		dn->renameNode( it->newPName.c_str(), 
			        it->oldPName.c_str(), false );
	    } catch( rlog::Error &err )
	    {
		err.log( _RLWarningChannel );
		// continue on anyway...
	    }
	    ++undoCount;
	};
    
	rWarning("Undo rename count: %i", undoCount);
    }
};

DirNode::DirNode(EncFS_Context *_ctx,
	const string &sourceDir, const shared_ptr<Config> &_config)
{
    pthread_mutex_init( &mutex, 0 );
    
    Lock _lock( mutex );

    ctx = _ctx;
    rootDir = sourceDir;
    config = _config;

    // make sure rootDir ends in '/', so that we can form a path by appending
    // the rest..
    if( rootDir[ rootDir.length()-1 ] != '/' )
	rootDir.append( 1, '/');

    naming = config->nameCoding;
}

DirNode::~DirNode()
{
}

bool
DirNode::hasDirectoryNameDependency() const
{
    return naming ? naming->getChainedNameIV() : false;
}

string
DirNode::rootDirectory()
{
    // don't update last access here, otherwise 'du' would cause lastAccess to
    // be reset.
    // chop off '/' terminator from root dir.
    return string( rootDir, 0, rootDir.length()-1 );
}

string 
DirNode::cipherPath( const char *plaintextPath )
{
    return rootDir + naming->encodePath( plaintextPath );
}

string
DirNode::plainPath( const char *cipherPath_ )
{
    try
    {
	if( !strncmp( cipherPath_, rootDir.c_str(), 
		    rootDir.length() ) )
	{
	    return naming->decodePath( cipherPath_ + rootDir.length() );
	} else
	{
	    if ( cipherPath_[0] == '+' )
	    {
		// decode as fully qualified path
		return string("/") + naming->decodeName( cipherPath_+1, 
			strlen(cipherPath_+1) );
	    } else
	    {
		return naming->decodePath( cipherPath_ );
	    }
	}

    } catch( rlog::Error &err )
    {
	rError("decode err: %s", err.message());
	err.log( _RLWarningChannel );

	return string();
    }
}

string
DirNode::relativeCipherPath( const char *plaintextPath )
{
    try
    {
	if(plaintextPath[0] == '/')
	{
	    // mark with '+' to indicate special decoding..
	    return string("+") + naming->encodeName(plaintextPath+1, 
		    strlen(plaintextPath+1));
	} else
	{
	    return naming->encodePath( plaintextPath );
	}
    } catch( rlog::Error &err )
    {
	rError("encode err: %s", err.message());
	err.log( _RLWarningChannel );

	return string();
    }
}

DirTraverse DirNode::openDir(const char *plaintextPath)
{
    string cyName = rootDir + naming->encodePath( plaintextPath );
    //rDebug("openDir on %s", cyName.c_str() );

    shared_ptr<DIR> dp( ::opendir( cyName.c_str() ), DirDeleter() );
    if(!dp)
    {
	rDebug("opendir error %s", strerror(errno));
	return DirTraverse( dp, 0, shared_ptr<NameIO>() );
    } else
    {
	uint64_t iv = 0;
	// if we're using chained IV mode, then compute the IV at this
	// directory level..
	try
	{
	    if( naming->getChainedNameIV() )
		naming->encodePath( plaintextPath, &iv );
	} catch( rlog::Error &err )
	{
	    rError("encode err: %s", err.message());
	    err.log( _RLWarningChannel );
	}
	return DirTraverse( dp, iv, naming );
    }
}

bool DirNode::genRenameList( list<RenameEl> &renameList, 
	const char *fromP, const char *toP )
{
    uint64_t fromIV = 0, toIV = 0;

    // compute the IV for both paths
    string fromCPart = naming->encodePath( fromP, &fromIV );
    string toCPart = naming->encodePath( toP, &toIV );

    // where the files live before the rename..
    string sourcePath = rootDir + fromCPart;

    // ok..... we wish it was so simple.. should almost never happen
    if(fromIV == toIV)
	return true;

    // generate the real destination path, where we expect to find the files..
    rDebug("opendir %s", sourcePath.c_str() );
    shared_ptr<DIR> dir = shared_ptr<DIR>(
	    opendir( sourcePath.c_str() ), DirDeleter() );
    if(!dir)
	return false;
    
    struct dirent *de = NULL;
    while((de = ::readdir( dir.get() )) != NULL)
    {
	// decode the name using the oldIV
	uint64_t localIV = fromIV;
	string plainName;

	if((de->d_name[0] == '.') &&
		((de->d_name[1] == '\0') 
		 || ((de->d_name[1] == '.') && (de->d_name[2] == '\0'))))
	{
	    // skip "." and ".."
	    continue;
	}

	try
	{
	    plainName = naming->decodePath( de->d_name, &localIV );
	} catch( rlog::Error &ex )
	{
	    // if filename can't be decoded, then ignore it..
	    continue;
	}

	// any error in the following will trigger a rename failure.
	try
	{
	    // re-encode using the new IV..
	    localIV = toIV;
	    string newName = naming->encodePath( plainName.c_str(), &localIV );
	
    	    // store rename information..
    	    string oldFull = sourcePath + '/' + de->d_name;
    	    string newFull = sourcePath + '/' + newName;

	    RenameEl ren;
	    ren.oldCName = oldFull;
	    ren.newCName = newFull;
	    ren.oldPName = string(fromP) + '/' + plainName;
	    ren.newPName = string(toP) + '/' + plainName;
	    
	    bool isDir;
#if defined(_DIRENT_HAVE_D_TYPE)
	    if(de->d_type != DT_UNKNOWN)
	    {
		isDir = (de->d_type == DT_DIR);
	    } else
#endif
	    {
		isDir = isDirectory( oldFull.c_str() );
	    }

	    ren.isDirectory = isDir;

	    if(isDir)
	    {
		// recurse..  We want to add subdirectory elements before the
		// parent, as that is the logical rename order..
		if(!genRenameList( renameList, 
			    ren.oldPName.c_str(), 
			    ren.newPName.c_str()))
		{
		    return false;
		}
	    }

	    rDebug("adding file %s to rename list",
		    oldFull.c_str());

	    renameList.push_back( ren );

	} catch( rlog::Error &err )
	{
	    // We can't convert this name, because we don't have a valid IV for
	    // it (or perhaps a valid key).. It will be inaccessible..
	    rWarning("Aborting rename: error on file: %s",
		    fromCPart.append(1, '/').append(de->d_name).c_str());
	    err.log( _RLDebugChannel );

	    // abort.. Err on the side of safety and disallow rename, rather
	    // then loosing files..
	    return false;
	}
    }

    return true;
}


/*
    A bit of a pain.. If a directory is renamed in a filesystem with
    directory initialization vector chaining, then we have to recursively
    rename every descendent of this directory, as all initialization vectors
    will have changed..

    Returns a list of renamed items on success, a null list on failure.
*/
shared_ptr<RenameOp>
DirNode::newRenameOp( const char *fromP, const char *toP )
{
    // Do the rename in two stages to avoid chasing our tail
    // Undo everything if we encounter an error!
    shared_ptr< list<RenameEl> > renameList(new list<RenameEl>);
    if(!genRenameList( *renameList.get(), fromP, toP ))
    {
	rWarning("Error during generation of recursive rename list");
	return shared_ptr<RenameOp>();
    } else
	return shared_ptr<RenameOp>( new RenameOp(this, renameList) );
}


int DirNode::mkdir(const char *plaintextPath, mode_t mode, 
	uid_t uid, gid_t gid)
{
    string cyName = rootDir + naming->encodePath( plaintextPath );
    rAssert( !cyName.empty() );

    rLog( Info, "mkdir on %s", cyName.c_str() );

    // if uid or gid are set, then that should be the directory owner
    int olduid = -1;
    int oldgid = -1;
    if(uid != 0)
	olduid = setfsuid( uid );
    if(gid != 0)
	oldgid = setfsgid( gid );

    int res = ::mkdir( cyName.c_str(), mode );

    if(olduid >= 0)
	setfsuid( olduid );
    if(oldgid >= 0)
	setfsgid( oldgid );

    if(res == -1)
    {
	int eno = errno;
	rWarning("mkdir error on %s mode %i: %s", cyName.c_str(), 
		mode, strerror(eno));
	res = -eno;
    } else
	res = 0;

    return res;
}

int 
DirNode::rename( const char *fromPlaintext, const char *toPlaintext )
{
    Lock _lock( mutex );

    string fromCName = rootDir + naming->encodePath( fromPlaintext );
    string toCName = rootDir + naming->encodePath( toPlaintext );
    rAssert( !fromCName.empty() );
    rAssert( !toCName.empty() );
    
    rLog( Info, "rename %s -> %s", fromCName.c_str(), toCName.c_str() );
   
    shared_ptr<FileNode> toNode = findOrCreate( toPlaintext );

    shared_ptr<RenameOp> renameOp;
    if( hasDirectoryNameDependency() && isDirectory( fromCName.c_str() ))
    {
	rLog( Info, "recursive rename begin" );
	renameOp = newRenameOp( fromPlaintext, toPlaintext );

	if(!renameOp || !renameOp->apply())
	{
	    if(renameOp)
		renameOp->undo();

	    rWarning("rename aborted");
	    return -EACCES;
	}
	rLog( Info, "recursive rename end" );
    }

    int res = 0;
    try
    {
	renameNode( fromPlaintext, toPlaintext );
	res = ::rename( fromCName.c_str(), toCName.c_str() );

	if(res == -1)
	{
	    // undo
	    res = -errno;
	    renameNode( toPlaintext, fromPlaintext, false );

	    if(renameOp)
		renameOp->undo();
	}
    } catch( rlog::Error &err )
    {
	// exception from renameNode, just show the error and continue..
	err.log( _RLWarningChannel );
	res = -EIO;
    }
   
    if(res != 0)
    {
	rLog( Info, "rename failed: %s", strerror( errno ));
	res = -errno;
    }

    return res;
}

int DirNode::link( const char *from, const char *to )
{
    Lock _lock( mutex );

    string fromCName = rootDir + naming->encodePath( from );
    string toCName = rootDir + naming->encodePath( to );

    rAssert( !fromCName.empty() );
    rAssert( !toCName.empty() );

    rLog(Info, "link %s -> %s", fromCName.c_str(), toCName.c_str());

    int res = -EPERM;
    if( config->externalIVChaining )
    {
	rLog(Info, "hard links not supported with external IV chaining!");
    } else
    {
	res = ::link( fromCName.c_str(), toCName.c_str() );
	if(res == -1)
	    res = -errno;
	else
	    res = 0;
    }

    return res;
}

/*
    The node is keyed by filename, so a rename means the internal node names
    must be changed.
*/
shared_ptr<FileNode> DirNode::renameNode( const char *from, const char *to )
{
    return renameNode( from, to, true );
}

shared_ptr<FileNode> DirNode::renameNode( const char *from, const char *to, 
	bool forwardMode )
{
    shared_ptr<FileNode> node = findOrCreate( from );

    if(node)
    {
	uint64_t newIV = 0;
	string cname = rootDir + naming->encodePath( to, &newIV );

	rLog(Info, "renaming internal node %s -> %s",
		node->cipherName(), cname.c_str());

	if(node->setName( to, cname.c_str(), newIV, forwardMode ))
	{
	    if(ctx)
		ctx->renameNode( from, to );
	} else
	{
	    // rename error! - put it back 
	    rError("renameNode failed");
	    throw ERROR("Internal node name change failed!");
	}
    }

    return node;
}

shared_ptr<FileNode> DirNode::findOrCreate( const char *plainName)
{
    shared_ptr<FileNode> node;
    if(ctx)
	node = ctx->lookupNode( plainName );

    if(!node)
    {
	uint64_t iv = 0;
	string cipherName = naming->encodePath( plainName, &iv );
	node.reset( new FileNode( this, 
		config->fsSubVersion,
		plainName, 
		(rootDir + cipherName).c_str(), 
		config->cipher, config->key,
		config->blockSize, config->blockMACBytes,
		config->blockMACRandBytes, 
		config->uniqueIV,
		config->externalIVChaining,
		config->forceDecode,
		config->reverseEncryption) );
		
	if(config->externalIVChaining)
	    node->setName(0, 0, iv);

	rLog(Info, "created FileNode for %s", node->cipherName());
    }

    return node;
}

shared_ptr<FileNode>
DirNode::lookupNode( const char *plainName, const char * requestor )
{
    (void)requestor;
    Lock _lock( mutex );

    shared_ptr<FileNode> node = findOrCreate( plainName );

    return node;
}

/*
    Similar to lookupNode, except that we also call open() and only return a
    node on sucess..  This is done in one step to avoid any race conditions
    with the stored state of the file.
*/
shared_ptr<FileNode>
DirNode::openNode( const char *plainName, const char * requestor, int flags,
	int *result )
{
    (void)requestor;
    rAssert( result != NULL );
    Lock _lock( mutex );

    shared_ptr<FileNode> node = findOrCreate( plainName );

    if( node && (*result = node->open( flags )) >= 0 )
	return node;
    else
	return shared_ptr<FileNode>();
}

int DirNode::unlink( const char *plaintextName )
{
    string cyName = naming->encodePath( plaintextName );
    rLog( Info, "unlink %s", cyName.c_str() );

    Lock _lock( mutex );
   
    int res = 0;
    if(ctx && ctx->lookupNode( plaintextName ))
    {
	// If FUSE is running with "hard_remove" option where it doesn't
	// hide open files for us, then we can't allow an unlink of an open
	// file..
	rWarning("Refusing to unlink open file: %s, hard_remove option "
		"is probably in effect", cyName.c_str() );
	res = -EBUSY;
    } else
    {
	string fullName = rootDir + cyName;
	res = ::unlink( fullName.c_str() );
	if(res == -1)
	{
	    res = -errno;
	    rDebug("unlink error: %s", strerror(errno));
	} 
    }
	
    return res;
}

