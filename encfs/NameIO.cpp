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

#include "NameIO.h"
#include "config.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>

#include <map>

// for static build.  Need to reference the modules which are registered at
// run-time, to ensure that the linker doesn't optimize them away.
#include <iostream>
#include "BlockNameIO.h"
#include "StreamNameIO.h"
#include "NullNameIO.h"

using namespace std;
using namespace rel;
using namespace rlog;

#define REF_MODULE(TYPE) \
    if(!TYPE::Enabled() ) \
        cerr << "referenceModule: should never happen\n";

static
void AddSymbolReferences()
{
    REF_MODULE(BlockNameIO)
    REF_MODULE(StreamNameIO)
    REF_MODULE(NullNameIO)
}


struct NameIOAlg
{
    bool hidden;
    NameIO::Constructor constructor;
    string description;
    Interface iface;
};

typedef multimap< string, NameIOAlg > NameIOMap_t;
static NameIOMap_t *gNameIOMap = 0;


list< NameIO::Algorithm > 
NameIO::GetAlgorithmList( bool includeHidden )
{
    AddSymbolReferences();

    list< Algorithm > result;
    if(gNameIOMap)
    {
	NameIOMap_t::const_iterator it;
	NameIOMap_t::const_iterator end = gNameIOMap->end();
	for(it = gNameIOMap->begin(); it != end; ++it)
	{
	    if(includeHidden || !it->second.hidden)
	    {
		Algorithm tmp;
		tmp.name = it->first;
		tmp.description = it->second.description;
		tmp.iface = it->second.iface;

		result.push_back( tmp );
	    }
	}
    }

    return result;
}

bool NameIO::Register( const char *name, const char *description,
	const Interface &iface, Constructor constructor,
	bool hidden )
{
    if( !gNameIOMap )
	gNameIOMap = new NameIOMap_t;

    NameIOAlg alg;
    alg.hidden = hidden;
    alg.constructor = constructor;
    alg.description = description;
    alg.iface = iface;

    gNameIOMap->insert( make_pair( string(name), alg ));
    return true;
}

shared_ptr<NameIO> NameIO::New( const string &name, 
	const shared_ptr<Cipher> &cipher, const CipherKey &key)
{
    shared_ptr<NameIO> result;
    if(gNameIOMap)
    {
	NameIOMap_t::const_iterator it = gNameIOMap->find( name );
	if(it != gNameIOMap->end())
	{
	    Constructor fn = it->second.constructor;
	    result = (*fn)( it->second.iface, cipher, key );
	}
    }
    return result;
}

shared_ptr<NameIO> NameIO::New( const Interface &iface, 
	const shared_ptr<Cipher> &cipher, const CipherKey &key )
{
    shared_ptr<NameIO> result;
    if(gNameIOMap)
    {
	NameIOMap_t::const_iterator it;
	NameIOMap_t::const_iterator end = gNameIOMap->end();
	for(it = gNameIOMap->begin(); it != end; ++it)
	{
	    if( it->second.iface.implements( iface ))
	    {
		Constructor fn = it->second.constructor;
		result = (*fn)( iface, cipher, key );
		break;
	    }
	}
    }
    return result;
}



NameIO::NameIO()
    : chainedNameIV( false ), reverseEncryption( false )
{
}

NameIO::~NameIO()
{
}

void NameIO::setChainedNameIV( bool enable )
{
    chainedNameIV = enable;
}

bool NameIO::getChainedNameIV() const
{
    return chainedNameIV;
}

void NameIO::setReverseEncryption( bool enable )
{
    reverseEncryption = enable;
}

bool NameIO::getReverseEncryption() const
{
    return reverseEncryption;
}


std::string NameIO::recodePath( const char *path, 
	int (NameIO::*_length)(int) const,
	int (NameIO::*_code)(const char*, int, uint64_t *, char*) const,
	uint64_t *iv ) const
{
    string output;

    while( *path )
    {
	if( *path == '/' )
	{
	    if( !output.empty() ) // don't start the string with '/'
		output += '/';
	    ++path;
	} else
	{
	    bool isDotFile = (*path == '.');
	    char *next = strchr( path, '/' );
	    int len = next ? next - path : strlen( path );

	    // at this point we know that len > 0
	    if( isDotFile && (path[len-1] == '.') && (len <= 2) )
	    {
		output.append(len, '.'); // append [len] copies of '.'
		path += len;
		continue;
	    }

	    // figure out buffer sizes
	    int approxLen = (this->*_length)( len );
	    if(approxLen <= 0)
		throw ERROR("Filename too small to decode");

	    BUFFER_INIT( codeBuf, 32, (unsigned int)approxLen+1 )

	    // code the name
	    int codedLen = (this->*_code)( path, len, iv, codeBuf );
	    rAssert( codedLen <= approxLen );
	    rAssert( codeBuf[codedLen] == '\0' );
	    path += len;

	    // append result to string
	    output += (char*)codeBuf;

	    BUFFER_RESET( codeBuf )
	}
    }

    return output;
}

std::string NameIO::encodePath( const char *plaintextPath ) const
{
    uint64_t iv = 0;
    return encodePath( plaintextPath, &iv);
}

std::string NameIO::decodePath( const char *cipherPath ) const
{
    uint64_t iv = 0;
    return decodePath( cipherPath, &iv );
}

std::string NameIO::_encodePath( const char *plaintextPath, uint64_t *iv ) const
{
    // if chaining is not enabled, then the iv pointer is not used..
    if(!chainedNameIV)
	iv = 0;
    return recodePath( plaintextPath, 
	    &NameIO::maxEncodedNameLen, &NameIO::encodeName, iv);
}

std::string NameIO::_decodePath( const char *cipherPath, uint64_t *iv ) const
{
    // if chaining is not enabled, then the iv pointer is not used..
    if(!chainedNameIV)
	iv = 0;
    return recodePath( cipherPath, 
	    &NameIO::maxDecodedNameLen, &NameIO::decodeName, iv);
}

std::string NameIO::encodePath( const char *path, uint64_t *iv ) const
{
    return getReverseEncryption() ? 
	_decodePath( path, iv ) :
	_encodePath( path, iv );
} 

std::string NameIO::decodePath( const char *path, uint64_t *iv ) const
{
    return getReverseEncryption() ? 
	_encodePath( path, iv ) :
	_decodePath( path, iv );
} 


int NameIO::encodeName( const char *input, int length, char *output ) const
{
    return encodeName( input, length, (uint64_t*)0, output );
}

int NameIO::decodeName( const char *input, int length, char *output ) const
{
    return decodeName( input, length, (uint64_t*)0, output );
}

std::string NameIO::_encodeName( const char *plaintextName, int length ) const
{
    int approxLen = maxEncodedNameLen( length );

    BUFFER_INIT( codeBuf, 32, (unsigned int)approxLen+1 )

    // code the name
    int codedLen = encodeName( plaintextName, length, 0, codeBuf );
    rAssert( codedLen <= approxLen );
    rAssert( codeBuf[codedLen] == '\0' );

    // append result to string
    std::string result = (char*)codeBuf;

    BUFFER_RESET( codeBuf )

    return result;
}

std::string NameIO::_decodeName( const char *encodedName, int length ) const
{
    int approxLen = maxDecodedNameLen( length );

    BUFFER_INIT( codeBuf, 32, (unsigned int)approxLen+1 )

    // code the name
    int codedLen = decodeName( encodedName, length, 0, codeBuf );
    rAssert( codedLen <= approxLen );
    rAssert( codeBuf[codedLen] == '\0' );

    // append result to string
    std::string result = (char*)codeBuf;

    BUFFER_RESET( codeBuf )

    return result;
}

std::string NameIO::encodeName( const char *path, int length ) const
{
   return getReverseEncryption() ?
	_decodeName( path, length ) :
	_encodeName( path, length );
}

std::string NameIO::decodeName( const char *path, int length ) const
{
   return getReverseEncryption() ?
	_encodeName( path, length ) :
	_decodeName( path, length );
}
/*
int NameIO::encodeName( const char *path, int length, 
	char *output ) const
{
   return getReverseEncryption() ?
	_decodeName( path, length, output ) :
	_encodeName( path, length, output );
}

int NameIO::decodeName( const char *path, int length,
	 char *output ) const
{
   return getReverseEncryption() ?
	_encodeName( path, length, output ) :
	_decodeName( path, length, output );
}
*/
