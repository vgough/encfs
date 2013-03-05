/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2002-2004, Valient Gough
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

#include "base/config.h"
#include "cipher/Cipher.h"

#include <map>
#include <list>
#include <string>
#include <iostream>

#include "base/Interface.h"
#include "base/Range.h"
#include "base/base64.h"

// for static build.  Need to reference the modules which are registered at
// run-time, to ensure that the linker doesn't optimize them away.
#include "cipher/NullCipher.h"
#include "cipher/SSL_Cipher.h"

using namespace std;

namespace encfs {

#define REF_MODULE(TYPE)  \
    if( !TYPE::Enabled() ) \
	cerr << "referenceModule: should never happen\n";

static
void AddSymbolReferences()
{
    REF_MODULE(SSL_Cipher)
    REF_MODULE(NullCipher)
}


struct CipherAlg
{
    bool hidden;
    Cipher::CipherConstructor constructor;
    string description;
    Interface iface;
    Range keyLength;
    Range blockSize;
    bool hasStreamMode;
};

typedef multimap< string, CipherAlg> CipherMap_t;
static CipherMap_t *gCipherMap = NULL;

std::list<Cipher::CipherAlgorithm> 
Cipher::GetAlgorithmList( bool includeHidden )
{
    AddSymbolReferences();

    list<CipherAlgorithm> result;

    if(!gCipherMap)
	return result;

    CipherMap_t::const_iterator it;
    CipherMap_t::const_iterator mapEnd = gCipherMap->end();
    for(it = gCipherMap->begin(); it != mapEnd; ++it)
    {
	if(includeHidden || !it->second.hidden)
	{
	    CipherAlgorithm tmp;
	    tmp.name = it->first;
	    tmp.description = it->second.description;
	    tmp.iface = it->second.iface;
	    tmp.keyLength = it->second.keyLength;
	    tmp.blockSize = it->second.blockSize;
            tmp.hasStreamMode = it->second.hasStreamMode;

	    result.push_back( tmp );
	}
    }

    return result;
}

bool Cipher::Register(const char *name, const char *description,
	const Interface &iface, CipherConstructor fn, 
        bool hasStreamMode, bool hidden)
{
    Range keyLength(-1,-1,1);
    Range blockSize(-1,-1,1);
    return Cipher::Register( name, description, iface, 
	    keyLength, blockSize, fn, hasStreamMode, hidden );
}

bool Cipher::Register(const char *name, const char *description,
	const Interface &iface, const Range &keyLength, 
	const Range &blockSize, 
	CipherConstructor fn, 
        bool hasStreamMode,
        bool hidden)
{
    if(!gCipherMap)
	gCipherMap = new CipherMap_t;

    CipherAlg ca;
    ca.hidden = hidden;
    ca.constructor = fn;
    ca.description = description;
    ca.iface = iface;
    ca.keyLength = keyLength;
    ca.blockSize = blockSize;
    ca.hasStreamMode = hasStreamMode;

    gCipherMap->insert( make_pair(string(name), ca) );
    return true;
}

shared_ptr<Cipher> Cipher::New(const string &name, int keyLen)
{
    shared_ptr<Cipher> result;

    if(gCipherMap)
    {
	CipherMap_t::const_iterator it = gCipherMap->find( name );
	if(it != gCipherMap->end())
	{
	    CipherConstructor fn = it->second.constructor;
	    // use current interface..
	    result = (*fn)( it->second.iface, keyLen );
	}
    }

    return result;
}

shared_ptr<Cipher> Cipher::New( const Interface &iface, int keyLen )
{
    shared_ptr<Cipher> result;
    if(gCipherMap)
    {
	CipherMap_t::const_iterator it;
	CipherMap_t::const_iterator mapEnd = gCipherMap->end();

	for(it = gCipherMap->begin(); it != mapEnd; ++it)
	{
	    // TODO: we should look for the newest implementation..
	    if( implements(it->second.iface, iface) )
	    {
		CipherConstructor fn = it->second.constructor;
		// pass in requested interface..
		result = (*fn)( iface, keyLen );

		// if we're not going to compare the options, then just stop
		// now..
		break;
	    }
	}
    }

    return result;
}

Cipher::Cipher()
{
}

Cipher::~Cipher()
{
}

unsigned int Cipher::MAC_32( const byte *src, int len, 
	const CipherKey &key, uint64_t *chainedIV ) const
{
    uint64_t mac64 = MAC_64( src, len, key, chainedIV );

    unsigned int mac32 = ((mac64 >> 32) & 0xffffffff) ^ (mac64 & 0xffffffff);

    return mac32;
}

unsigned int Cipher::MAC_16( const byte *src, int len, 
	const CipherKey &key, uint64_t *chainedIV ) const
{
    uint64_t mac64 = MAC_64( src, len, key, chainedIV );

    unsigned int mac32 = ((mac64 >> 32) & 0xffffffff) ^ (mac64 & 0xffffffff);
    unsigned int mac16 = ((mac32 >> 16) & 0xffff) ^ (mac32 & 0xffff);

    return mac16;
}

string Cipher::encodeAsString(const CipherKey &key,
        const CipherKey &encodingKey )
{
    int encodedKeySize = this->encodedKeySize();
    byte *keyBuf = new byte[ encodedKeySize ];

    this->writeKey( key, keyBuf, encodingKey );

    int b64Len = B256ToB64Bytes( encodedKeySize );
    byte *b64Key = new byte[ b64Len + 1 ];

    changeBase2( keyBuf, encodedKeySize, 8, b64Key,
            b64Len, 6 );
    B64ToAscii( b64Key, b64Len );
    b64Key[ b64Len - 1 ] = '\0';

    return string( (const char *)b64Key );
}

bool Cipher::hasStreamMode() const
{
  return true;
}

}  // namespace encfs
