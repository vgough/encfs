/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2002-2003, Valient Gough
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
 *
 */

#ifndef _Cipher_incl_
#define _Cipher_incl_

#include "encfs.h"

#include "Range.h"
#include "Interface.h"
#include "CipherKey.h"

#include <string>
#include <list>
#include <inttypes.h>

using boost::shared_ptr;

/*
    Mostly pure virtual interface defining operations on a cipher.

    Cipher's should register themselves so they can be instanciated via
    Cipher::New().
*/
class Cipher
{
public:
    // if no key length was indicated when cipher was registered, then keyLen
    // <= 0 will be used.
    typedef boost::shared_ptr<Cipher> (*CipherConstructor)( const rel::Interface &iface,
	                                      int keyLenBits );

    struct CipherAlgorithm
    {
	std::string name;
	std::string description;
	rel::Interface iface;
	Range keyLength;
	Range blockSize;
    };


    typedef std::list<CipherAlgorithm> AlgorithmList;
    static AlgorithmList GetAlgorithmList( bool includeHidden = false );


    static boost::shared_ptr<Cipher> New( const rel::Interface &iface, 
	                                  int keyLen = -1);
    static boost::shared_ptr<Cipher> New( const std::string &cipherName, 
	                                  int keyLen = -1 );


    static bool Register(const char *cipherName, 
	    const char *description, 
	    const rel::Interface &iface,
	    CipherConstructor constructor,
	    bool hidden = false);
    static bool Register(const char *cipherName, 
	    const char *description, 
	    const rel::Interface &iface,
	    const Range &keyLength, const Range &blockSize,
	    CipherConstructor constructor,
	    bool hidden = false);


    Cipher();
    virtual ~Cipher();

    virtual rel::Interface interface() const =0;

    // create a new key based on a password
    virtual CipherKey newKey(const char *password, int passwdLength) =0;
    // create a new random key
    virtual CipherKey newRandomKey() =0;

    // data must be len encodedKeySize()
    virtual CipherKey readKey(const unsigned char *data, 
	                      const CipherKey &encodingKey,
			      bool checkKey = true) =0;
    virtual void writeKey(const CipherKey &key, unsigned char *data, 
	                  const CipherKey &encodingKey) =0; 

    virtual std::string encodeAsString(const CipherKey &key,
                                  const CipherKey &encodingKey );

    // for testing purposes
    virtual bool compareKey( const CipherKey &A, const CipherKey &B ) const =0;

    // meta-data about the cypher
    virtual int keySize() const=0;
    virtual int encodedKeySize() const=0; // size 
    virtual int cipherBlockSize() const=0; // size of a cipher block

    // fill the supplied buffer with random data
    // The data may be pseudo random and might not be suitable for key
    // generation.  For generating keys, uses newRandomKey() instead.
    virtual void randomize( unsigned char *buf, int len ) const =0;

    // 64 bit MAC of the data with the given key
    virtual uint64_t MAC_64( const unsigned char *src, int len,
	    const CipherKey &key, uint64_t *chainedIV = 0 ) const =0;
    // based on reductions of MAC_64
    unsigned int MAC_32( const unsigned char *src, int len,
	    const CipherKey &key, uint64_t *chainedIV = 0 ) const;
    unsigned int MAC_16( const unsigned char *src, int len,
	    const CipherKey &key, uint64_t *chainedIV = 0 ) const;

    // functional interfaces
    /*
	Stream encoding of data in-place.  The stream data can be any length.
    */
    virtual bool streamEncode( unsigned char *data, int len, 
	    uint64_t iv64, const CipherKey &key) const=0;
    virtual bool streamDecode( unsigned char *data, int len, 
	    uint64_t iv64, const CipherKey &key) const=0;

    /*
	These are just aliases of streamEncode / streamDecode, but there are
	provided here for backward compatibility for earlier ciphers that has
	effectively two stream modes - one for encoding partial blocks and
	another for encoding filenames.
    */
    virtual bool nameEncode( unsigned char *data, int len, 
	    uint64_t iv64, const CipherKey &key) const;
    virtual bool nameDecode( unsigned char *data, int len, 
	    uint64_t iv64, const CipherKey &key) const;

    /*
	Block encoding of data in-place.  The data size should be a multiple of
	the cipher block size.
    */
    virtual bool blockEncode(unsigned char *buf, int size, 
	                     uint64_t iv64, const CipherKey &key) const=0;
    virtual bool blockDecode(unsigned char *buf, int size, 
	                     uint64_t iv64, const CipherKey &key) const=0;
};


#endif

