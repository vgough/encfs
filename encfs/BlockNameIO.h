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

#ifndef _BlockNameIO_incl_
#define _BlockNameIO_incl_

#include "NameIO.h"
#include "CipherKey.h"

#include <boost/shared_ptr.hpp>

class Cipher;

/*
    Implement NameIO interface for filename encoding.  Uses cipher in block
    mode to encode filenames.  The filenames are padded to be a multiple of the
    cipher block size.
*/
class BlockNameIO : public NameIO
{
public:
    static rel::Interface CurrentInterface();

    BlockNameIO( const rel::Interface &iface,
	         const boost::shared_ptr<Cipher> &cipher, 
	         const CipherKey &key, int blockSize );
    virtual ~BlockNameIO();

    virtual rel::Interface interface() const;

    virtual int maxEncodedNameLen( int plaintextNameLen ) const;
    virtual int maxDecodedNameLen( int encodedNameLen ) const;

    // hack to help with static builds
    static bool Enabled();
protected:
    virtual int encodeName( const char *plaintextName, int length,
	                    uint64_t *iv, char *encodedName ) const;
    virtual int decodeName( const char *encodedName, int length,
	                    uint64_t *iv, char *plaintextName ) const;

private:
    int _interface;
    int _bs;
    boost::shared_ptr<Cipher> _cipher;
    CipherKey _key;
};


#endif

