/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004-2011, Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "BlockNameIO.h"

#include "Cipher.h"
#include "base64.h"

#include <cstring>
#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>

#include "i18n.h"

using namespace rlog;
using namespace boost;

static RLogChannel * Info = DEF_CHANNEL( "info/nameio", Log_Info );


static shared_ptr<NameIO> NewBlockNameIO( const Interface &iface,
	const shared_ptr<Cipher> &cipher, const CipherKey &key )
{
    int blockSize = 8;
    if(cipher)
	blockSize = cipher->cipherBlockSize();

    return shared_ptr<NameIO>( 
        new BlockNameIO( iface, cipher, key, blockSize, false));
}

static shared_ptr<NameIO> NewBlockNameIO32( const Interface &iface,
	const shared_ptr<Cipher> &cipher, const CipherKey &key )
{
    int blockSize = 8;
    if(cipher)
	blockSize = cipher->cipherBlockSize();

    return shared_ptr<NameIO>( 
        new BlockNameIO( iface, cipher, key, blockSize, true));
}

static bool BlockIO_registered = NameIO::Register("Block",
	// description of block name encoding algorithm..
	// xgroup(setup)
	gettext_noop("Block encoding, hides file name size somewhat"),
	BlockNameIO::CurrentInterface(false),
	NewBlockNameIO);

static bool BlockIO32_registered = NameIO::Register("Block32",
	// description of block name encoding algorithm..
	// xgroup(setup)
	gettext_noop("Block encoding with base32 output for case-sensitive systems"),
	BlockNameIO::CurrentInterface(true),
	NewBlockNameIO32);

/*
    - Version 1.0 computed MAC over the filename, but not the padding bytes.
      This version was from pre-release 1.1, never publically released, so no
      backward compatibility necessary.

    - Version 2.0 includes padding bytes in MAC computation.  This way the MAC
      computation uses the same number of bytes regardless of the number of
      padding bytes.

    - Version 3.0 uses full 64 bit initialization vector during IV chaining.
      Prior versions used only the output from the MAC_16 call, giving a 1 in
      2^16 chance of the same name being produced.  Using the full 64 bit IV
      changes that to a 1 in 2^64 chance..

    - Version 4.0 adds support for base32, creating names more suitable for
      case-insensitive filesystems (eg Mac).
*/
Interface BlockNameIO::CurrentInterface(bool caseSensitive)
{
    // implement major version 4 plus support for two prior versions
    if (caseSensitive)
        return makeInterface("nameio/block32", 4, 0, 2);
    else
        return makeInterface("nameio/block", 4, 0, 2);
}

BlockNameIO::BlockNameIO( const Interface &iface,
	const shared_ptr<Cipher> &cipher, 
	const CipherKey &key, int blockSize,
        bool caseSensitiveEncoding )
    : _interface( iface.major() )
    , _bs( blockSize )
    , _cipher( cipher )
    , _key( key )
    , _caseSensitive( caseSensitiveEncoding )
{
    // just to be safe..
    rAssert( blockSize < 128 );
}

BlockNameIO::~BlockNameIO()
{
}

Interface BlockNameIO::interface() const
{
    return CurrentInterface(_caseSensitive);
}

int BlockNameIO::maxEncodedNameLen( int plaintextNameLen ) const
{
    // number of blocks, rounded up.. Only an estimate at this point, err on
    // the size of too much space rather then too little.
    int numBlocks = ( plaintextNameLen + _bs ) / _bs;
    int encodedNameLen = numBlocks * _bs + 2; // 2 checksum bytes
    if (_caseSensitive)
      return B256ToB32Bytes( encodedNameLen );
    else
      return B256ToB64Bytes( encodedNameLen );
}

int BlockNameIO::maxDecodedNameLen( int encodedNameLen ) const
{
    int decLen256 = _caseSensitive ? 
      B32ToB256Bytes( encodedNameLen ) :
      B64ToB256Bytes( encodedNameLen );
    return decLen256 - 2; // 2 checksum bytes removed..
}

int BlockNameIO::encodeName( const char *plaintextName, int length,
	uint64_t *iv, char *encodedName ) const
{
    // copy the data into the encoding buffer..
    memcpy( encodedName+2, plaintextName, length );
    
    // Pad encryption buffer to block boundary..
    int padding = _bs - length % _bs;
    if(padding == 0)
	padding = _bs; // padding a full extra block!

    memset( encodedName+length+2, (unsigned char)padding, padding );
    
    // store the IV before it is modified by the MAC call.
    uint64_t tmpIV = 0;
    if( iv && _interface >= 3 )
	tmpIV = *iv;

    // include padding in MAC computation
    unsigned int mac = _cipher->MAC_16( (unsigned char *)encodedName+2,
	    length+padding, _key, iv );

    // add checksum bytes
    encodedName[0] = (mac >> 8) & 0xff;
    encodedName[1] = (mac     ) & 0xff;

    _cipher->blockEncode( (unsigned char *)encodedName+2, length+padding,
	    (uint64_t)mac ^ tmpIV, _key);

    // convert to base 64 ascii
    int encodedStreamLen = length + 2 + padding;
    int encLen;
    
    if (_caseSensitive) 
    {
        encLen = B256ToB32Bytes( encodedStreamLen );

        changeBase2Inline( (unsigned char *)encodedName, encodedStreamLen,
	        8, 5, true );
        B32ToAscii( (unsigned char *)encodedName, encLen );
    } else 
    {
        encLen = B256ToB64Bytes( encodedStreamLen );

        changeBase2Inline( (unsigned char *)encodedName, encodedStreamLen,
	        8, 6, true );
        B64ToAscii( (unsigned char *)encodedName, encLen );
    }

    return encLen;
}

int BlockNameIO::decodeName( const char *encodedName, int length,
	uint64_t *iv, char *plaintextName ) const
{
    int decLen256 = _caseSensitive ?
        B32ToB256Bytes( length ) :
        B64ToB256Bytes( length );
    int decodedStreamLen = decLen256 - 2;

    // don't bother trying to decode files which are too small
    if(decodedStreamLen < _bs)
	throw ERROR("Filename too small to decode");

    BUFFER_INIT( tmpBuf, 32, (unsigned int)length );

    // decode into tmpBuf,
    if (_caseSensitive) 
    {
        AsciiToB32((unsigned char *)tmpBuf, (unsigned char *)encodedName, length);
        changeBase2Inline((unsigned char *)tmpBuf, length, 5, 8, false);
    } else 
    {
        AsciiToB64((unsigned char *)tmpBuf, (unsigned char *)encodedName, length);
        changeBase2Inline((unsigned char *)tmpBuf, length, 6, 8, false);
    }

    // pull out the header information
    unsigned int mac = ((unsigned int)((unsigned char)tmpBuf[0])) << 8
	             | ((unsigned int)((unsigned char)tmpBuf[1]));

    uint64_t tmpIV = 0;
    if( iv && _interface >= 3 )
	tmpIV = *iv;

    _cipher->blockDecode( (unsigned char *)tmpBuf+2, decodedStreamLen,
	    (uint64_t)mac ^ tmpIV, _key);

    // find out true string length
    int padding = (unsigned char)tmpBuf[2+decodedStreamLen-1];
    int finalSize = decodedStreamLen - padding;
    
    // might happen if there is an error decoding..
    if(padding > _bs || finalSize < 0)
    {
	rDebug("padding, _bx, finalSize = %i, %i, %i", padding, 
		_bs, finalSize);
	throw ERROR( "invalid padding size" );
    }

    // copy out the result..
    memcpy(plaintextName, tmpBuf+2, finalSize);
    plaintextName[finalSize] = '\0';

    // check the mac
    unsigned int mac2 = _cipher->MAC_16((const unsigned char *)tmpBuf+2,
	    decodedStreamLen, _key, iv);
    
    BUFFER_RESET( tmpBuf );

    if(mac2 != mac)
    {
	rDebug("checksum mismatch: expected %u, got %u", mac, mac2);
	rDebug("on decode of %i bytes", finalSize);
	throw ERROR( "checksum mismatch in filename decode" );
    }

    return finalSize;
}

bool BlockNameIO::Enabled()
{
    return true;
}

