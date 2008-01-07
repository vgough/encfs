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

#include "StreamNameIO.h"

#include "Cipher.h"
#include "base64.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>

#include "i18n.h"

using namespace rel;
using namespace std;

static shared_ptr<NameIO> NewStreamNameIO( const Interface &iface,
	const shared_ptr<Cipher> &cipher, const CipherKey &key)
{
    return shared_ptr<NameIO>( new StreamNameIO( iface, cipher, key ) );
}

static bool StreamIO_registered = NameIO::Register("Stream",
	gettext_noop("Stream encoding, keeps filenames as short as possible"),
	StreamNameIO::CurrentInterface(),
	NewStreamNameIO);


/*
    - Version 0.1 is for EncFS 0.x support.  The difference to 1.0 is that 0.x
      stores the file checksums at the end of the encoded name, where 1.0
      stores them at the beginning.

    - Version 1.0 is the basic stream encoding mode used since the beginning of
      EncFS.  There is a slight difference in filename encodings from EncFS 0.x
      to 1.0.x.  This implements just the 1.0.x method.

    - Version 1.1 adds support for IV chaining.  This is transparently
      backward compatible, since older filesystems do not use IV chaining.

    - Version 2.0 uses full 64 bit IV during IV chaining mode.  Prior versions
      used only the 16 bit output from MAC_16.  This reduces the theoretical
      possibility (unlikely to make any difference in practice) of two files
      with the same name in different directories ending up with the same
      encrypted name.  Added because there is no good reason to chop to 16
      bits.

    - Version 2.1 adds support for version 0 for EncFS 0.x compatibility.
*/
Interface StreamNameIO::CurrentInterface()
{
    // implement major version 2, 1, and 0
    return Interface("nameio/stream", 2, 1, 2);
}

StreamNameIO::StreamNameIO( const rel::Interface &iface,
	const shared_ptr<Cipher> &cipher, 
	const CipherKey &key )
    : _interface( iface.current() )
    , _cipher( cipher )
    , _key( key )
{

}

StreamNameIO::~StreamNameIO()
{
}

Interface StreamNameIO::interface() const
{
    return CurrentInterface();
}

int StreamNameIO::maxEncodedNameLen( int plaintextStreamLen ) const
{
    int encodedStreamLen = 2 + plaintextStreamLen;
    return B256ToB64Bytes( encodedStreamLen );
}

int StreamNameIO::maxDecodedNameLen( int encodedStreamLen ) const
{
    int decLen256 = B64ToB256Bytes( encodedStreamLen );
    return decLen256 - 2;
}

int StreamNameIO::encodeName( const char *plaintextName, int length,
	uint64_t *iv, char *encodedName ) const
{
    uint64_t tmpIV = 0;
    if( iv && _interface >= 2 )
	tmpIV = *iv;

    unsigned int mac = _cipher->MAC_16( (const unsigned char *)plaintextName, 
	    length, _key, iv );

    // add on checksum bytes
    unsigned char *encodeBegin;
    if(_interface >= 1)
    {
	// current versions store the checksum at the beginning
	encodedName[0] = (mac >> 8) & 0xff;
	encodedName[1] = (mac     ) & 0xff;
	encodeBegin = (unsigned char *)encodedName+2;
    } else
    {
	// encfs 0.x stored checksums at the end.
	encodedName[length] = (mac >> 8) & 0xff;
	encodedName[length+1] = (mac     ) & 0xff;
	encodeBegin = (unsigned char *)encodedName;
    }

    // stream encode the plaintext bytes
    memcpy( encodeBegin, plaintextName, length );
    _cipher->nameEncode( encodeBegin, length, (uint64_t)mac ^ tmpIV, _key);

    // convert the entire thing to base 64 ascii..
    int encodedStreamLen = length + 2;
    int encLen64 = B256ToB64Bytes( encodedStreamLen );

    changeBase2Inline( (unsigned char *)encodedName, encodedStreamLen,
	    8, 6, true );
    B64ToAscii( (unsigned char *)encodedName, encLen64 );

    return encLen64;
}

int StreamNameIO::decodeName( const char *encodedName, int length,
	uint64_t *iv, char *plaintextName ) const
{
    rAssert(length > 2);
    int decLen256 = B64ToB256Bytes( length );
    int decodedStreamLen = decLen256 - 2;

    if(decodedStreamLen <= 0)
	throw ERROR("Filename too small to decode");

    BUFFER_INIT( tmpBuf, 32, (unsigned int)length );

    // decode into tmpBuf, because this step produces more data then we can fit
    // into the result buffer..
    AsciiToB64( (unsigned char *)tmpBuf, (unsigned char *)encodedName, length );
    changeBase2Inline((unsigned char *)tmpBuf, length, 6, 8, false);

    // pull out the checksum value which is used as an initialization vector
    uint64_t tmpIV = 0;
    unsigned int mac;
    if(_interface >= 1)
    {
	// current versions store the checksum at the beginning
	mac = ((unsigned int)((unsigned char)tmpBuf[0])) << 8
  	    | ((unsigned int)((unsigned char)tmpBuf[1]));
   
	// version 2 adds support for IV chaining..
       	if( iv && _interface >= 2 )
    	    tmpIV = *iv;
    
	memcpy( plaintextName, tmpBuf+2, decodedStreamLen );
    } else
    {
	// encfs 0.x stored checksums at the end.
	mac = ((unsigned int)((unsigned char)tmpBuf[decodedStreamLen])) << 8
  	    | ((unsigned int)((unsigned char)tmpBuf[decodedStreamLen+1]));

	memcpy( plaintextName, tmpBuf, decodedStreamLen );
    }

    // use nameDeocde instead of streamDecode for backward compatibility
    _cipher->nameDecode( (unsigned char *)plaintextName, decodedStreamLen, 
	    (uint64_t)mac ^ tmpIV, _key);

    // compute MAC to check with stored value
    unsigned int mac2 = _cipher->MAC_16((const unsigned char *)plaintextName, 
	    decodedStreamLen, _key, iv);
    
    BUFFER_RESET( tmpBuf );
    if(mac2 != mac)
    {
	rDebug("checksum mismatch: expected %u, got %u", mac, mac2);
	rDebug("on decode of %i bytes", decodedStreamLen);
	throw ERROR( "checksum mismatch in filename decode" );
    }

    return decodedStreamLen;
}

bool StreamNameIO::Enabled()
{
    return true;
}

