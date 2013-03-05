/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2002-2003, Valient Gough
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

#ifndef _base64_incl_
#define _base64_incl_

#include "base/types.h"

namespace encfs {

inline int B64ToB256Bytes( int numB64Bytes )
{
    return (numB64Bytes * 6) / 8; // round down
}

inline int B32ToB256Bytes( int numB32Bytes )
{
    return (numB32Bytes * 5) / 8; // round down
}

inline int B256ToB64Bytes( int numB256Bytes )
{
    return (numB256Bytes * 8 + 5) / 6; // round up
}

inline int B256ToB32Bytes( int numB256Bytes )
{
    return (numB256Bytes * 8 + 4) / 5; // round up
}


/*
    convert data between different bases - each being a power of 2.
*/
void changeBase2(byte *src, int srcLength, int srcPow2,
                 byte *dst, int dstLength, int dstPow2);

/*
    same as changeBase2, but writes output over the top of input data.
*/
void changeBase2Inline(byte *buf, int srcLength,
	int srcPow2, int dst2Pow, 
	bool outputPartialLastByte);


// inplace translation from values [0,2^6] => base64 ASCII
void B64ToAscii(byte *buf, int length);
// inplace translation from values [0,2^5] => base32 ASCII
void B32ToAscii(byte *buf, int length);

// inplace translation from values base64 ASCII => [0,2^6]
void AsciiToB64(byte *buf, int length);
void AsciiToB64(byte *out, const byte *in, int length);

// inplace translation from values base32 ASCII => [0,2^5]
void AsciiToB32(byte *buf, int length);
void AsciiToB32(byte *out, const byte *in, int length);

}  // namespace encfs

#endif

