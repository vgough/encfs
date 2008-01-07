/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2002-2004, Valient Gough
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

#include "base64.h"

// change between two powers of two, stored as the low bits of the bytes in the
// arrays.
// It is the caller's responsibility to make sure the output array is large
// enough.
void changeBase2(unsigned char *src, int srcLen, int src2Pow,
                 unsigned char *dst, int dstLen, int dst2Pow)
{
    unsigned long work = 0;
    int workBits = 0; // number of bits left in the work buffer
    unsigned char *end = src + srcLen;
    unsigned char *origDst = dst;
    const int mask = (1 << dst2Pow) -1;

    // copy the new bits onto the high bits of the stream.
    // The bits that fall off the low end are the output bits.
    while(src != end)
    {
	work |= ((unsigned long)(*src++)) << workBits;
	workBits += src2Pow;

	while(workBits >= dst2Pow)
	{
	    *dst++ = work & mask;
	    work >>= dst2Pow;
	    workBits -= dst2Pow;
	}
    }

    // now, we could have a partial value left in the work buffer..
    if(workBits && ((dst - origDst) < dstLen))
	*dst++ = work & mask;
}

/*
    Same as changeBase2, except the output is written over the input data.  The
    output is assumed to be large enough to accept the data.

    Uses the stack to store output values.  Recurse every time a new value is
    to be written, then write the value at the tail end of the recursion.
*/
static
void changeBase2Inline(unsigned char *src, int srcLen, 
	               int src2Pow, int dst2Pow,
		       bool outputPartialLastByte,
		       unsigned long work,
		       int workBits,
		       unsigned char *outLoc)
{
    const int mask = (1 << dst2Pow) -1;
    if(!outLoc)
	outLoc = src;

    // copy the new bits onto the high bits of the stream.
    // The bits that fall off the low end are the output bits.
    while(srcLen && workBits < dst2Pow)
    {
	work |= ((unsigned long)(*src++)) << workBits;
	workBits += src2Pow;
	--srcLen;
    }

    // we have at least one value that can be output
    char outVal = work & mask;
    work >>= dst2Pow;
    workBits -= dst2Pow;

    if(srcLen)
    {
	// more input left, so recurse
	changeBase2Inline( src, srcLen, src2Pow, dst2Pow,
		           outputPartialLastByte, work, workBits, outLoc+1);
	*outLoc = outVal;
    } else
    {
	// no input left, we can write remaining values directly
	*outLoc++ = outVal;

	// we could have a partial value left in the work buffer..
	if(workBits && outputPartialLastByte)
	    *outLoc = work & mask;
    }
}

void changeBase2Inline(unsigned char *src, int srcLen, 
	               int src2Pow, int dst2Pow,
		       bool outputPartialLastByte)
{
    changeBase2Inline(src, srcLen, src2Pow, dst2Pow, 
	    outputPartialLastByte, 0, 0, 0);
}


// character set for ascii b64:
// ",-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
// a standard base64 (eg a64l doesn't use ',-' but uses './'.  We don't
// do that because '/' is a reserved character, and it is useful not to have
// '.' included in the encrypted names, so that it can be reserved for files
// with special meaning.
static const char B642AsciiTable[] = ",-0123456789";
void B64ToAscii(unsigned char *in, int length)
{
    for(int offset=0; offset<length; ++offset)
    {
	int ch = in[offset];
	if(ch > 11)
	{
	    if(ch > 37)
		ch += 'a' - 38;
	    else
		ch += 'A' - 12;
	} else
	    ch = B642AsciiTable[ ch ];
	
	in[offset] = ch;
    }
}

static const unsigned char Ascii2B64Table[] = 
       "                                            01  23456789:;       ";
    //  0123456789 123456789 123456789 123456789 123456789 123456789 1234
    //  0         1         2         3         4         5         6
void AsciiToB64(unsigned char *in, int length)
{
    return AsciiToB64(in, in, length);
}

void AsciiToB64(unsigned char *out, const unsigned char *in, int length)
{
    while(length--)
    {
	unsigned char ch = *in++;
	if(ch >= 'A')
	{
	    if(ch >= 'a')
		ch += 38 - 'a';
	    else
		ch += 12 - 'A';
	} else
	    ch = Ascii2B64Table[ ch ] - '0';

	*out++ = ch;
    }
}

