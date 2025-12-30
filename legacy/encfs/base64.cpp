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

#include "base64.h"

#include <cctype>  // for toupper

#include "Error.h"

namespace encfs {

// change between two powers of two, stored as the low bits of the bytes in the
// arrays.
// It is the caller's responsibility to make sure the output array is large
// enough.
void changeBase2(unsigned char *src, int srcLen, int src2Pow,
                 unsigned char *dst, int dstLen, int dst2Pow) {
  unsigned long work = 0;
  int workBits = 0;  // number of bits left in the work buffer
  unsigned char *end = src + srcLen;
  unsigned char *origDst = dst;
  const int mask = (1 << dst2Pow) - 1;

  // copy the new bits onto the high bits of the stream.
  // The bits that fall off the low end are the output bits.
  while (src != end) {
    work |= ((unsigned long)(*src++)) << workBits;
    workBits += src2Pow;

    while (workBits >= dst2Pow) {
      *dst++ = work & mask;
      work >>= dst2Pow;
      workBits -= dst2Pow;
    }
  }

  // now, we could have a partial value left in the work buffer..
  if ((workBits != 0) && ((dst - origDst) < dstLen)) {
    *dst++ = work & mask;
  }
}

/*
    Same as changeBase2, except the output is written over the input data.  The
    output is assumed to be large enough to accept the data.

    Uses the stack to store output values.  Recurse every time a new value is
    to be written, then write the value at the tail end of the recursion.
*/
static void changeBase2Inline(unsigned char *src, int srcLen, int src2Pow,
                              int dst2Pow, bool outputPartialLastByte,
                              unsigned long work, int workBits,
                              unsigned char *outLoc) {
  const int mask = (1 << dst2Pow) - 1;
  if (outLoc == nullptr) {
    outLoc = src;
  }

  // copy the new bits onto the high bits of the stream.
  // The bits that fall off the low end are the output bits.
  while ((srcLen != 0) && workBits < dst2Pow) {
    work |= ((unsigned long)(*src++)) << workBits;
    workBits += src2Pow;
    --srcLen;
  }

  // we have at least one value that can be output
  unsigned char outVal = work & mask;
  work >>= dst2Pow;
  workBits -= dst2Pow;

  if (srcLen != 0) {
    // more input left, so recurse
    changeBase2Inline(src, srcLen, src2Pow, dst2Pow, outputPartialLastByte,
                      work, workBits, outLoc + 1);
    *outLoc = outVal;
  } else {
    // no input left, we can write remaining values directly
    *outLoc++ = outVal;

    // we could have a partial value left in the work buffer..
    if (outputPartialLastByte) {
      while (workBits > 0) {
        *outLoc++ = work & mask;
        work >>= dst2Pow;
        workBits -= dst2Pow;
      }
    }
  }
}

void changeBase2Inline(unsigned char *src, int srcLen, int src2Pow, int dst2Pow,
                       bool outputPartialLastByte) {
  changeBase2Inline(src, srcLen, src2Pow, dst2Pow, outputPartialLastByte, 0, 0,
                    nullptr);
}

// character set for ascii b64:
// ",-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
// a standard base64 (eg a64l doesn't use ',-' but uses './'.  We don't
// do that because '/' is a reserved character, and it is useful not to have
// '.' included in the encrypted names, so that it can be reserved for files
// with special meaning.
static const char B642AsciiTable[] = ",-0123456789";
void B64ToAscii(unsigned char *in, int length) {
  for (int offset = 0; offset < length; ++offset) {
    int ch = in[offset];
    if (ch > 11) {
      if (ch > 37) {
        ch += 'a' - 38;
      } else {
        ch += 'A' - 12;
      }
    } else {
      ch = B642AsciiTable[ch];
    }

    in[offset] = ch;
  }
}

static const unsigned char Ascii2B64Table[] =
    "                                            01  23456789:;       ";
//  0123456789 123456789 123456789 123456789 123456789 123456789 1234
//  0         1         2         3         4         5         6
void AsciiToB64(unsigned char *in, int length) {
  return AsciiToB64(in, in, length);
}

void AsciiToB64(unsigned char *out, const unsigned char *in, int length) {
  while ((length--) != 0) {
    unsigned char ch = *in++;
    if (ch >= 'A') {
      if (ch >= 'a') {
        ch += 38 - 'a';
      } else {
        ch += 12 - 'A';
      }
    } else {
      ch = Ascii2B64Table[ch] - '0';
    }
    *out++ = ch;
  }
}

void B32ToAscii(unsigned char *buf, int len) {
  for (int offset = 0; offset < len; ++offset) {
    int ch = buf[offset];
    if (ch >= 0 && ch < 26) {
      ch += 'A';
    } else {
      ch += '2' - 26;
    }

    buf[offset] = ch;
  }
}

void AsciiToB32(unsigned char *in, int length) {
  return AsciiToB32(in, in, length);
}

void AsciiToB32(unsigned char *out, const unsigned char *in, int length) {
  while ((length--) != 0) {
    unsigned char ch = *in++;
    int lch = toupper(ch);
    if (lch >= 'A') {
      lch -= 'A';
    } else {
      lch += 26 - '2';
    }
    *out++ = (unsigned char)lch;
  }
}

#define WHITESPACE 64
#define EQUALS 65
#define INVALID 66

static const unsigned char d[] = {
    66, 66, 66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
    66, 66, 66, 66, 66, 66, 66, 66, 66, 62, 66, 66, 66, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 66, 66,  // 50-59
    66, 65, 66, 66, 66, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 66, 66, 66,
    66, 66, 66, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,  // 100-109
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

bool B64StandardDecode(unsigned char *out, const unsigned char *in, int inLen) {
  const unsigned char *end = in + inLen;
  size_t buf = 1;

  while (in < end) {
    unsigned char v = *in++;
    if (v > 'z') {
      RLOG(ERROR) << "Invalid character: " << (unsigned int)v;
      return false;
    }
    unsigned char c = d[v];

    switch (c) {
      case WHITESPACE:
        continue; /* skip whitespace */
      case INVALID:
        RLOG(ERROR) << "Invalid character: " << (unsigned int)v;
        return false; /* invalid input, return error */
      case EQUALS:    /* pad character, end of data */
        in = end;
        continue;
      default:
        buf = buf << 6 | c;

        /* If the buffer is full, split it into bytes */
        if ((buf & 0x1000000) != 0u) {
          *out++ = buf >> 16;
          *out++ = buf >> 8;
          *out++ = buf;
          buf = 1;
        }
    }
  }

  if ((buf & 0x40000) != 0u) {
    *out++ = buf >> 10;
    *out++ = buf >> 2;
  } else if ((buf & 0x1000) != 0u) {
    *out++ = buf >> 4;
  }

  return true;
}

// Lookup table for encoding
// If you want to use an alternate alphabet, change the characters here
const static char encodeLookup[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string B64StandardEncode(const std::vector<unsigned char> &inputBuffer) {
  std::string encodedString;
  encodedString.reserve(B256ToB64Bytes(inputBuffer.size()));
  long temp;
  auto cursor = inputBuffer.begin();
  for (size_t idx = 0; idx < inputBuffer.size() / 3; idx++) {
    temp = (*cursor++) << 16;  // Convert to big endian
    temp += (*cursor++) << 8;
    temp += (*cursor++);
    encodedString.append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
    encodedString.append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
    encodedString.append(1, encodeLookup[(temp & 0x00000FC0) >> 6]);
    encodedString.append(1, encodeLookup[(temp & 0x0000003F)]);
  }

  switch (inputBuffer.size() % 3) {
    case 1:
      temp = (*cursor++) << 16;  // Convert to big endian
      encodedString.append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
      encodedString.append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
      encodedString.append(2, '=');
      break;
    case 2:
      temp = (*cursor++) << 16;  // Convert to big endian
      temp += (*cursor++) << 8;
      encodedString.append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
      encodedString.append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
      encodedString.append(1, encodeLookup[(temp & 0x00000FC0) >> 6]);
      encodedString.append(1, '=');
      break;
  }
  return encodedString;
}

}  // namespace encfs
