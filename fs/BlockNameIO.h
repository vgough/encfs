/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
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

#ifndef _BlockNameIO_incl_
#define _BlockNameIO_incl_

#include "fs/NameIO.h"

#include <memory>

namespace encfs {

class CipherV1;

/*
    Implement NameIO interface for filename encoding.  Uses cipher in block
    mode to encode filenames.  The filenames are padded to be a multiple of the
    cipher block size.
*/
class BlockNameIO : public NameIO
{
 public:
  static Interface CurrentInterface(bool caseSensitive = false);

  BlockNameIO(const Interface &iface,
              const shared_ptr<CipherV1> &cipher, 
              bool caseSensitiveEncoding = false );
  virtual ~BlockNameIO();

  virtual Interface interface() const;

  virtual int maxEncodedNameLen( int plaintextNameLen ) const;
  virtual int maxDecodedNameLen( int encodedNameLen ) const;

  // hack to help with static builds
  static bool Enabled();
 protected:
  virtual int encodeName(const char *plaintextName, int length,
                         uint64_t *iv, char *encodedName ) const;
  virtual int decodeName(const char *encodedName, int length,
                         uint64_t *iv, char *plaintextName ) const;

 private:
  int _interface;
  int _bs;
  shared_ptr<CipherV1> _cipher;
  bool _caseSensitive;
};

}  // namespace encfs

#endif

