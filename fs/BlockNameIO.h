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
#include <vector>

namespace encfs {

class CipherV1;

/*
    Implement NameIO interface for filename encoding.  Uses cipher in block
    mode to encode filenames.  The filenames are padded to be a multiple of the
    cipher block size.
*/
class BlockNameIO : public NameIO {
 public:
  static Interface CurrentInterface(bool caseSensitive = false);

  BlockNameIO(const Interface &iface, const shared_ptr<CipherV1> &cipher,
              bool caseSensitiveEncoding = false);
  virtual ~BlockNameIO();

  virtual Interface interface() const override;

  virtual int maxEncodedNameLen(int plaintextNameLen) const override;
  virtual int maxDecodedNameLen(int encodedNameLen) const override;

  // hack to help with static builds
  static bool Enabled();

 protected:
  virtual std::string encodeName(const std::string &plaintextName,
                                 uint64_t *iv) const override;
  virtual std::string decodeName(const std::string &encodedName,
                                 uint64_t *iv) const override;

 private:
  int _interface;
  int _bs;
  shared_ptr<CipherV1> _cipher;
  bool _caseSensitive;
};

}  // namespace encfs

#endif
