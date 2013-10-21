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

#ifndef _NullNameIO_incl_
#define _NullNameIO_incl_

#include "fs/NameIO.h"

namespace encfs {

class NullNameIO : public NameIO {
 public:
  static Interface CurrentInterface();

  NullNameIO();

  virtual ~NullNameIO();

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
};

}  // namespace encfs

#endif
