/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2012, Valient Gough
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

#ifndef _XmlReader_incl_
#define _XmlReader_incl_

#include <memory>
#include <string>

#include "Interface.h"

namespace encfs {

class XmlValue;
using XmlValuePtr = std::shared_ptr<XmlValue>;

class XmlValue {
  std::string value;

 public:
  XmlValue() {}

  XmlValue(const std::string &value) { this->value = value; }
  virtual ~XmlValue();

  XmlValuePtr operator[](const char *path) const;

  const std::string &text() const { return value; }

  bool read(const char *path, std::string *out) const;
  bool readB64(const char *path, unsigned char *out, int length) const;

  bool read(const char *path, int *out) const;
  bool read(const char *path, long *out) const;
  bool read(const char *path, double *out) const;
  bool read(const char *path, bool *out) const;

  bool read(const char *path, Interface *out) const;

 protected:
  virtual XmlValuePtr find(const char *name) const;
};

class XmlReader {
 public:
  XmlReader();
  ~XmlReader();

  bool load(const char *fileName);

  XmlValuePtr operator[](const char *name) const;

 private:
  struct XmlReaderData;
  std::shared_ptr<XmlReaderData> pd;
};

}  // namespace encfs

#endif
