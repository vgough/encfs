/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2012, Valient Gough
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
                             
#ifndef _XmlReader_incl_
#define _XmlReader_incl_

#include <boost/shared_ptr.hpp>
#include <string>

class XmlValue;
typedef boost::shared_ptr<XmlValue> XmlValuePtr;

class XmlValue
{
  std::string value;
public:
  XmlValue()
  {
  }

  XmlValue(const std::string &value)
  {
    this->value = value;
  }
  virtual ~XmlValue();

  XmlValuePtr operator[] (const char *path) const;

  bool readB64Data(unsigned char *data, int length) const;

  const std::string &text() const
  {
    return value;
  }

protected:
  virtual XmlValuePtr find(const char *name) const;
};

const XmlValuePtr & operator >> (const XmlValuePtr &ptr, std::string &outStr);
const XmlValuePtr & operator >> (const XmlValuePtr &ptr, int &out);
const XmlValuePtr & operator >> (const XmlValuePtr &ptr, long &out);
const XmlValuePtr & operator >> (const XmlValuePtr &ptr, double &out);
const XmlValuePtr & operator >> (const XmlValuePtr &ptr, bool &out);

class XmlReader
{
public:
  XmlReader();
  ~XmlReader();

  bool load(const char *fileName);

  XmlValuePtr operator[](const char *name) const;

private:
  struct XmlReaderData;
  boost::shared_ptr<XmlReaderData> pd;
};

#endif
