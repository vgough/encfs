/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2012-2013, Valient Gough
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

#include "base/XmlReader.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <map>

#include <tinyxml.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <glog/logging.h>
#include "base/base64.h"
#include "base/Interface.h"

using namespace std;

namespace encfs {

XmlValue::~XmlValue()
{
}

XmlValuePtr XmlValue::operator[] (const char *path) const
{
  return find(path);
}

XmlValuePtr XmlValue::find(const char *path) const
{
  LOG_FIRST_N(ERROR, 1) << "in XmlValue::find( " << path << ")";
  return XmlValuePtr();
}

bool XmlValue::read(const char *path, std::string *out) const
{
  XmlValuePtr value = find(path);
  if (!value)
    return false;

  *out = value->text();
  return true;
}

bool XmlValue::read(const char *path, int *out) const
{
  XmlValuePtr value = find(path);
  if (!value)
    return false;

  *out = atoi(value->text().c_str());
  return true;
}

bool XmlValue::read(const char *path, long *out) const
{
  XmlValuePtr value = find(path);
  if (!value)
    return false;

  *out = atol(value->text().c_str());
  return true;
}

bool XmlValue::read(const char *path, double *out) const
{
  XmlValuePtr value = find(path);
  if (!value)
    return false;

  *out = atof(value->text().c_str());
  return true;
}

bool XmlValue::read(const char *path, bool *out) const
{
  XmlValuePtr value = find(path);
  if (!value)
    return false;

  *out = atoi(value->text().c_str());
  return true;
}

bool XmlValue::readB64(const char *path, byte *data, int length) const
{
  XmlValuePtr value = find(path);
  if (!value)
    return false;
  
  std::string s = value->text();
  s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO *bmem = BIO_new_mem_buf((void *)s.c_str(), s.size());
  bmem = BIO_push(b64, bmem);

  int decodedSize = BIO_read(bmem, data, length);
  BIO_free_all(b64);
  
  if (decodedSize != length) 
  {
    LOG(ERROR) << "decoding bytes len " << s.size()
               << ", expecting output len " << length
               << ", got " << decodedSize;
    return false;
  }

  return true;
}

bool XmlValue::read(const char *path, Interface *out) const
{
  XmlValuePtr node = find(path);
  if (!node)
    return false;

  int major, minor;
  bool ok = node->read("name", out->mutable_name())
         && node->read("major", &major)
         && node->read("minor", &minor);

  if (!ok)
    return false;

  out->set_major(major);
  out->set_minor(minor);
  return true;
}

std::string safeValueForNode(const TiXmlElement *element)
{
  std::string value;
  if (element == NULL)
    return value;

  const TiXmlNode *child = element->FirstChild();
  if (child)
  {
    const TiXmlText *childText = child->ToText();
    if (childText)
      value = childText->Value();
  }

  return value;
}

class XmlNode : virtual public XmlValue
{
  const TiXmlElement *element;
public:
  XmlNode(const TiXmlElement *element_)
    : XmlValue(safeValueForNode(element_))
    , element(element_)
  {
  }

  virtual ~XmlNode()
  {
  }

  virtual XmlValuePtr find(const char *name) const
  {
    if (name[0] == '@') 
    {
      const char *value = element->Attribute(name+1);
      if (value)
        return XmlValuePtr(new XmlValue(value));
      else 
        return XmlValuePtr();
    } else
    {
      const TiXmlElement *el = element->FirstChildElement(name);
      if (el)
        return XmlValuePtr(new XmlNode(el));
      else
        return XmlValuePtr();
    }
  }
};

struct XmlReader::XmlReaderData
{
  shared_ptr<TiXmlDocument> doc;
};

XmlReader::XmlReader()
  : pd(new XmlReaderData())
{
}

XmlReader::~XmlReader()
{
}

bool XmlReader::load(const char *fileName)
{
  pd->doc.reset(new TiXmlDocument(fileName));

  return pd->doc->LoadFile();
}

XmlValuePtr XmlReader::operator[] ( const char *name ) const
{
  TiXmlNode *node = pd->doc->FirstChild(name);
  if (node == NULL)
  {
    LOG(ERROR) << "Xml node " << name << " not found";
    return XmlValuePtr(new XmlValue());
  }

  TiXmlElement *element = node->ToElement();
  if (element == NULL)
  {
    LOG(ERROR) << "Xml node " << name
               << " not element, type = " << node->Type();
    return XmlValuePtr(new XmlValue());
  }

  return XmlValuePtr(new XmlNode(element));
}

}  // namespace encfs
