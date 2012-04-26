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

#include "XmlReader.h"
#include "base64.h"

#include <rlog/rlog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

#include <map>

#include <tinyxml.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

using namespace std;
using namespace rlog;

XmlValue::~XmlValue()
{
}

XmlValuePtr XmlValue::operator[] (const char *path) const
{
  return this->find(path);
}

XmlValuePtr XmlValue::find(const char *name) const
{
  rError("in XmlValue::operator[%s]", name);
  return XmlValuePtr(new XmlValue());
}

const XmlValuePtr & operator >> (const XmlValuePtr &ptr, std::string &out)
{
  out = ptr->text();
  return ptr;
}

const XmlValuePtr & operator >> (const XmlValuePtr &ptr, int &out)
{
  out = atoi(ptr->text().c_str());
  return ptr;
}

const XmlValuePtr & operator >> (const XmlValuePtr &ptr, long &out)
{
  out = atol(ptr->text().c_str());
  return ptr;
}

const XmlValuePtr & operator >> (const XmlValuePtr &ptr, double &out)
{
  out = atof(ptr->text().c_str());
  return ptr;
}

const XmlValuePtr & operator >> (const XmlValuePtr &ptr, bool &out)
{
  out = atoi(ptr->text().c_str());
  return ptr;
}

bool XmlValue::readB64Data(unsigned char *data, int length) const
{
  std::string s = value;
  s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  BIO *bmem = BIO_new_mem_buf((void *)s.c_str(), s.size());
  bmem = BIO_push(b64, bmem);

  int decodedSize = BIO_read(bmem, data, length);
  BIO_free_all(b64);
  
  if (decodedSize != length) 
  {
    rError("decoding bytes len %i, expecting output len %i, got %i",
        (int)s.size(), length, decodedSize);
    return false;
  }

  return true;
}

std::string safeValueForNode(TiXmlElement *element)
{
  std::string value;
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
  TiXmlElement *element;
public:
  XmlNode(TiXmlElement *element_)
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
      return XmlValuePtr(new XmlValue(element->Attribute(name+1)));
    } else
    {
      return XmlValuePtr(new XmlNode(element->FirstChild(name)->ToElement()));
    }
  }
};

struct XmlReader::XmlReaderData
{
  boost::shared_ptr<TiXmlDocument> doc;
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
    rError("Xml node %s not found", name);
    return XmlValuePtr(new XmlValue());
  }

  TiXmlElement *element = node->ToElement();
  if (element == NULL)
  {
    rError("Xml node %s not element, type = %i", name, node->Type());
    return XmlValuePtr(new XmlValue());
  }

  return XmlValuePtr(new XmlNode(element));
}

