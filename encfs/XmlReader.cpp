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

#include "XmlReader.h"

#include <algorithm>  // for remove_if
#include <cstring>    // for NULL
#include <memory>     // for shared_ptr
#include <fstream>    // for ifstream
#include <sstream>    // for ostringstream

#include <tinyxml2.h>  // for XMLElement, XMLNode, XMLDocument (ptr only)

#include "Error.h"
#include "Interface.h"
#include "base64.h"

namespace encfs {

XmlValue::~XmlValue() {}

XmlValuePtr XmlValue::operator[](const char *path) const { return find(path); }

XmlValuePtr XmlValue::find(const char *path) const {
  // Shouldn't get here.
  RLOG(ERROR) << "in XmlValue::find for path " << path;
  return XmlValuePtr();
}

bool XmlValue::read(const char *path, std::string *out) const {
  XmlValuePtr value = find(path);
  if (!value) return false;

  *out = value->text();
  return true;
}

bool XmlValue::read(const char *path, int *out) const {
  XmlValuePtr value = find(path);
  if (!value) return false;

  *out = atoi(value->text().c_str());
  return true;
}

bool XmlValue::read(const char *path, long *out) const {
  XmlValuePtr value = find(path);
  if (!value) return false;

  *out = atol(value->text().c_str());
  return true;
}

bool XmlValue::read(const char *path, double *out) const {
  XmlValuePtr value = find(path);
  if (!value) return false;

  *out = atof(value->text().c_str());
  return true;
}

bool XmlValue::read(const char *path, bool *out) const {
  XmlValuePtr value = find(path);
  if (!value) return false;

  *out = atoi(value->text().c_str());
  return true;
}

bool XmlValue::readB64(const char *path, unsigned char *data,
                       int length) const {
  XmlValuePtr value = find(path);
  if (!value) return false;

  std::string s = value->text();
  s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
  s.erase(s.find_last_not_of("=") + 1);

  int decodedSize = B64ToB256Bytes(s.size());
  if (decodedSize != length) {
    RLOG(ERROR) << "decoding bytes len " << s.size()
                << ", expecting output len " << length << ", got "
                << decodedSize;
    return false;
  }
  if (!B64StandardDecode(data, (unsigned char *)s.data(), s.size())) {
    RLOG(ERROR) << "B64 decode failure on \"" << s << "\"";
    return false;
  }

  return true;
}

bool XmlValue::read(const char *path, Interface *out) const {
  XmlValuePtr node = find(path);
  if (!node) return false;

  bool ok = node->read("name", &out->name()) &&
            node->read("major", &out->current()) &&
            node->read("minor", &out->revision());

  return ok;
}

std::string safeValueForNode(const tinyxml2::XMLElement *element) {
  std::string value;
  if (element == NULL) return value;

  const tinyxml2::XMLNode *child = element->FirstChild();
  if (child) {
    const tinyxml2::XMLText *childText = child->ToText();
    if (childText) value = childText->Value();
  }

  return value;
}

class XmlNode : virtual public XmlValue {
  const tinyxml2::XMLElement *element;

 public:
  XmlNode(const tinyxml2::XMLElement *element_)
      : XmlValue(safeValueForNode(element_)), element(element_) {}

  virtual ~XmlNode() {}

  virtual XmlValuePtr find(const char *name) const {
    if (name[0] == '@') {
      const char *value = element->Attribute(name + 1);
      if (value)
        return XmlValuePtr(new XmlValue(value));
      else
        return XmlValuePtr();
    } else {
      const tinyxml2::XMLElement *el = element->FirstChildElement(name);
      if (el)
        return XmlValuePtr(new XmlNode(el));
      else
        return XmlValuePtr();
    }
  }
};

struct XmlReader::XmlReaderData {
  std::shared_ptr<tinyxml2::XMLDocument> doc;
};

XmlReader::XmlReader() : pd(new XmlReaderData()) {}

XmlReader::~XmlReader() {}

bool XmlReader::load(const char *fileName) {
  pd->doc.reset(new tinyxml2::XMLDocument());

  std::ifstream in(fileName);
  if (!in) return false;

  std::ostringstream fileContent;
  fileContent << in.rdbuf();
  auto err = pd->doc->Parse(fileContent.str().c_str());
  return err == tinyxml2::XML_SUCCESS;
}

XmlValuePtr XmlReader::operator[](const char *name) const {
  tinyxml2::XMLNode *node = pd->doc->FirstChildElement(name);
  if (node == NULL) {
    RLOG(ERROR) << "Xml node " << name << " not found";
    return XmlValuePtr(new XmlValue());
  }

  tinyxml2::XMLElement *element = node->ToElement();
  if (element == NULL) {
    RLOG(ERROR) << "Xml node " << name << " not element";
    return XmlValuePtr(new XmlValue());
  }

  return XmlValuePtr(new XmlNode(element));
}

}  // namespace encfs
