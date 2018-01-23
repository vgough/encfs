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
#include <fstream>    // for ifstream
#include <limits>
#include <memory>     // for shared_ptr
#include <sstream>    // for ostringstream

#include <tinyxml2.h>  // for XMLElement, XMLNode, XMLDocument (ptr only)

#include "Error.h"
#include "Interface.h"
#include "base64.h"

namespace encfs {

XmlValue::~XmlValue() = default;

XmlValuePtr XmlValue::operator[](const char *path) const { return find(path); }

XmlValuePtr XmlValue::find(const char *path) const {
  // Shouldn't get here.
  RLOG(ERROR) << "in XmlValue::find for path " << path;
  return XmlValuePtr();
}

bool XmlValue::read(const char *path, std::string *out) const {
  XmlValuePtr value = find(path);
  if (!value) {
    return false;
  }

  *out = value->text();
  return true;
}

bool XmlValue::read(const char *path, int *out) const {
  XmlValuePtr value = find(path);
  if (!value) {
    return false;
  }

  char * e;
  long lout = strtol(value->text().c_str(), &e, 10);
  if (*e != '\0') {
    return false;
  }
  if (lout < std::numeric_limits<int>::min() || lout > std::numeric_limits<int>::max()) {
    return false;
  }
  *out = (int)lout;
  return true;
}

bool XmlValue::read(const char *path, long *out) const {
  XmlValuePtr value = find(path);
  if (!value) {
    return false;
  }

  char * e;
  *out = strtol(value->text().c_str(), &e, 10);
  return (*e == '\0');
}

bool XmlValue::read(const char *path, double *out) const {
  XmlValuePtr value = find(path);
  if (!value) {
    return false;
  }

  char * e;
  *out = strtod(value->text().c_str(), &e);
  return (*e == '\0');
}

bool XmlValue::read(const char *path, bool *out) const {
  XmlValuePtr value = find(path);
  if (!value) {
    return false;
  }

  char * e;
  *out = (strtol(value->text().c_str(), &e, 10) != 0);
  return (*e == '\0');
}

bool XmlValue::readB64(const char *path, unsigned char *data,
                       int length) const {
  XmlValuePtr value = find(path);
  if (!value) {
    return false;
  }

  std::string s = value->text();
  s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
  s.erase(s.find_last_not_of('=') + 1);

  int decodedSize = B64ToB256Bytes(s.size());
  if (decodedSize != length) {
    RLOG(ERROR) << "decoding bytes len " << s.size()
                << ", expecting output len " << length << ", got "
                << decodedSize;
    return false;
  }
  if (!B64StandardDecode(data, (unsigned char *)s.data(), s.size())) {
    RLOG(ERROR) << R"(B64 decode failure on ")" << s << R"(")";
    return false;
  }

  return true;
}

bool XmlValue::read(const char *path, Interface *out) const {
  XmlValuePtr node = find(path);
  if (!node) {
    return false;
  }

  bool ok = node->read("name", &out->name()) &&
            node->read("major", &out->current()) &&
            node->read("minor", &out->revision());

  return ok;
}

std::string safeValueForNode(const tinyxml2::XMLElement *element) {
  std::string value;
  if (element == nullptr) {
    return value;
  }

  const tinyxml2::XMLNode *child = element->FirstChild();
  if (child != nullptr) {
    const tinyxml2::XMLText *childText = child->ToText();
    if (childText != nullptr) {
      value = childText->Value();
    }
  }

  return value;
}

class XmlNode : virtual public XmlValue {
  const tinyxml2::XMLElement *element;

 public:
  explicit XmlNode(const tinyxml2::XMLElement *element_)
      : XmlValue(safeValueForNode(element_)), element(element_) {}

  // destructor
  ~XmlNode() override = default;

  XmlNode(const XmlNode &src) = delete; // copy constructor
  XmlNode(XmlNode&& other) = delete; // move constructor
  XmlNode& operator=(const XmlNode& other) = delete; // copy assignment
  XmlNode& operator=(XmlNode&& other) = delete; // move assignment

  XmlValuePtr find(const char *name) const override {
    if (name[0] == '@') {
      const char *value = element->Attribute(name + 1);
      if (value != nullptr) {
        return std::make_shared<encfs::XmlValue>(value);
      }
      return XmlValuePtr();
    }
    const tinyxml2::XMLElement *el = element->FirstChildElement(name);
    if (el != nullptr) {
      return XmlValuePtr(new XmlNode(el));
    }
    return XmlValuePtr();
  }
};

struct XmlReader::XmlReaderData {
  std::shared_ptr<tinyxml2::XMLDocument> doc;
};

XmlReader::XmlReader() : pd(new XmlReaderData()) {}

XmlReader::~XmlReader() = default;

bool XmlReader::load(const char *fileName) {
  pd->doc.reset(new tinyxml2::XMLDocument());

  std::ifstream in(fileName);
  if (!in) {
    return false;
  }

  std::ostringstream fileContent;
  fileContent << in.rdbuf();
  auto err = pd->doc->Parse(fileContent.str().c_str());
  return err == tinyxml2::XML_SUCCESS;
}

XmlValuePtr XmlReader::operator[](const char *name) const {
  tinyxml2::XMLNode *node = pd->doc->FirstChildElement(name);
  if (node == nullptr) {
    RLOG(ERROR) << "Xml node " << name << " not found";
    return std::make_shared<encfs::XmlValue>();
  }

  tinyxml2::XMLElement *element = node->ToElement();
  if (element == nullptr) {
    RLOG(ERROR) << "Xml node " << name << " not element";
    return std::make_shared<encfs::XmlValue>();
  }

  return XmlValuePtr(new XmlNode(element));
}

}  // namespace encfs
