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

#include "base/config.h"
#include "base/Error.h"
#include "fs/NameIO.h"

#include <glog/logging.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <vector>

// for static build.  Need to reference the modules which are registered at
// run-time, to ensure that the linker doesn't optimize them away.
#include "fs/BlockNameIO.h"
#include "fs/StreamNameIO.h"
#include "fs/NullNameIO.h"

using std::list;
using std::make_pair;
using std::multimap;
using std::string;
using std::vector;

namespace encfs {

#define REF_MODULE(TYPE)                                              \
  do {                                                                \
    CHECK(TYPE::Enabled()) << "referenceModule: should never happen"; \
  } while (0)

static void AddSymbolReferences() {
  REF_MODULE(BlockNameIO);
  REF_MODULE(StreamNameIO);
  REF_MODULE(NullNameIO);
}

struct NameIOAlg {
  bool hidden;
  NameIO::Constructor constructor;
  string description;
  Interface iface;
  bool needsStreamMode;
};

typedef multimap<string, NameIOAlg> NameIOMap_t;
static NameIOMap_t *gNameIOMap = nullptr;

list<NameIO::Algorithm> NameIO::GetAlgorithmList(bool includeHidden) {
  AddSymbolReferences();

  list<Algorithm> result;
  if (gNameIOMap) {
    NameIOMap_t::const_iterator it;
    NameIOMap_t::const_iterator end = gNameIOMap->end();
    for (it = gNameIOMap->begin(); it != end; ++it) {
      if (includeHidden || !it->second.hidden) {
        Algorithm tmp;
        tmp.name = it->first;
        tmp.description = it->second.description;
        tmp.iface = it->second.iface;
        tmp.needsStreamMode = it->second.needsStreamMode;

        result.push_back(tmp);
      }
    }
  }

  return result;
}

bool NameIO::Register(const char *name, const char *description,
                      const Interface &iface, Constructor constructor,
                      bool needsStreamMode, bool hidden) {
  if (!gNameIOMap) gNameIOMap = new NameIOMap_t;

  NameIOAlg alg;
  alg.hidden = hidden;
  alg.constructor = constructor;
  alg.description = description;
  alg.iface = iface;
  alg.needsStreamMode = needsStreamMode;

  gNameIOMap->insert(make_pair(string(name), alg));
  return true;
}

shared_ptr<NameIO> NameIO::New(const string &name,
                               const shared_ptr<CipherV1> &cipher) {
  shared_ptr<NameIO> result;
  if (gNameIOMap) {
    NameIOMap_t::const_iterator it = gNameIOMap->find(name);
    if (it != gNameIOMap->end()) {
      Constructor fn = it->second.constructor;
      result = (*fn)(it->second.iface, cipher);
    }
  }
  return result;
}

shared_ptr<NameIO> NameIO::New(const Interface &iface,
                               const shared_ptr<CipherV1> &cipher) {
  shared_ptr<NameIO> result;
  if (gNameIOMap) {
    NameIOMap_t::const_iterator it;
    NameIOMap_t::const_iterator end = gNameIOMap->end();
    for (it = gNameIOMap->begin(); it != end; ++it) {
      if (implements(it->second.iface, iface)) {
        Constructor fn = it->second.constructor;
        result = (*fn)(iface, cipher);
        break;
      }
    }
  }
  return result;
}

NameIO::NameIO() : chainedNameIV(false), reverseEncryption(false) {}

NameIO::~NameIO() {}

void NameIO::setChainedNameIV(bool enable) { chainedNameIV = enable; }

bool NameIO::getChainedNameIV() const { return chainedNameIV; }

void NameIO::setReverseEncryption(bool enable) { reverseEncryption = enable; }

bool NameIO::getReverseEncryption() const { return reverseEncryption; }

string NameIO::recodePath(const string &path, int (NameIO::*_length)(int) const,
                          string (NameIO::*_code)(const string &,
                                                  uint64_t *) const,
                          uint64_t *iv) const {
  string output;

  for (auto it = path.begin(); it != path.end();) {
    bool isDotFile = (*it == '.');
    auto next = std::find(it, path.end(), '/');
    int len = std::distance(it, next);

    if (*it == '/') {
      // don't start the string with '/'
      output += output.empty() ? '+' : '/';
      len = 1;
    } else if (*it == '+' && output.empty()) {
      output += '/';
      len = 1;
    } else if (isDotFile && (len <= 2) && (it[len - 1] == '.')) {
        output.append(len, '.');  // append [len] copies of '.'
    } else {
      int approxLen = (this->*_length)(len);
      if (approxLen <= 0) throw Error("Filename too small to decode");

      // code the name
      string input(it, it + len);
      string coded = (this->*_code)(input, iv);

      // append result to string
      output.append(coded);
    }

    it += len;
  }

  return output;
}

string NameIO::encodePath(const string &plaintextPath) const {
  uint64_t iv = 0;
  return encodePath(plaintextPath, &iv);
}

string NameIO::decodePath(const string &cipherPath) const {
  uint64_t iv = 0;
  return decodePath(cipherPath, &iv);
}

string NameIO::_encodePath(const string &plaintextPath, uint64_t *iv) const {
  // if chaining is not enabled, then the iv pointer is not used..
  if (!chainedNameIV) iv = nullptr;
  return recodePath(plaintextPath, &NameIO::maxEncodedNameLen,
                    &NameIO::encodeName, iv);
}

string NameIO::_decodePath(const string &cipherPath, uint64_t *iv) const {
  // if chaining is not enabled, then the iv pointer is not used..
  if (!chainedNameIV) iv = nullptr;
  return recodePath(cipherPath, &NameIO::maxDecodedNameLen, &NameIO::decodeName,
                    iv);
}

string NameIO::encodePath(const string &path, uint64_t *iv) const {
  return getReverseEncryption() ? _decodePath(path, iv) : _encodePath(path, iv);
}

string NameIO::decodePath(const string &path, uint64_t *iv) const {
  return getReverseEncryption() ? _encodePath(path, iv) : _decodePath(path, iv);
}

string NameIO::encodeName(const string &name) const {
  return getReverseEncryption() ? decodeName(name, nullptr)
                                : encodeName(name, nullptr);
}

string NameIO::decodeName(const string &name) const {
  return getReverseEncryption() ? encodeName(name, nullptr)
                                : decodeName(name, nullptr);
}

}  // namespace encfs
