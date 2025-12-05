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

#include "NullCipher.h"

#include <cstring>
#include <memory>

#include "Cipher.h"
#include "Interface.h"
#include "Range.h"

using namespace std;

namespace encfs {

static Interface NullInterface("nullCipher", 1, 0, 0);
static Range NullKeyRange(0);
static Range NullBlockRange(1, 4096, 1);

static std::shared_ptr<Cipher> NewNullCipher(const Interface &iface,
                                             int keyLen) {
  (void)keyLen;
  return std::shared_ptr<Cipher>(new NullCipher(iface));
}

const bool HiddenCipher = true;

static bool NullCipher_registered = Cipher::Register(
    "Null", "Non encrypting cipher.  For testing only!", NullInterface,
    NullKeyRange, NullBlockRange, NewNullCipher, HiddenCipher);

class NullKey : public AbstractCipherKey {
 public:
  NullKey() = default;

  // destructor
  ~NullKey() override = default;

  NullKey(const NullKey &src) = delete; // copy constructor
  NullKey(NullKey&& other) = delete; // move constructor
  NullKey& operator=(const NullKey& other) = delete; // copy assignment
  NullKey& operator=(NullKey&& other) = delete; // move assignment
};

class NullDestructor {
 public:
  NullDestructor() = default;

  // destructor
  ~NullDestructor() = default;

  // copy contructor
  NullDestructor(const NullDestructor &) = default;

  // move constructor
  NullDestructor(NullDestructor &&) = default;

  NullDestructor &operator=(const NullDestructor &) = delete; // copy assignment
  NullDestructor& operator=(NullDestructor&& other) = delete; // move assignment

  void operator()(NullKey *&) {}
};
std::shared_ptr<AbstractCipherKey> gNullKey(new NullKey(), NullDestructor());

NullCipher::NullCipher(const Interface &iface_) { this->iface = iface_; }

NullCipher::~NullCipher() = default;

Interface NullCipher::interface() const { return iface; }

CipherKey NullCipher::newKey(const char *, int, int &, long,
                             const unsigned char *, int) {
  return gNullKey;
}

CipherKey NullCipher::newKey(const char *, int) { return gNullKey; }

CipherKey NullCipher::newRandomKey() { return gNullKey; }

bool NullCipher::randomize(unsigned char *buf, int len, bool) const {
  memset(buf, 0, len);
  return true;
}

uint64_t NullCipher::MAC_64(const unsigned char *, int, const CipherKey &,
                            uint64_t *) const {
  return 0;
}

CipherKey NullCipher::readKey(const unsigned char *, const CipherKey &, bool) {
  return gNullKey;
}

void NullCipher::writeKey(const CipherKey &, unsigned char *,
                          const CipherKey &) {}

bool NullCipher::compareKey(const CipherKey &A_, const CipherKey &B_) const {
  std::shared_ptr<NullKey> A = dynamic_pointer_cast<NullKey>(A_);
  std::shared_ptr<NullKey> B = dynamic_pointer_cast<NullKey>(B_);
  return A.get() == B.get();
}

int NullCipher::encodedKeySize() const { return 0; }

int NullCipher::keySize() const { return 0; }

int NullCipher::cipherBlockSize() const { return 1; }

bool NullCipher::streamEncode(unsigned char *src, int len, uint64_t iv64,
                              const CipherKey &key) const {
  (void)src;
  (void)len;
  (void)iv64;
  (void)key;
  return true;
}

bool NullCipher::streamDecode(unsigned char *src, int len, uint64_t iv64,
                              const CipherKey &key) const {
  (void)src;
  (void)len;
  (void)iv64;
  (void)key;
  return true;
}

bool NullCipher::blockEncode(unsigned char *, int, uint64_t,
                             const CipherKey &) const {
  return true;
}

bool NullCipher::blockDecode(unsigned char *, int, uint64_t,
                             const CipherKey &) const {
  return true;
}

bool NullCipher::Enabled() { return true; }

}  // namespace encfs
