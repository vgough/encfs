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

#ifndef _NameIO_incl_
#define _NameIO_incl_

#include <inttypes.h>
#include <list>
#include <memory>
#include <stdint.h>
#include <string.h>
#include <string>

#include "CipherKey.h"
#include "Interface.h"

namespace encfs {

class Cipher;

class NameIO {
 public:
  typedef std::shared_ptr<NameIO> (*Constructor)(
      const Interface &iface, const std::shared_ptr<Cipher> &cipher,
      const CipherKey &key);

  struct Algorithm {
    std::string name;
    std::string description;
    Interface iface;
  };

  typedef std::list<Algorithm> AlgorithmList;
  static AlgorithmList GetAlgorithmList(bool includeHidden = false);

  static std::shared_ptr<NameIO> New(const Interface &iface,
                                     const std::shared_ptr<Cipher> &cipher,
                                     const CipherKey &key);
  static std::shared_ptr<NameIO> New(const std::string &name,
                                     const std::shared_ptr<Cipher> &cipher,
                                     const CipherKey &key);

  static bool Register(const char *name, const char *description,
                       const Interface &iface, Constructor constructor,
                       bool hidden = false);

  NameIO();
  virtual ~NameIO();

  virtual Interface interface() const = 0;

  void setChainedNameIV(bool enable);
  bool getChainedNameIV() const;
  void setReverseEncryption(bool enable);
  bool getReverseEncryption() const;

  std::string encodePath(const char *plaintextPath) const;
  std::string decodePath(const char *encodedPath) const;

  std::string encodePath(const char *plaintextPath, uint64_t *iv) const;
  std::string decodePath(const char *encodedPath, uint64_t *iv) const;

  virtual int maxEncodedNameLen(int plaintextNameLen) const = 0;
  virtual int maxDecodedNameLen(int encodedNameLen) const = 0;

  std::string encodeName(const char *plaintextName, int length) const;
  std::string decodeName(const char *encodedName, int length) const;

 protected:
  virtual int encodeName(const char *plaintextName, int length,
                         char *encodedName, int bufferLength) const;
  virtual int decodeName(const char *encodedName, int length,
                         char *plaintextName, int bufferLength) const;

  virtual int encodeName(const char *plaintextName, int length, uint64_t *iv,
                         char *encodedName, int bufferLength) const = 0;
  virtual int decodeName(const char *encodedName, int length, uint64_t *iv,
                         char *plaintextName, int bufferLength) const = 0;

 private:
  std::string recodePath(const char *path, int (NameIO::*codingLen)(int) const,
                         int (NameIO::*codingFunc)(const char *, int,
                                                   uint64_t *, char *, int)
                             const,
                         uint64_t *iv) const;

  std::string _encodePath(const char *plaintextPath, uint64_t *iv) const;
  std::string _decodePath(const char *encodedPath, uint64_t *iv) const;
  std::string _encodeName(const char *plaintextName, int length) const;
  std::string _decodeName(const char *encodedName, int length) const;

  bool chainedNameIV;
  bool reverseEncryption;
};

/*
    Helper macros for creating temporary buffers with an optimization that
    below a given size (OptimizedSize) is allocated on the stack, and when a
    larger size is requested it is allocated on the heap.

    BUFFER_RESET should be called for the same name as BUFFER_INIT
*/
#define BUFFER_INIT(Name, OptimizedSize, Size)          \
  char Name##_Raw[OptimizedSize];                       \
  char *Name = Name##_Raw;                              \
  if (sizeof(Name##_Raw) < Size) Name = new char[Size]; \
  memset(Name, 0, Size);

#define BUFFER_INIT_S(Name, OptimizedSize, Size, BufSize) \
  char Name##_Raw[OptimizedSize];                         \
  BufSize = sizeof(Name##_Raw);                           \
  char *Name = Name##_Raw;                                \
  if (sizeof(Name##_Raw) < Size) {                        \
    Name = new char[Size];                                \
    BufSize = Size;                                       \
  }                                                       \
  memset(Name, 0, Size);

#define BUFFER_RESET(Name)    \
  do {                        \
    if (Name != Name##_Raw) { \
      delete[] Name;          \
      Name = Name##_Raw;      \
    }                         \
  } while (0);

}  // namespace encfs

#endif
