#ifndef ENCFS_MAC_H
#define ENCFS_MAC_H

#include <string>

#include "base/Registry.h"
#include "base/types.h"
#include "cipher/CipherKey.h"

namespace encfs {

static const char NAME_SHA1_HMAC[] = "SHA-1/HMAC";

// MAC provides keyed MessageAuthenticationCode algorithms, eg HMAC.
class MAC
{
 public:
  DECLARE_REGISTERABLE_TYPE(MAC);

  struct Properties {
    int blockSize;      // Block length of hash function.
    std::string hashFunction;
    std::string mode;
    std::string library;

    std::string toString() const {
      return hashFunction + "/" + mode;
    }
  };

  MAC();
  virtual ~MAC();

  virtual int outputSize() const =0;

  virtual bool setKey(const CipherKey &key) =0;

  virtual void reset() =0;
  virtual bool update(const byte *in, int length) =0;
  virtual bool write(byte *out) =0;
};

}  // namespace encfs

#endif // ENCFS_MAC_H
