#ifndef ENCFS_MAC_H
#define ENCFS_MAC_H

#include <string>

#include "base/Registry.h"
#include "base/types.h"

namespace encfs {

// MessageAuthenticationCode provides keyed MAC algorithms, eg HMAC.
class MessageAuthenticationCode
{
 public:
  DECLARE_REGISTERABLE_TYPE(MessageAuthenticationCode);

  struct Properties {
    int blockSize;      // Block length of hash function.
    std::string hashFunction;
    std::string mode;
    std::string library;

    std::string toString() const {
      return hashFunction + "/" + mode;
    }
  };

  MessageAuthenticationCode();
  virtual ~MessageAuthenticationCode();

  virtual int outputSize() const =0;

  virtual bool setKey(const byte *key, int keyLength) =0;
  virtual bool randomKey(int keyLength) =0;

  virtual void reset() =0;
  virtual bool update(const byte *in, int length) =0;
  virtual bool write(byte *out) =0;
};

}  // namespace encfs

#endif // ENCFS_MAC_H
