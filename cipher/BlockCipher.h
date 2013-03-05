#ifndef BLOCKCIPHER_H
#define BLOCKCIPHER_H

#include "base/Interface.h"
#include "base/Range.h"
#include "base/Registry.h"
#include "base/shared_ptr.h"
#include "base/types.h"
#include "cipher/StreamCipher.h"

namespace encfs {

static const char NAME_AES_CBC[] = "AES/CBC";
static const char NAME_BLOWFISH_CBC[] = "Blowfish/CBC";

// BlockCipher is a StreamCipher with a block size.
// Encryption and decryption must be in multiples of the block size.
class BlockCipher : public StreamCipher
{
 public:
  DECLARE_REGISTERABLE_TYPE(BlockCipher);

  BlockCipher();
  virtual ~BlockCipher();

  // Not valid until a key has been set, as they key size may determine the
  // block size.
  virtual int blockSize() const =0;
};

}  // namespace encfs

#endif // BLOCKCIPHER_H
