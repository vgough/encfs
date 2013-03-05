#ifndef BLOCKCIPHER_H
#define BLOCKCIPHER_H

#include "base/Interface.h"
#include "base/Range.h"
#include "base/Registry.h"
#include "base/shared_ptr.h"
#include "base/types.h"
#include "cipher/StreamCipher.h"

namespace encfs {

// BlockCipher is a StreamCipher with a block size.
// Encryption and decryption must be in multiples of the block size.
class BlockCipher : public StreamCipher
{
 public:
  static Registry<BlockCipher>& GetRegistry();

  BlockCipher();
  virtual ~BlockCipher();

  virtual int blockSize() const =0;
};

}  // namespace encfs

#endif // BLOCKCIPHER_H
