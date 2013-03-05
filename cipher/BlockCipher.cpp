#include "cipher/BlockCipher.h"

// TODO: add ifdef when OpenSSL becomes optional.
#include "cipher/openssl.h"
#include "cipher/NullCiphers.h"

namespace encfs {

Registry<BlockCipher>& BlockCipher::GetRegistry()
{
  static Registry<BlockCipher> registry;
  static bool first = true;
  if (first)
  {
    OpenSSL::registerCiphers();
    NullCiphers::registerCiphers();
    first = false;
  }
  return registry;
}

BlockCipher::BlockCipher()
{
}

BlockCipher::~BlockCipher()
{
}

}  // namespace encfs

