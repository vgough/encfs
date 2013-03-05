#include "cipher/BlockCipher.h"

#include "base/config.h"

#ifdef WITH_OPENSSL
#include "cipher/openssl.h"
#endif
#ifdef WITH_COMMON_CRYPTO
#include "cipher/CommonCrypto.h"
#endif

#include "cipher/NullCiphers.h"

namespace encfs {

Registry<BlockCipher>& BlockCipher::GetRegistry()
{
  static Registry<BlockCipher> registry;
  static bool first = true;
  if (first)
  {
#ifdef WITH_OPENSSL
    OpenSSL::registerCiphers();
#endif
#ifdef WITH_COMMON_CRYPTO
    CommonCrypto::registerCiphers();
#endif
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

