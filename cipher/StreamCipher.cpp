#include "cipher/StreamCipher.h"

namespace encfs {

Registry<StreamCipher>& StreamCipher::GetRegistry()
{
  static Registry<StreamCipher> registry;
  return registry;
}

StreamCipher::StreamCipher()
{
}

StreamCipher::~StreamCipher()
{
}

}  // namespace encfs

