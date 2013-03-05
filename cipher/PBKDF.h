#ifndef ENCFS_PBKDF_H
#define ENCFS_PBKDF_H

#include <string>

#include "base/Registry.h"
#include "base/types.h"

namespace encfs {

// Password Based Key Derivation Function.
class PBKDF
{
 public:
  DECLARE_REGISTERABLE_TYPE(PBKDF);

  struct Properties {
    std::string mode;
    std::string library;

    std::string toString() const { return mode; }
  };

  PBKDF();
  virtual ~PBKDF();

  virtual bool makeKey(const char *password, int passwordLength,
                       const byte *salt, int saltLength,
                       int numIterations,
                       byte *outKey, int keyLength) const = 0;
};

}  // namespace encfs

#endif // ENCFS_PBKDF_H
