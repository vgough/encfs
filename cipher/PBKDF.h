#ifndef ENCFS_PBKDF_H
#define ENCFS_PBKDF_H

#include <string>

#include "base/Registry.h"
#include "base/types.h"
#include "cipher/CipherKey.h"

namespace encfs {

// Well-known algorithms.
static const char NAME_PBKDF2_HMAC_SHA1[] = "PBKDF2_HMAC_SHA1";
static const char NAME_PBKDF2_HMAC_SHA256[] = "PBKDF2_HMAC_SHA256";

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
                       int numIterations, CipherKey *outKey) = 0;

  // Create a new key with strong randomization.
  virtual CipherKey randomKey(int length) =0;

  // Randomize the output.  Pseudo randomization is allowed, so this may not be
  // used for keys or other critical values.
  virtual bool pseudoRandom(byte *out, int byteLen) =0;
};

}  // namespace encfs

#endif // ENCFS_PBKDF_H
