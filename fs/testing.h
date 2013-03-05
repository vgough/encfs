#ifndef _TESTING_incl_
#define _TESTING_incl_

#include <string>

#include "cipher/CipherV1.h"
#include "fs/FileUtils.h"
#include "fs/FSConfig.h"

namespace encfs {

class FileIO;

FSConfigPtr makeConfig(const shared_ptr<CipherV1>& cipher, int blockSize);

void runWithCipher(const std::string& cipherName, int blockSize,
                   void (*func)(FSConfigPtr& config));
void runWithAllCiphers(void (*func)(FSConfigPtr& config));

void comparisonTest(FSConfigPtr& cfg, FileIO* a, FileIO* b);

void compare(FileIO* a, FileIO* b, int offset, int len);

}  // namespace encfs

#endif

