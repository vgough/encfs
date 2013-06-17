
#include <list>

#include <gtest/gtest.h>

#include "base/config.h"
#include "base/shared_ptr.h"
#include "cipher/CipherV1.h"
#include "cipher/MemoryPool.h"
#include "cipher/testing.h"

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

using namespace encfs;
using std::list;
using std::string;

namespace {

class CipherKeyTest : public testing::Test {
 protected:
  virtual void SetUp() {
    CipherV1::init(false);
  }
};

TEST_F(CipherKeyTest, ReadWrite) {
  for (auto alg : CipherV1::GetAlgorithmList()) {
    auto cipher = CipherV1::New(alg.iface);
    ASSERT_FALSE(!cipher);

    CipherKey masterKey = cipher->newRandomKey();
    CipherKey volumeKey = cipher->newRandomKey();

    int encodedSize = cipher->encodedKeySize();
    unsigned char *keyBuf = new unsigned char[encodedSize];

    cipher->setKey(masterKey);
    cipher->writeKey(volumeKey, keyBuf);

    CipherKey readKey = cipher->readKey(keyBuf, true);
    ASSERT_TRUE(readKey.valid());
    ASSERT_TRUE(readKey == volumeKey);
    ASSERT_FALSE(readKey == masterKey);

    delete[] keyBuf;
  }
}


} //  namespace
