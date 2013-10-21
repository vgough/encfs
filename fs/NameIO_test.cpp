#include <gtest/gtest.h>
#include <string>

#include "cipher/CipherV1.h"

#include "fs/BlockNameIO.h"
#include "fs/NameIO.h"
#include "fs/NullNameIO.h"
#include "fs/StreamNameIO.h"
#include "fs/testing.h"

namespace {

using namespace encfs;
using std::string;

string TEST_PATHS[] = {"a/b/c/d/e",      //
                       "/a/b",           //
                       "/a",             //
                       "/",              //
                       "../../foo/bar",  //
                       "./.encfs",       //
                       "."};

TEST(NameIOTest, NameIO) {
  NameIO::AlgorithmList algorithms = NameIO::GetAlgorithmList(true);
  // Test all NameIO algorithms.
  for (auto algorithm : algorithms) {
    shared_ptr<CipherV1> cipher = CipherV1::New("AES", 256);
    CipherKey key = cipher->newRandomKey();
    cipher->setKey(key);

    // Test all supported versions.
    for (unsigned int version = algorithm.iface.major() - algorithm.iface.age();
         version <= algorithm.iface.major(); ++version) {
      Interface iface = makeInterface(algorithm.iface.name(), version, 0, 0);
      SCOPED_TRACE(testing::Message() << "Testing " << iface.DebugString());

      auto io = NameIO::New(iface, cipher);

      // Check round-trip of test paths.
      for (string path : TEST_PATHS) {
        string encoded = io->encodePath(path);
        string decoded = io->decodePath(encoded);
        ASSERT_EQ(path, decoded);
      }

      // Try encoding names of various lengths.
      for (int len = 1; len < 40; ++len) {
        string name(len, 'A');
        string encoded = io->encodeName(name);
        string decoded = io->decodeName(encoded);
        ASSERT_EQ(name, decoded);
      }
    }
  }
}

}  // namespace
