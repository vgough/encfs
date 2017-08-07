#include "gtest/gtest.h"

#include "encfs/BlockNameIO.h"
#include "encfs/Cipher.h"
#include "encfs/CipherKey.h"
#include "encfs/DirNode.h"
#include "encfs/FSConfig.h"
#include "encfs/FileUtils.h"
#include "encfs/StreamNameIO.h"

using namespace encfs;
using namespace testing;
using std::string;

const int FSBlockSize = 256;
const char TEST_ROOTDIR[] = "/foo";

static void testNameCoding(DirNode &dirNode) {
  // encrypt a name
  const char *name[] = {
      "1234567",         "12345678",         "123456789",
      "123456789ABCDEF", "123456789ABCDEF0", "123456789ABCDEF01",
      "test-name",       "test-name2",       "test",
      "../test",         "/foo/bar/blah",    "test-name.21",
      "test-name.22",    "test-name.o",      "1.test",
      "2.test",          "a/b/c/d",          "a/c/d/e",
      "b/c/d/e",         "b/a/c/d",          NULL};

  const char **orig = name;
  while (*orig) {
    string encName = dirNode.relativeCipherPath(*orig);

    // decrypt name
    string decName = dirNode.plainPath(encName.c_str());

    ASSERT_EQ(decName, *orig);
    orig++;
  }
}

class CipherTest : public TestWithParam<Cipher::CipherAlgorithm> {
 protected:
  virtual void SetUp() {
    Cipher::CipherAlgorithm alg = GetParam();
    cipher = Cipher::New(alg.name, alg.keyLength.closest(256));
  }
  virtual void TearDown() {}
  std::shared_ptr<Cipher> cipher;
};

TEST_P(CipherTest, SaveRestoreKey) {
  auto key = cipher->newRandomKey();

  auto encodingKey = cipher->newRandomKey();
  int encodedKeySize = cipher->encodedKeySize();
  unsigned char keyBuf[encodedKeySize];

  cipher->writeKey(key, keyBuf, encodingKey);
  auto restored = cipher->readKey(keyBuf, encodingKey);
  EXPECT_TRUE(restored);
  EXPECT_TRUE(cipher->compareKey(key, restored));
}

TEST_P(CipherTest, NameStreamEncoding) {
  auto key = cipher->newRandomKey();

  FSConfigPtr fsCfg = FSConfigPtr(new FSConfig);
  fsCfg->cipher = cipher;
  fsCfg->key = key;
  fsCfg->config.reset(new EncFSConfig);
  fsCfg->config->blockSize = FSBlockSize;
  fsCfg->opts.reset(new EncFS_Opts);
  fsCfg->opts->idleTracking = false;
  fsCfg->config->uniqueIV = false;

  fsCfg->nameCoding.reset(
      new StreamNameIO(StreamNameIO::CurrentInterface(), cipher, key));

  {
    fsCfg->nameCoding->setChainedNameIV(true);
    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);
    testNameCoding(dirNode);
  }
  {
    fsCfg->nameCoding->setChainedNameIV(false);
    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);
    testNameCoding(dirNode);
  }
}

TEST_P(CipherTest, NameBlockEncoding) {
  auto key = cipher->newRandomKey();

  FSConfigPtr fsCfg = FSConfigPtr(new FSConfig);
  fsCfg->cipher = cipher;
  fsCfg->key = key;
  fsCfg->config.reset(new EncFSConfig);
  fsCfg->config->blockSize = FSBlockSize;
  fsCfg->opts.reset(new EncFS_Opts);
  fsCfg->opts->idleTracking = false;
  fsCfg->config->uniqueIV = false;
  fsCfg->nameCoding.reset(new BlockNameIO(
      BlockNameIO::CurrentInterface(), cipher, key, cipher->cipherBlockSize()));

  {
    fsCfg->nameCoding->setChainedNameIV(true);
    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);
    testNameCoding(dirNode);
  }
  {
    fsCfg->nameCoding->setChainedNameIV(false);
    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);
    testNameCoding(dirNode);
  }
}

TEST_P(CipherTest, NameBlockBase32Encoding) {
  auto key = cipher->newRandomKey();

  FSConfigPtr fsCfg = FSConfigPtr(new FSConfig);
  fsCfg->cipher = cipher;
  fsCfg->key = key;
  fsCfg->config.reset(new EncFSConfig);
  fsCfg->config->blockSize = FSBlockSize;
  fsCfg->opts.reset(new EncFS_Opts);
  fsCfg->opts->idleTracking = false;
  fsCfg->config->uniqueIV = false;
  fsCfg->nameCoding.reset(new BlockNameIO(BlockNameIO::CurrentInterface(),
                                          cipher, key,
                                          cipher->cipherBlockSize(), true));

  {
    fsCfg->nameCoding->setChainedNameIV(true);
    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);
    testNameCoding(dirNode);
  }

  {
    fsCfg->nameCoding->setChainedNameIV(false);
    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);
    testNameCoding(dirNode);
  }
}

TEST_P(CipherTest, ConfigLoadStore) {
  auto key = cipher->newRandomKey();
  CipherKey encodingKey = cipher->newRandomKey();
  int encodedKeySize = cipher->encodedKeySize();
  unsigned char keyBuf[encodedKeySize];

  cipher->writeKey(key, keyBuf, encodingKey);

  // store in config struct..
  EncFSConfig cfg;
  cfg.cipherIface = cipher->interface();
  cfg.keySize = 8 * cipher->keySize();
  cfg.blockSize = FSBlockSize;
  cfg.assignKeyData(keyBuf, encodedKeySize);

  // save config
  // Creation of a temporary file should be more platform independent. On
  // c++17 we could use std::filesystem.
  std::string name = "/tmp/encfstestXXXXXX";
  int tmpFd = mkstemp(&name[0]);
  EXPECT_GE(tmpFd, 0);
  // mkstemp opens the temporary file, but we only need its name -> close it
  EXPECT_EQ(close(tmpFd), 0);
  {
    auto ok = writeV6Config(name.c_str(), &cfg);
    EXPECT_TRUE(ok);
  }

  // read back in and check everything..
  EncFSConfig cfg2;
  {
    auto ok = readV6Config(name.c_str(), &cfg2, nullptr);
    EXPECT_TRUE(ok);
  }
  // delete the temporary file where we stored the config
  EXPECT_EQ(unlink(name.c_str()), 0);

  // check..
  EXPECT_TRUE(cfg.cipherIface.implements(cfg2.cipherIface));
  EXPECT_EQ(cfg.keySize, cfg2.keySize);
  EXPECT_EQ(cfg.blockSize, cfg2.blockSize);

  // try decoding key..

  CipherKey key2 = cipher->readKey(cfg2.getKeyData(), encodingKey);
  EXPECT_TRUE(key2);
  EXPECT_TRUE(cipher->compareKey(key, key2));
}

INSTANTIATE_TEST_CASE_P(CipherKey, CipherTest,
                        ValuesIn(Cipher::GetAlgorithmList()));
