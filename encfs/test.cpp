/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 *
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <list>
#include <memory>
#include <sstream>
#include <string>
#include <time.h>
#include <unistd.h>

#include "BlockNameIO.h"
#include "Cipher.h"
#include "CipherKey.h"
#include "DirNode.h"
#include "Error.h"
#include "FSConfig.h"
#include "FileUtils.h"
#include "Interface.h"
#include "MemoryPool.h"
#include "NameIO.h"
#include "Range.h"
#include "StreamNameIO.h"
#include "internal/easylogging++.h"

#define NO_DES
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

using namespace std;
using namespace encfs;

const int FSBlockSize = 256;

static int checkErrorPropogation(const std::shared_ptr<Cipher> &cipher,
                                 int size, int byteToChange,
                                 const CipherKey &key) {
  MemBlock orig = MemoryPool::allocate(size);
  MemBlock data = MemoryPool::allocate(size);

  for (int i = 0; i < size; ++i) {
    unsigned char tmp = rand();
    orig.data[i] = tmp;
    data.data[i] = tmp;
  }

  if (size != FSBlockSize)
    cipher->streamEncode(data.data, size, 0, key);
  else
    cipher->blockEncode(data.data, size, 0, key);

  // intoduce an error in the encoded data, so we can check error propogation
  if (byteToChange >= 0 && byteToChange < size) {
    unsigned char previousValue = data.data[byteToChange];
    do {
      data.data[byteToChange] = rand();
    } while (data.data[byteToChange] == previousValue);
  }

  if (size != FSBlockSize)
    cipher->streamDecode(data.data, size, 0, key);
  else
    cipher->blockDecode(data.data, size, 0, key);

  int numByteErrors = 0;
  for (int i = 0; i < size; ++i) {
    if (data.data[i] != orig.data[i]) ++numByteErrors;
  }

  MemoryPool::release(data);
  MemoryPool::release(orig);

  return numByteErrors;
}

const char TEST_ROOTDIR[] = "/foo";

static bool testNameCoding(DirNode &dirNode, bool verbose) {
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
    if (verbose) cerr << "   coding name \"" << *orig << "\"";

    string encName = dirNode.relativeCipherPath(*orig);

    if (verbose) cerr << " -> \"" << encName.c_str() << "\"";

    // decrypt name
    string decName = dirNode.plainPath(encName.c_str());

    if (decName == *orig) {
      if (verbose) cerr << "   OK\n";
    } else {
      if (verbose) cerr << "   FAILED (got " << decName << ")\n";
      return false;
    }

    orig++;
  }

  return true;
}

bool runTests(const std::shared_ptr<Cipher> &cipher, bool verbose) {
  // create a random key
  if (verbose) {
    cerr << "Generating new key, output will be different on each run\n\n";
  }
  CipherKey key = cipher->newRandomKey();

  if (verbose) cerr << "Testing key save / restore :";
  {
    CipherKey encodingKey = cipher->newRandomKey();
    int encodedKeySize = cipher->encodedKeySize();
    unsigned char keyBuf[encodedKeySize];

    cipher->writeKey(key, keyBuf, encodingKey);
    CipherKey key2 = cipher->readKey(keyBuf, encodingKey);
    if (!key2) {
      if (verbose) cerr << "   FAILED (decode error)\n";
      return false;
    }

    if (cipher->compareKey(key, key2)) {
      if (verbose) cerr << "   OK\n";
    } else {
      if (verbose) cerr << "   FAILED\n";
      return false;
    }
  }

  if (verbose) cerr << "Testing Config interface load / store :";
  {
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
    //Creation of a temporary file should be more platform independent. On c++17 we could use std::filesystem.
    string name = "/tmp/encfstestXXXXXX";
    int tmpFd = mkstemp(&name[0]);
    rAssert(-1 != tmpFd);
    //mkstemp opens the temporary file, but we only need its name -> close it
    rAssert(0 == close(tmpFd));
    {
      auto ok = writeV6Config(name.c_str(), &cfg);
      rAssert(ok == true);
    }

    // read back in and check everything..
    EncFSConfig cfg2;
    {
      auto ok = readV6Config(name.c_str(), &cfg2, nullptr);
      rAssert(ok == true);
    }
    //delete the temporary file where we stored the config
    rAssert(0 == unlink(name.c_str()));
    
    // check..
    rAssert(cfg.cipherIface.implements(cfg2.cipherIface));
    rAssert(cfg.keySize == cfg2.keySize);
    rAssert(cfg.blockSize == cfg2.blockSize);

    // try decoding key..

    CipherKey key2 = cipher->readKey(cfg2.getKeyData(), encodingKey);
    if (!key2) {
      if (verbose) cerr << "   FAILED (decode error)\n";
      return false;
    }

    if (cipher->compareKey(key, key2)) {
      if (verbose) cerr << "   OK\n";
    } else {
      if (verbose) cerr << "   FAILED\n";
      return false;
    }
  }

  FSConfigPtr fsCfg = FSConfigPtr(new FSConfig);
  fsCfg->cipher = cipher;
  fsCfg->key = key;
  fsCfg->config.reset(new EncFSConfig);
  fsCfg->config->blockSize = FSBlockSize;

  if (verbose)
    cerr << "Testing name encode/decode (stream coding w/ IV chaining)\n";
  {
    fsCfg->opts.reset(new EncFS_Opts);
    fsCfg->opts->idleTracking = false;
    fsCfg->config->uniqueIV = false;

    fsCfg->nameCoding.reset(
        new StreamNameIO(StreamNameIO::CurrentInterface(), cipher, key));
    fsCfg->nameCoding->setChainedNameIV(true);

    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);

    if (!testNameCoding(dirNode, verbose)) return false;
  }

  if (verbose)
    cerr << "Testing name encode/decode (block coding w/ IV chaining)\n";
  {
    fsCfg->opts->idleTracking = false;
    fsCfg->config->uniqueIV = false;
    fsCfg->nameCoding.reset(new BlockNameIO(BlockNameIO::CurrentInterface(),
                                            cipher, key,
                                            cipher->cipherBlockSize()));
    fsCfg->nameCoding->setChainedNameIV(true);

    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);

    if (!testNameCoding(dirNode, verbose)) return false;
  }

  if (verbose)
    cerr
        << "Testing name encode/decode (block coding w/ IV chaining, base32)\n";
  {
    fsCfg->opts->idleTracking = false;
    fsCfg->config->uniqueIV = false;
    fsCfg->nameCoding.reset(new BlockNameIO(BlockNameIO::CurrentInterface(),
                                            cipher, key,
                                            cipher->cipherBlockSize(), true));
    fsCfg->nameCoding->setChainedNameIV(true);

    DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);

    if (!testNameCoding(dirNode, verbose)) return false;
  }

  if (!verbose) {
    {
      // test stream mode, this time without IV chaining
      fsCfg->nameCoding = std::shared_ptr<NameIO>(
          new StreamNameIO(StreamNameIO::CurrentInterface(), cipher, key));
      fsCfg->nameCoding->setChainedNameIV(false);

      DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);

      if (!testNameCoding(dirNode, verbose)) return false;
    }

    {
      // test block mode, this time without IV chaining
      fsCfg->nameCoding = std::shared_ptr<NameIO>(
          new BlockNameIO(BlockNameIO::CurrentInterface(), cipher, key,
                          cipher->cipherBlockSize()));
      fsCfg->nameCoding->setChainedNameIV(false);

      DirNode dirNode(NULL, TEST_ROOTDIR, fsCfg);

      if (!testNameCoding(dirNode, verbose)) return false;
    }
  }

  if (verbose) cerr << "Testing block encode/decode on full block -  ";
  {
    int numErrors = checkErrorPropogation(cipher, FSBlockSize, -1, key);
    if (numErrors) {
      if (verbose) cerr << " FAILED!\n";
      return false;
    } else {
      if (verbose) cerr << " OK\n";
    }
  }
  if (verbose) cerr << "Testing block encode/decode on partial block -  ";
  {
    int numErrors = checkErrorPropogation(cipher, FSBlockSize - 1, -1, key);
    if (numErrors) {
      if (verbose) cerr << " FAILED!\n";
      return false;
    } else {
      if (verbose) cerr << " OK\n";
    }
  }

  if (verbose) cerr << "Checking error propogation in partial block:\n";
  {
    int minChanges = FSBlockSize - 1;
    int maxChanges = 0;
    int minAt = 0;
    int maxAt = 0;
    for (int i = 0; i < FSBlockSize - 1; ++i) {
      int numErrors = checkErrorPropogation(cipher, FSBlockSize - 1, i, key);

      if (numErrors < minChanges) {
        minChanges = numErrors;
        minAt = i;
      }
      if (numErrors > maxChanges) {
        maxChanges = numErrors;
        maxAt = i;
      }
    }

    if (verbose) {
      cerr << "modification of 1 byte affected between " << minChanges
           << " and " << maxChanges << " decoded bytes\n";
      cerr << "minimum change at byte " << minAt << " and maximum at byte "
           << maxAt << "\n";
    }
  }
  if (verbose) cerr << "Checking error propogation on full block:\n";
  {
    int minChanges = FSBlockSize;
    int maxChanges = 0;
    int minAt = 0;
    int maxAt = 0;
    for (int i = 0; i < FSBlockSize; ++i) {
      int numErrors = checkErrorPropogation(cipher, FSBlockSize, i, key);

      if (numErrors < minChanges) {
        minChanges = numErrors;
        minAt = i;
      }
      if (numErrors > maxChanges) {
        maxChanges = numErrors;
        maxAt = i;
      }
    }

    if (verbose) {
      cerr << "modification of 1 byte affected between " << minChanges
           << " and " << maxChanges << " decoded bytes\n";
      cerr << "minimum change at byte " << minAt << " and maximum at byte "
           << maxAt << "\n";
    }
  }

  return true;
}

static bool testCipherSize(const string &name, int keySize, int blockSize,
                           bool verbose) {
  cerr << name << ", key length " << keySize << ", block size " << blockSize
       << ":  ";

  std::shared_ptr<Cipher> cipher = Cipher::New(name, keySize);
  if (!cipher) {
    cerr << "FAILED TO CREATE\n";
    return false;
  } else {
    try {
      if (runTests(cipher, verbose)) {
        cerr << "OK\n";
      } else {
        cerr << "FAILED\n";
        return false;
      }
    } catch (encfs::Error &er) {
      cerr << "Error: " << er.what() << "\n";
      return false;
    }
  }
  return true;
}

int main(int argc, char *argv[]) {
  START_EASYLOGGINGPP(argc, argv);
  encfs::initLogging();

  SSL_load_error_strings();
  SSL_library_init();

#ifndef OPENSSL_NO_ENGINE
  ENGINE_load_builtin_engines();
  ENGINE_register_all_ciphers();
  ENGINE_register_all_digests();
  ENGINE_register_all_RAND();
#endif

  srand(time(0));

  // get a list of the available algorithms
  std::list<Cipher::CipherAlgorithm> algorithms = Cipher::GetAlgorithmList();
  std::list<Cipher::CipherAlgorithm>::const_iterator it;
  cerr << "Supported Crypto interfaces:\n";
  for (it = algorithms.begin(); it != algorithms.end(); ++it) {
    cerr << it->name << " ( " << it->iface.name() << " " << it->iface.current()
         << ":" << it->iface.revision() << ":" << it->iface.age()
         << " ) : " << it->description << "\n";
    cerr << " - key length " << it->keyLength.min() << " to "
         << it->keyLength.max() << " , block size " << it->blockSize.min()
         << " to " << it->blockSize.max() << "\n";
  }
  cerr << "\n";

  cerr << "Testing interfaces\n";
  for (it = algorithms.begin(); it != algorithms.end(); ++it) {
    int blockSize = it->blockSize.closest(256);
    for (int keySize = it->keyLength.min(); keySize <= it->keyLength.max();
         keySize += it->keyLength.inc()) {
      if (!testCipherSize(it->name, keySize, blockSize, false)) {
        // Run again in verbose mode, then exit with error.
        if (testCipherSize(it->name, keySize, blockSize, true)) {
          cerr << "Inconsistent test results!\n";
        }
        return 1;
      }
    }
  }

  // run one test with verbose output too..
  std::shared_ptr<Cipher> cipher = Cipher::New("AES", 192);
  if (!cipher) {
    cerr << "\nNo AES cipher found, skipping verbose test.\n";
  } else {
    cerr << "\nVerbose output for " << cipher->interface().name()
         << " test, key length " << cipher->keySize() * 8 << ", block size "
         << FSBlockSize << ":\n";

    runTests(cipher, true);
  }

  MemoryPool::destroyAll();

  return 0;
}
