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

#include "fs/encfs.h"

#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <sstream>

#include "base/config.h"
#include "base/Interface.h"
#include "base/Error.h"
#include "cipher/CipherV1.h"
#include "cipher/MemoryPool.h"
#include "fs/DirNode.h"
#include "fs/FileUtils.h"
#include "fs/StreamNameIO.h"
#include "fs/BlockNameIO.h"
#include "fs/NullNameIO.h"

#include <glog/logging.h>

#ifdef HAVE_SSL
#define NO_DES
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#endif

#include <google/protobuf/text_format.h>

#ifdef HAVE_TR1_UNORDERED_SET
#include <tr1/unordered_set>
using std::tr1::unordered_set;
#else
#include <unordered_set>
using std::unordered_set;
#endif

using std::cerr;
using std::string;
using namespace encfs;

namespace encfs {

const int FSBlockSize = 256;

static
int checkErrorPropogation( const shared_ptr<CipherV1> &cipher,
    int size, int byteToChange )
{
  MemBlock orig;
  orig.allocate(size);
  MemBlock data;
  data.allocate(size);

  for(int i=0; i<size; ++i)
  {
    unsigned char tmp = rand();
    orig.data[i] = tmp;
    data.data[i] = tmp;
  }

  if(size != FSBlockSize)
    cipher->streamEncode( data.data, size, 0 );
  else
    cipher->blockEncode( data.data, size, 0 );

  // intoduce an error in the encoded data, so we can check error propogation
  if(byteToChange >= 0 && byteToChange < size)
  {
    unsigned char previousValue = data.data[byteToChange];
    do
    {
      data.data[byteToChange] = rand();
    } while(data.data[byteToChange] == previousValue);
  }

  if(size != FSBlockSize)
    cipher->streamDecode( data.data, size, 0 );
  else
    cipher->blockDecode( data.data, size, 0 );

  int numByteErrors = 0;
  for(int i=0; i<size; ++i)
  {
    if( data.data[i] != orig.data[i] )
      ++numByteErrors;
  }

  return numByteErrors;
}

const char TEST_ROOTDIR[] = "/foo";

static
bool testNameCoding( DirNode &dirNode, bool verbose, 
                     bool collisionTest = false )
{
  // encrypt a name
  const char *name[] = {
    "1234567",
    "12345678",
    "123456789",
    "123456789ABCDEF",
    "123456789ABCDEF0",
    "123456789ABCDEF01",
    "test-name",
    "test-name2",
    "test",
    "../test",
    "/foo/bar/blah",
    "test-name.21",
    "test-name.22",
    "test-name.o",
    "1.test",
    "2.test",
    "a/b/c/d",
    "a/c/d/e",
    "b/c/d/e",
    "b/a/c/d",
    NULL 
  };

  const char **orig = name;
  while(*orig)
  {
    if(verbose)
      cerr << "   coding name \"" << *orig << "\"";

    string encName = dirNode.relativeCipherPath( *orig );

    if(verbose)
      cerr << " -> \"" << encName.c_str() << "\"";

    // decrypt name
    string decName = dirNode.plainPath( encName.c_str() );

    if(decName == *orig)
    {
      if(verbose)
        cerr << "   OK\n";
    } else
    {
      if(verbose)
        cerr << "   FAILED (got " << decName << ")\n";
      return false;
    }

    orig++;
  }

  if (collisionTest)
  {
    if (verbose)
      cerr << "Checking for name collections, this will take a while..\n";
    // check for collision rate
    char buf[64];
    unordered_set<string> encryptedNames;
    for (long i=0; i < 10000000; i++) 
    {
      snprintf(buf, sizeof(buf), "%li", i);
      string encName = dirNode.relativeCipherPath( buf );
      // simulate a case-insisitive filesystem..
      std::transform(encName.begin(), encName.end(), encName.begin(),
          ::toupper);

      if (encryptedNames.insert(encName).second == false) {
        cerr << "collision detected after " << i << " iterations";
        break;
      }
    }
    cerr << "NO collisions detected";
  }

  return true;
}

bool runTests(const shared_ptr<CipherV1> &cipher, bool verbose)
{
  // create a random key
  if(verbose)
    cerr << "Generating new key, output will be different on each run\n\n";
  CipherKey key = cipher->newRandomKey();

  if(verbose)
    cerr << "Testing key save / restore :";
  {
    CipherKey encodingKey = cipher->newRandomKey();
    int encodedKeySize = cipher->encodedKeySize();
    unsigned char *keyBuf = new unsigned char [ encodedKeySize ];

    cipher->setKey(encodingKey);
    cipher->writeKey( key, keyBuf );
    CipherKey key2 = cipher->readKey( keyBuf, true );
    if(!key2.valid())
    {
      if(verbose)
        cerr << "   FAILED (decode error)\n";
      return false;
    }

    if(key == key2)
    {
      if(verbose)
        cerr << "   OK\n";
    } else
    {
      if(verbose)
        cerr << "   FAILED\n";
      return false;
    }
  }

  if(verbose)
    cerr << "Testing Config interface load / store :";
  {
    CipherKey encodingKey = cipher->newRandomKey();
    int encodedKeySize = cipher->encodedKeySize();
    unsigned char *keyBuf = new unsigned char [ encodedKeySize ];

    cipher->setKey(encodingKey);
    cipher->writeKey( key, keyBuf );

    // store in config struct..
    EncfsConfig cfg;
    cfg.mutable_cipher()->MergeFrom(cipher->interface());
    EncryptedKey *encryptedKey = cfg.mutable_key();
    encryptedKey->set_size(8 * cipher->keySize());
    encryptedKey->set_ciphertext( keyBuf, encodedKeySize );
    cfg.set_block_size(FSBlockSize);

    // save config
    string data;
    google::protobuf::TextFormat::PrintToString(cfg, &data);

    // read back in and check everything..
    EncfsConfig cfg2;
    google::protobuf::TextFormat::ParseFromString(data, &cfg2);

    // check..
    rAssert( implements(cfg.cipher(),cfg2.cipher()) );
    rAssert( cfg.key().size() == cfg2.key().size() );
    rAssert( cfg.block_size() == cfg2.block_size() );

    // try decoding key..
    CipherKey key2 = cipher->readKey( (unsigned char *)cfg2.key().ciphertext().data(), true );
    if(!key2.valid())
    {
      if(verbose)
        cerr << "   FAILED (decode error)\n";
      return false;
    }

    if(key == key2)
    {
      if(verbose)
        cerr << "   OK\n";
    } else
    {
      if(verbose)
        cerr << "   FAILED\n";
      return false;
    }
  }

  FSConfigPtr fsCfg = FSConfigPtr(new FSConfig);
  fsCfg->cipher = cipher;
  fsCfg->key = key;
  fsCfg->config.reset(new EncfsConfig);
  fsCfg->config->set_block_size(FSBlockSize);
  fsCfg->opts.reset(new EncFS_Opts);

  cipher->setKey(key);
  if(verbose)
    cerr << "Testing name encode/decode (stream coding w/ IV chaining)\n";
  {
    fsCfg->opts->idleTracking = false;
    fsCfg->config->set_unique_iv(false);

    fsCfg->nameCoding.reset( new StreamNameIO(
          StreamNameIO::CurrentInterface(), cipher) );
    fsCfg->nameCoding->setChainedNameIV( true );

    DirNode dirNode( NULL, TEST_ROOTDIR, fsCfg );

    if(!testNameCoding( dirNode, verbose ))
      return false;
  }

  if(verbose)
    cerr << "Testing name encode/decode (block coding w/ IV chaining)\n";
  {
    fsCfg->opts->idleTracking = false;
    fsCfg->config->set_unique_iv(false);
    fsCfg->nameCoding.reset( new BlockNameIO(
          BlockNameIO::CurrentInterface(), cipher) );
    fsCfg->nameCoding->setChainedNameIV( true );

    DirNode dirNode( NULL, TEST_ROOTDIR, fsCfg );

    if(!testNameCoding( dirNode, verbose ))
      return false;
  }

  if(verbose)
    cerr << "Testing name encode/decode (block coding w/ IV chaining, base32)\n";
  {
    fsCfg->opts->idleTracking = false;
    fsCfg->config->set_unique_iv(false);
    fsCfg->nameCoding.reset( new BlockNameIO(
          BlockNameIO::CurrentInterface(), cipher) );
    fsCfg->nameCoding->setChainedNameIV( true );

    DirNode dirNode( NULL, TEST_ROOTDIR, fsCfg );

    if(!testNameCoding( dirNode, verbose ))
      return false;
  }

  if(!verbose)
  {
    {
      // test stream mode, this time without IV chaining
      fsCfg->nameCoding =
        shared_ptr<NameIO>( new StreamNameIO( 
              StreamNameIO::CurrentInterface(), cipher) );
      fsCfg->nameCoding->setChainedNameIV( false );

      DirNode dirNode( NULL, TEST_ROOTDIR, fsCfg );

      if(!testNameCoding( dirNode, verbose ))
        return false;
    }

    {
      // test block mode, this time without IV chaining
      fsCfg->nameCoding = shared_ptr<NameIO>( new BlockNameIO(
            BlockNameIO::CurrentInterface(), cipher) );
      fsCfg->nameCoding->setChainedNameIV( false );

      DirNode dirNode( NULL, TEST_ROOTDIR, fsCfg );

      if(!testNameCoding( dirNode, verbose ))
        return false;
    }
  }

  if(verbose)
    cerr << "Testing block encode/decode on full block -  ";
  {
    int numErrors = checkErrorPropogation( cipher,
        FSBlockSize, -1 );
    if(numErrors)
    {
      if(verbose)
        cerr << " FAILED!\n";
      return false;
    } else
    {
      if(verbose)
        cerr << " OK\n";
    }
  }
  if(verbose)
    cerr << "Testing block encode/decode on partial block -  ";
  {
    int numErrors = checkErrorPropogation( cipher,
        FSBlockSize-1, -1 );
    if(numErrors)
    {
      if(verbose)
        cerr << " FAILED!\n";
      return false;
    } else
    {
      if(verbose)
        cerr << " OK\n";
    }
  }

  if(verbose)
    cerr << "Checking error propogation in partial block:\n";
  {
    int minChanges = FSBlockSize-1;
    int maxChanges = 0;
    int minAt = 0;
    int maxAt = 0;
    for(int i=0; i<FSBlockSize-1; ++i)
    {
      int numErrors = checkErrorPropogation( cipher,
          FSBlockSize-1, i );

      if(numErrors < minChanges) 
      {
        minChanges = numErrors;
        minAt = i;
      }
      if(numErrors > maxChanges)
      {
        maxChanges = numErrors;
        maxAt = i;
      }
    }

    if(verbose)
    {
      cerr << "modification of 1 byte affected between " << minChanges
        << " and " << maxChanges << " decoded bytes\n";
      cerr << "minimum change at byte " << minAt
        << " and  maximum at byte " << maxAt << "\n";
    }
  }
  if(verbose)
    cerr << "Checking error propogation on full block:\n";
  {
    int minChanges = FSBlockSize;
    int maxChanges = 0;
    int minAt = 0;
    int maxAt = 0;
    for(int i=0; i<FSBlockSize; ++i)
    {
      int numErrors = checkErrorPropogation( cipher,
          FSBlockSize, i );

      if(numErrors < minChanges) 
      {
        minChanges = numErrors;
        minAt = i;
      }
      if(numErrors > maxChanges)
      {
        maxChanges = numErrors;
        maxAt = i;
      }
    }

    if(verbose)
    {
      cerr << "modification of 1 byte affected between " << minChanges
        << " and " << maxChanges << " decoded bytes\n";
      cerr << "minimum change at byte " << minAt
        << " and  maximum at byte " << maxAt << "\n";
    }
  }

  return true;
}

}  // namespace encfs

int main(int argc, char *argv[])
{
  FLAGS_logtostderr = 1;
  FLAGS_minloglevel = 1;

  google::InitGoogleLogging(argv[0]);
  google::InstallFailureSignalHandler();

#ifdef HAVE_SSL
  SSL_load_error_strings();
  SSL_library_init();

#ifndef OPENSSL_NO_ENGINE
  ENGINE_load_builtin_engines();
  ENGINE_register_all_ciphers();
  ENGINE_register_all_digests();
  ENGINE_register_all_RAND();
#endif
#endif

  srand( time(0) );

  // get a list of the available algorithms
  std::list<CipherV1::CipherAlgorithm> algorithms =
    CipherV1::GetAlgorithmList();
  std::list<CipherV1::CipherAlgorithm>::const_iterator it;
  cerr << "Supported Crypto interfaces:\n";
  for(it = algorithms.begin(); it != algorithms.end(); ++it)
  {
    cerr << it->name 
      << " ( " << it->iface.name() << " " 
      << it->iface.major() << ":" 
      << it->iface.minor() << ":"
      << it->iface.age() << " ) : " << it->description << "\n";
    cerr << " - key length " << it->keyLength.min() << " to "
      << it->keyLength.max() << " , block size " << it->blockSize.min()
      << " to " << it->blockSize.max() << "\n";
  }
  cerr << "\n";

  cerr << "Testing interfaces\n";
  for(it = algorithms.begin(); it != algorithms.end(); ++it)
  {
    int blockSize = it->blockSize.closest( 256 );
    for(int keySize = it->keyLength.min(); keySize <= it->keyLength.max();
        keySize += it->keyLength.inc())
    {
      cerr << it->name << ", key length " << keySize
        << ", block size " << blockSize << ":  ";

      shared_ptr<CipherV1> cipher = CipherV1::New( it->name, keySize );
      if(!cipher)
      {
        cerr << "FAILED TO CREATE\n";
      } else
      {
        try
        {
          if(runTests( cipher, false ))
            cerr << "OK\n";
          else
            cerr << "FAILED\n";
        } catch( Error &er )
        {
          cerr << "Error: " << er.what() << "\n";
        }
      }
    }
  }

  // run one test with verbose output too..
  shared_ptr<CipherV1> cipher = CipherV1::New("AES", 192);
  if(!cipher)
  {
    cerr << "\nNo AES cipher found, skipping verbose test.\n";
  } else
  {
    cerr << "\nVerbose output for " << cipher->interface().name() 
      << " test, key length " << cipher->keySize()*8 << ", block size " 
      << FSBlockSize << ":\n";

    runTests( cipher, true );
  }

  return 0;
}

