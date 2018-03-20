/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2010 Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _FSConfig_incl_
#define _FSConfig_incl_

#include <memory>
#include <string>
#include <vector>

#include "CipherKey.h"
#include "Interface.h"
#include "encfs.h"

namespace encfs {

enum ConfigType {
  Config_None = 0,
  Config_Prehistoric,
  Config_V3,
  Config_V4,
  Config_V5,
  Config_V6
};

struct EncFS_Opts;
class Cipher;
class NameIO;

/**
 * Persistent configuration (stored in config file .encfs6.xml)
 */
struct EncFSConfig {
  ConfigType cfgType;

  std::string creator;
  int subVersion;

  // interface of cipher
  Interface cipherIface;
  // interface used for file name coding
  Interface nameIface;

  int keySize;    // reported in bits
  int blockSize;  // reported in bytes

  std::vector<unsigned char> keyData;
  std::vector<unsigned char> salt;

  int kdfIterations;
  long desiredKDFDuration;

  bool plainData;         // do not encrypt file content

  int blockMACBytes;      // MAC headers on blocks..
  int blockMACRandBytes;  // number of random bytes in the block header

  bool uniqueIV;            // per-file Initialization Vector
  bool externalIVChaining;  // IV seeding by filename IV chaining

  bool chainedNameIV;  // filename IV chaining
  bool allowHoles;     // allow holes in files (implicit zero blocks)

  EncFSConfig() : keyData(), salt() {
    cfgType = Config_None;
    subVersion = 0;
    plainData = false;
    blockMACBytes = 0;
    blockMACRandBytes = 0;
    uniqueIV = false;
    externalIVChaining = false;
    chainedNameIV = false;
    allowHoles = false;

    kdfIterations = 0;
    desiredKDFDuration = 500;
  }

  CipherKey getUserKey(bool useStdin);
  CipherKey getUserKey(const std::string &passwordProgram,
                       const std::string &rootDir);
  CipherKey getNewUserKey();

  std::shared_ptr<Cipher> getCipher() const;

  // deprecated
  void assignKeyData(const std::string &in);
  void assignKeyData(unsigned char *data, int length);
  void assignSaltData(unsigned char *data, int length);

  unsigned char *getKeyData() const;
  unsigned char *getSaltData() const;

 private:
  CipherKey makeKey(const char *password, int passwdLen);
};

// helpers for serializing to/from a stream
std::ostream &operator<<(std::ostream &os, const EncFSConfig &cfg);
std::istream &operator>>(std::istream &os, EncFSConfig &cfg);

struct FSConfig {
  std::shared_ptr<EncFSConfig> config;
  std::shared_ptr<EncFS_Opts> opts;

  std::shared_ptr<Cipher> cipher;
  CipherKey key;
  std::shared_ptr<NameIO> nameCoding;

  bool forceDecode;        // force decode on MAC block failures
  bool reverseEncryption;  // reverse encryption operation

  bool idleTracking;  // turn on idle monitoring of filesystem

  FSConfig()
      : forceDecode(false), reverseEncryption(false), idleTracking(false) {}
};

using FSConfigPtr = std::shared_ptr<FSConfig>;

}  // namespace encfs

#endif
