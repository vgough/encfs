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

#include "base/Interface.h"
#include "base/shared_ptr.h"
#include "cipher/CipherKey.h"
#include "fs/encfs.h"
#include "fs/fsconfig.pb.h"

#include <vector>

namespace encfs {

enum ConfigType
{
    Config_None = 0,
    Config_Prehistoric,
    Config_V3 = 3,
    Config_V4 = 4,
    Config_V5 = 5,
    Config_V6 = 6,
    Config_V7 = 7
};

struct EncFS_Opts;
class CipherV1;
class NameIO;

CipherKey getUserKey(const EncfsConfig &config, bool useStdin);
CipherKey getUserKey(const EncfsConfig &config,
                     const std::string &passwordProgram,
                     const std::string &rootDir);

CipherKey getNewUserKey(EncfsConfig &config, bool useStdin, 
    const std::string &program, const std::string &rootDir);
    
shared_ptr<CipherV1> getCipher(const EncfsConfig &cfg);
shared_ptr<CipherV1> getCipher(const Interface &iface, int keySize);

// helpers for serializing to/from a stream
std::ostream &operator << (std::ostream &os, const EncfsConfig &cfg);
std::istream &operator >> (std::istream &os, EncfsConfig &cfg);

// Filesystem state
struct FSConfig
{
    shared_ptr<EncfsConfig> config;
    shared_ptr<EncFS_Opts> opts;

    shared_ptr<CipherV1> cipher;
    CipherKey key;
    shared_ptr<NameIO> nameCoding;

    bool forceDecode; // force decode on MAC block failures
    bool reverseEncryption; // reverse encryption operation

    bool idleTracking; // turn on idle monitoring of filesystem
};

typedef shared_ptr<FSConfig> FSConfigPtr;

}  // namespace encfs

#endif

