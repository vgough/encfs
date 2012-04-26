/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2010 Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _FSConfig_incl_
#define _FSConfig_incl_

#include "encfs.h"
#include "Interface.h"
#include "CipherKey.h"

#include <vector>
#include <boost/shared_ptr.hpp>

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

class EncFS_Opts;
class Cipher;
class NameIO;
class EncfsConfig;

CipherKey getUserKey(const EncfsConfig &config, bool useStdin);
CipherKey getUserKey(const EncfsConfig &config,
                     const std::string &passwordProgram,
                     const std::string &rootDir);

CipherKey getNewUserKey(EncfsConfig &config, bool useStdin, 
    const std::string &program, const std::string &rootDir);
    
boost::shared_ptr<Cipher> getCipher(const EncfsConfig &cfg);
boost::shared_ptr<Cipher> getCipher(const Interface &iface, int keySize);

// helpers for serializing to/from a stream
std::ostream &operator << (std::ostream &os, const EncfsConfig &cfg);
std::istream &operator >> (std::istream &os, EncfsConfig &cfg);

// Filesystem state
struct FSConfig
{
    boost::shared_ptr<EncfsConfig> config;
    boost::shared_ptr<EncFS_Opts> opts;

    boost::shared_ptr<Cipher> cipher;
    CipherKey key;
    boost::shared_ptr<NameIO> nameCoding;

    bool forceDecode; // force decode on MAC block failures
    bool reverseEncryption; // reverse encryption operation

    bool idleTracking; // turn on idle monitoring of filesystem
};

typedef boost::shared_ptr<FSConfig> FSConfigPtr;

#endif

