/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
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

#ifndef _FileUtils_incl_
#define _FileUtils_incl_

#include <memory>
#include <string>
#include <sys/types.h>

#include "CipherKey.h"
#include "FSConfig.h"
#include "Interface.h"
#include "encfs.h"

namespace encfs {

// true if the path points to an existing node (of any type)
bool fileExists(const char *fileName);
// true if path is a directory
bool isDirectory(const char *fileName);
// true if starts with '/'
bool isAbsolutePath(const char *fileName);
// pointer to just after the last '/'
const char *lastPathElement(const char *name);

std::string parentDirectory(const std::string &path);

// ask the user for permission to create the directory.  If they say ok, then
// do it and return true.
bool userAllowMkdir(const char *dirPath, mode_t mode);
bool userAllowMkdir(int promptno, const char *dirPath, mode_t mode);

class Cipher;
class DirNode;

struct EncFS_Root {
  std::shared_ptr<Cipher> cipher;
  CipherKey volumeKey;
  std::shared_ptr<DirNode> root;

  EncFS_Root();
  ~EncFS_Root();
};

typedef std::shared_ptr<EncFS_Root> RootPtr;

enum ConfigMode { Config_Prompt, Config_Standard, Config_Paranoia };

/**
 * EncFS_Opts stores internal settings
 *
 * See struct EncFS_Args (main.cpp) for the parsed command line arguments
 */
struct EncFS_Opts {
  std::string rootDir;
  std::string mountPoint;  // where to make filesystem visible
  bool createIfNotFound;   // create filesystem if not found
  bool idleTracking;       // turn on idle monitoring of filesystem
  bool mountOnDemand;      // mounting on-demand
  bool delayMount;         // delay initial mount

  bool checkKey;     // check crypto key decoding
  bool forceDecode;  // force decode on MAC block failures

  std::string passwordProgram;  // path to password program (or empty)
  bool useStdin;  // read password from stdin rather then prompting
  bool annotate;  // print annotation line prompt to stderr.

  bool ownerCreate;  // set owner of new files to caller

  bool reverseEncryption;  // Reverse encryption

  bool noCache; /* Disable block cache (in EncFS) and stat cache (in kernel).
                 * This is needed if the backing files may be modified
                 * behind the back of EncFS (for example, in reverse mode).
                 * See main.cpp for a longer explaination. */

  bool readOnly;  // Mount read-only

  bool requireMac;  // Throw an error if MAC is disabled

  ConfigMode configMode;

  EncFS_Opts() {
    createIfNotFound = true;
    idleTracking = false;
    mountOnDemand = false;
    delayMount = false;
    checkKey = true;
    forceDecode = false;
    useStdin = false;
    annotate = false;
    ownerCreate = false;
    reverseEncryption = false;
    configMode = Config_Prompt;
    noCache = false;
    readOnly = false;
    requireMac = false;
  }
};

/*
    Read existing config file.  Looks for any supported configuration version.
*/
ConfigType readConfig(const std::string &rootDir, EncFSConfig *config);

/*
    Save the configuration.  Saves back as the same configuration type as was
    read from.
*/
bool saveConfig(ConfigType type, const std::string &rootdir,
                const EncFSConfig *config);

class EncFS_Context;

RootPtr initFS(EncFS_Context *ctx, const std::shared_ptr<EncFS_Opts> &opts);

RootPtr createV6Config(EncFS_Context *ctx,
                       const std::shared_ptr<EncFS_Opts> &opts);

void showFSInfo(const EncFSConfig *config);

bool readV4Config(const char *configFile, EncFSConfig *config,
                  struct ConfigInfo *);
bool writeV4Config(const char *configFile, const EncFSConfig *config);

bool readV5Config(const char *configFile, EncFSConfig *config,
                  struct ConfigInfo *);
bool writeV5Config(const char *configFile, const EncFSConfig *config);

bool readV6Config(const char *configFile, EncFSConfig *config,
                  struct ConfigInfo *);
bool writeV6Config(const char *configFile, const EncFSConfig *config);

}  // namespace encfs

#endif
