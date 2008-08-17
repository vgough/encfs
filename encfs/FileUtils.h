/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 * 
 * This program is free software; you can distribute it and/or modify it under 
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
                             
#ifndef _FileUtils_incl_
#define _FileUtils_incl_

#include "encfs.h"
#include "Interface.h"
#include "DirNode.h"
#include "CipherKey.h"

// true if the path points to an existing node (of any type)
bool fileExists( const char *fileName );
// true if path is a directory
bool isDirectory( const char *fileName );
// true if starts with '/'
bool isAbsolutePath( const char *fileName );
// pointer to just after the last '/'
const char *lastPathElement( const char *name );

std::string parentDirectory( const std::string &path );

// ask the user for permission to create the directory.  If they say ok, then
// do it and return true.
bool userAllowMkdir( const char *dirPath, mode_t mode );

enum ConfigType
{
    Config_None = 0,
    Config_Prehistoric,
    Config_V3,
    Config_V4,
    Config_V5,
    Config_V6
};

struct EncFSConfig
{
    ConfigType cfgType;

    std::string creator;
    int subVersion;

    // interface of cipher
    rel::Interface cipherIface;
    // interface used for file name coding
    rel::Interface nameIface;
    int keySize; // reported in bits
    int blockSize; // reported in bytes
    std::string keyData;

    int saltSize; // in bytes
    unsigned char *saltData;
    int kdfIterations;
    long desiredKDFDuration;

    int blockMACBytes; // MAC headers on blocks..
    int blockMACRandBytes; // number of random bytes in the block header

    bool uniqueIV; // per-file Initialization Vector
    bool externalIVChaining; // IV seeding by filename IV chaining

    bool chainedNameIV; // filename IV chaining
    bool allowHoles; // allow holes in files (implicit zero blocks)

    EncFSConfig()
    {
        cfgType = Config_None;
        subVersion = 0;
        blockMACBytes = 0;
        blockMACRandBytes = 0;
        uniqueIV = false;
        externalIVChaining = false;
        chainedNameIV = false;
        allowHoles = false;

        saltSize = 0;
        saltData = NULL;
        kdfIterations = 0;
        desiredKDFDuration = 500;
    }

    ~EncFSConfig()
    {
        if(saltData != NULL)
            delete[] saltData;
    }

    CipherKey getUserKey(bool useStdin);
    CipherKey getUserKey(const std::string &passwordProgram,
                         const std::string &rootDir);
    CipherKey getNewUserKey();
    
    shared_ptr<Cipher> getCipher();
private:
    CipherKey makeKey(const char *password, int passwdLen);
};

class Cipher;

struct EncFS_Root
{
    boost::shared_ptr<Cipher> cipher;
    CipherKey volumeKey;
    boost::shared_ptr<DirNode> root;

    EncFS_Root();
    ~EncFS_Root();
};

typedef boost::shared_ptr<EncFS_Root> RootPtr;

/*
    Read existing config file.  Looks for any supported configuration version.
*/
ConfigType readConfig( const std::string &rootDir, EncFSConfig *config ); 

/*
    Save the configuration.  Saves back as the same configuration type as was
    read from.
*/
bool saveConfig( ConfigType type, const std::string &rootdir, 
	EncFSConfig *config );


struct EncFS_Opts
{
    std::string rootDir;
    bool createIfNotFound;  // create filesystem if not found
    bool idleTracking; // turn on idle monitoring of filesystem
    bool mountOnDemand; // mounting on-demand

    bool checkKey;  // check crypto key decoding
    bool forceDecode; // force decode on MAC block failures

    std::string passwordProgram; // path to password program (or empty)
    bool useStdin; // read password from stdin rather then prompting

    bool ownerCreate; // set owner of new files to caller

    bool reverseEncryption; // Reverse encryption
    EncFS_Opts()
    {
	createIfNotFound = true;
	idleTracking = false;
	mountOnDemand = false;
	checkKey = true;
	forceDecode = false;
	useStdin = false;
	ownerCreate = false;
	reverseEncryption = false;
    }
};

class EncFS_Context;

RootPtr initFS( EncFS_Context *ctx, const shared_ptr<EncFS_Opts> &opts );

RootPtr createV6Config( EncFS_Context *ctx, const std::string &rootDir, 
	bool enableIdleTracking,
	bool forceDecode,
	const std::string &passwordProgram, bool reverseEncryption,
        bool allowHoles );


void showFSInfo( const EncFSConfig &config );

bool readV4Config( const char *configFile, EncFSConfig *config,
	struct ConfigInfo *);
bool writeV4Config( const char *configFile, EncFSConfig *config);

bool readV5Config( const char *configFile, EncFSConfig *config,
	struct ConfigInfo *);
bool writeV5Config( const char *configFile, EncFSConfig *config);

bool readV6Config( const char *configFile, EncFSConfig *config,
	struct ConfigInfo *);
bool writeV6Config( const char *configFile, EncFSConfig *config);


#endif
