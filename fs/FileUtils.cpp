/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004-2012, Valient Gough
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

// defines needed for RedHat 7.3...
#ifdef linux
#define _XOPEN_SOURCE 500 // make sure pwrite() is pulled in
#endif
#define _BSD_SOURCE // pick up setenv on RH7.3

#include "fs/encfs.h"
#include "fs/fsconfig.pb.h"

#include "base/autosprintf.h"
#include "base/config.h"
#include "base/ConfigReader.h"
#include "base/Error.h"
#include "base/i18n.h"
#include "base/XmlReader.h"

#include "cipher/CipherV1.h"
#include "cipher/MemoryPool.h"
#include "cipher/readpassphrase.h"

#include "fs/BlockNameIO.h"
#include "fs/Context.h"
#include "fs/DirNode.h"
#include "fs/FileUtils.h"
#include "fs/FSConfig.h"
#include "fs/NullNameIO.h"
#include "fs/StreamNameIO.h"

#include <glog/logging.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <iostream>
#include <sstream>

#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

using gnu::autosprintf;
using std::cout;
using std::cerr;
using std::endl;
using std::map;
using std::string;

namespace encfs {

static const int DefaultBlockSize = 2048;
// The maximum length of text passwords.  If longer are needed,
// use the extpass option, as extpass can return arbitrary length binary data.
static const int MaxPassBuf = 2048;

static const int NormalKDFDuration = 500; // 1/2 a second
static const int ParanoiaKDFDuration = 3000; // 3 seconds

// environment variable names for values encfs stores in the environment when
// calling an external password program.
static const char ENCFS_ENV_ROOTDIR[] = "encfs_root";
static const char ENCFS_ENV_STDOUT[] = "encfs_stdout";
static const char ENCFS_ENV_STDERR[] = "encfs_stderr";

const int V5Latest = 20040813; // fix MACFileIO block size issues
const int ProtoSubVersion = 20120902;

const char ConfigFileName[] = ".encfs.txt";

struct ConfigInfo
{
  ConfigType type;
  const char *fileName;
  const char *environmentOverride;
  bool (*loadFunc)(const char *fileName, 
      EncfsConfig &config, ConfigInfo *cfg);
} ConfigFileMapping[] = {
  {Config_V7, ConfigFileName, "ENCFS_CONFIG", readProtoConfig },
  {Config_V6, ".encfs6.xml", "ENCFS6_CONFIG", readV6Config },
  // backward compatible support for older versions
  {Config_V5, ".encfs5", "ENCFS5_CONFIG", readV5Config },
  {Config_V4, ".encfs4", NULL, readV4Config },
  // prehistoric - no longer support
  {Config_V3, ".encfs3", NULL, NULL },
  {Config_Prehistoric, ".encfs2", NULL, NULL },
  {Config_Prehistoric, ".encfs", NULL, NULL },
  {Config_None, NULL, NULL, NULL } };

EncFS_Root::EncFS_Root()
{
}

EncFS_Root::~EncFS_Root()
{
}


bool fileExists( const char * fileName )
{
  struct stat buf;
  if(!lstat( fileName, &buf ))
  {
    return true;
  } else
  {
    // XXX show perror?
    return false;
  }
}

bool isDirectory( const char *fileName )
{
  struct stat buf;
  if( !lstat( fileName, &buf ))
  {
    return S_ISDIR( buf.st_mode );
  } else
  {
    return false;
  }
}

bool isAbsolutePath( const char *fileName )
{
  if(fileName && fileName[0] != '\0' && fileName[0] == '/')
    return true;
  else
    return false;
}

const char *lastPathElement( const char *name )
{
  const char *loc = strrchr( name, '/' );
  return loc ? loc + 1 : name;
}

std::string parentDirectory( const std::string &path )
{
  size_t last = path.find_last_of( '/' );
  if(last == string::npos)
    return string("");
  else
    return path.substr(0, last);
}

bool userAllowMkdir(const char *path, mode_t mode )
{
    return userAllowMkdir(0, path, mode);
}

bool userAllowMkdir(int promptno, const char *path, mode_t mode )
{
  // TODO: can we internationalize the y/n names?  Seems strange to prompt in
  // their own language but then have to respond 'y' or 'n'.
  // xgroup(setup)
  cerr << autosprintf( _("The directory \"%s\" does not exist. Should it be created? (y,n) "), path );
  char answer[10];
  char *res;

  switch (promptno)
  {
  case 1:
    cerr << endl << "$PROMPT$ create_root_dir" << endl;
    break;
  case 2:
    cerr << endl << "$PROMPT$ create_mount_point" << endl;
    break;
  default:
    break;
  }
  res = fgets( answer, sizeof(answer), stdin );

  if(res != 0 && toupper(answer[0]) == 'Y')
  {
    int result = mkdir( path, mode );
    if(result < 0)
    {
      perror( _("Unable to create directory: ") );
      return false;
    } else
      return true;
  } else
  {
    // Directory not created, by user request
    cerr << _("Directory not created.") << "\n";
    return false;
  }
}

ConfigType readConfig_load( ConfigInfo *nm, const char *path, 
    EncfsConfig &config )
{
  if( nm->loadFunc )
  {
    try
    {
      if( (*nm->loadFunc)( path, config, nm ))
        return nm->type;
    } catch( Error &err )
    {
      LOG(WARNING) << "readConfig failed: " << err.what();
    }

    LOG(ERROR) << "Found config file " << path << ", but failed to load";
    return Config_None;
  } else
  {
    // No load function - must be an unsupported type..
    return Config_None;
  }
}

ConfigType readConfig( const string &rootDir, EncfsConfig &config )
{
  ConfigInfo *nm = ConfigFileMapping;
  while(nm->fileName)
  {
    // allow environment variable to override default config path
    if( nm->environmentOverride != NULL )
    {
      char *envFile = getenv( nm->environmentOverride );
      if( envFile != NULL )
        return readConfig_load( nm, envFile, config );
    }
    // the standard place to look is in the root directory
    string path = rootDir + nm->fileName;
    if( fileExists( path.c_str() ) )
      return readConfig_load( nm, path.c_str(), config);

    ++nm;
  }

  return Config_None;
}

// Read a boost::serialization config file using an Xml reader..
bool readV6Config( const char *configFile, 
    EncfsConfig &cfg, ConfigInfo *info)
{
  (void)info;

  XmlReader rdr;
  if (!rdr.load(configFile))
  {
    LOG(ERROR) << "Failed to load config file " << configFile;
    return false;
  }

  XmlValuePtr serialization = rdr["boost_serialization"];
  XmlValuePtr config = (*serialization)["cfg"];
  if (!config) {
    config = (*serialization)["config"];
  }
  if (!config) {
    LOG(ERROR) << "Unable to find XML configuration in file " << configFile;
    return false;
  }

  int version;
  if (!config->read("version", &version) &&
      !config->read("@version", &version)) {
    LOG(ERROR) << "Unable to find version in config file";
    return false;
  }

  // version numbering was complicated by boost::archive 
  if (version == 20 || version >= 20100713)
  {
    VLOG(1) << "found new serialization format";
    cfg.set_revision(version);
  } else if (version == 26800)
  {
    VLOG(1) << "found 20080816 version";
    cfg.set_revision(20080816);
  } else if (version == 26797)
  {
    VLOG(1) << "found 20080813";
    cfg.set_revision(20080813);
  } else if (version < V5Latest)
  {
    LOG(ERROR) << "Invalid version " << version
      << " - please fix config file";
  } else
  {
    LOG(INFO) << "Boost <= 1.41 compatibility mode";
    cfg.set_revision(version);
  }
  VLOG(1) << "subVersion = " << cfg.revision();

  config->read("creator", cfg.mutable_creator());
  config->read("cipherAlg", cfg.mutable_cipher());
  config->read("nameAlg", cfg.mutable_naming());

  //(*config)["keySize"] >> cfg.keySize;
  int blockSize, blockMacBytes, blockMacRandBytes;
  bool uniqueIv, chainedNameIv, externalIv, allowHoles;

  config->read("blockSize", &blockSize);
  config->read("uniqueIV", &uniqueIv);
  config->read("chainedNameIV", &chainedNameIv);
  config->read("externalIVChaining", &externalIv);
  config->read("blockMACBytes", &blockMacBytes);
  config->read("blockMACRandBytes", &blockMacRandBytes);
  config->read("allowHoles", &allowHoles);

  cfg.set_block_size(blockSize);
  cfg.set_unique_iv(uniqueIv);
  cfg.set_chained_iv(chainedNameIv);
  cfg.set_external_iv(externalIv);
  cfg.set_block_mac_bytes(blockMacBytes);
  cfg.set_block_mac_rand_bytes(blockMacRandBytes);
  cfg.set_allow_holes(allowHoles);

  EncryptedKey *encryptedKey = cfg.mutable_key();
  int encodedSize;
  config->read("encodedKeySize", &encodedSize);
  unsigned char *key = new unsigned char[encodedSize];
  config->readB64("encodedKeyData", key, encodedSize);
  encryptedKey->set_ciphertext(key, encodedSize);
  delete[] key;
  
  int keySize;
  config->read("keySize", &keySize);
  encryptedKey->set_size(keySize / 8); // save as size in bytes

  if(cfg.revision() >= 20080816)
  {
    int saltLen;
    config->read("saltLen", &saltLen);
    unsigned char *salt = new unsigned char[saltLen];
    config->readB64("saltData", salt, saltLen);
    encryptedKey->set_salt(salt, saltLen);
    delete[] salt;

    int kdfIterations, desiredKDFDuration;
    config->read("kdfIterations", &kdfIterations);
    config->read("desiredKDFDuration", &desiredKDFDuration);
    encryptedKey->set_kdf_iterations(kdfIterations);
    encryptedKey->set_kdf_duration(desiredKDFDuration);
  } else
  {
    encryptedKey->clear_salt();
    encryptedKey->set_kdf_iterations(16);
    encryptedKey->clear_kdf_duration();
  }

  return true;
}

// Read a v5 archive, which is a proprietary binary format.
bool readV5Config( const char *configFile, 
    EncfsConfig &config, ConfigInfo *)
{
  bool ok = false;

  // use Config to parse the file and query it..
  ConfigReader cfgRdr;
  if(cfgRdr.load( configFile ))
  {
    try
    {
      config.set_revision(cfgRdr["subVersion"].readInt(0));
      if(config.revision() > V5Latest)
      {
        /* config file specifies a version outside our supported
           range..   */
        LOG(ERROR) << "Config subversion " << config.revision()
          << " found, but this version of encfs only supports up to version "
          << V5Latest;
        return false;
      }
      if( config.revision() < V5Latest )
      {
        LOG(ERROR) << "This version of EncFS doesn't support "
          << "filesystems created with EncFS releases before 2004-08-13";
        return false;
      }

      cfgRdr["creator"] >> (*config.mutable_creator());
      cfgRdr["cipher"] >> (*config.mutable_cipher());
      cfgRdr["naming"] >> (*config.mutable_naming());

      int blockSize;
      cfgRdr["blockSize"] >> blockSize;
      config.set_block_size(blockSize);

      EncryptedKey *encryptedKey = config.mutable_key();
      int keySize;
      cfgRdr["keySize"] >> keySize;
      encryptedKey->set_size(keySize / 8);
      cfgRdr["keyData"] >> (*encryptedKey->mutable_ciphertext());

      config.set_unique_iv( cfgRdr["uniqueIV"].readBool( false ) );
      config.set_chained_iv( cfgRdr["chainedIV"].readBool( false ) );
      config.set_external_iv( cfgRdr["externalIV"].readBool( false ) );
      config.set_block_mac_bytes( cfgRdr["blockMACBytes"].readInt(0) );
      config.set_block_mac_rand_bytes( cfgRdr["blockMACRandBytes"].readInt(0) );

      ok = true;
    } catch( Error &err)
    {
      LOG(WARNING) << "Error parsing data in config file " << configFile
        << "; " << err.what();
      ok = false;
    }
  }

  return ok;
}

bool readV4Config( const char *configFile, 
    EncfsConfig &config, ConfigInfo *)
{
  bool ok = false;

  // use Config to parse the file and query it..
  ConfigReader cfgRdr;
  if(cfgRdr.load( configFile ))
  {
    try
    {
      cfgRdr["cipher"] >> (*config.mutable_cipher());
      int blockSize;
      cfgRdr["blockSize"] >> blockSize;
      config.set_block_size(blockSize);

      EncryptedKey *key = config.mutable_key();
      cfgRdr["keyData"] >> (*key->mutable_ciphertext());

      // fill in default for V4
      config.mutable_naming()->MergeFrom( makeInterface("nameio/stream", 1, 0, 0) );
      config.set_creator( "EncFS 1.0.x" );

      ok = true;
    } catch( Error &err)
    {
      LOG(WARNING) << "Error parsing config file " << configFile
        << ": " << err.what();
      ok = false;
    }
  }

  return ok;
}

bool writeTextConfig( const char *fileName, const EncfsConfig &cfg )
{
  int fd = ::open( fileName, O_RDWR | O_CREAT, 0640 );
  if (fd < 0)
  {
    LOG(ERROR) << "Unable to open or create file " << fileName;
    return false;
  }

  google::protobuf::io::FileOutputStream fos( fd );
  google::protobuf::TextFormat::Print( cfg, &fos );

  fos.Close();
  return true;
}

bool saveConfig( const string &rootDir, const EncfsConfig &config )
{
  bool ok = false;

  ConfigInfo *nm = ConfigFileMapping;
    
  // TODO(vgough): remove old config after saving a new one?
  string path = rootDir + ConfigFileName;
  if( nm->environmentOverride != NULL )
  {
    // use environment file if specified..
    const char *envFile = getenv( nm->environmentOverride );
    if( envFile != NULL )
      path.assign( envFile );
  }

  try
  {
    const_cast<EncfsConfig &>(config).set_writer("EncFS " VERSION );
    ok = writeTextConfig( path.c_str(), config );
  } catch( Error &err )
  {
    LOG(WARNING) << "saveConfig failed: " << err.what();
    ok = false;
  }

  return ok;
}

bool readProtoConfig( const char *fileName, EncfsConfig &config,
    struct ConfigInfo *)
{
  int fd = ::open( fileName, O_RDONLY, 0640 );
  if (fd < 0)
  {
    LOG(ERROR) << "Unable to open file " << fileName;
    return false;
  }

  google::protobuf::io::FileInputStream fis( fd );
  google::protobuf::TextFormat::Parse( &fis, &config );

  return true;
}

static
CipherV1::CipherAlgorithm findCipherAlgorithm(const char *name,
    int keySize )
{
  for (auto &it : CipherV1::GetAlgorithmList()) 
  {
    if( !strcmp( name, it.name.c_str() )
        && it.keyLength.allowed( keySize ))
    {
      return it;
    }
  }

  CipherV1::CipherAlgorithm result;
  return result;
}

static
CipherV1::CipherAlgorithm selectCipherAlgorithm()
{
  for(;;)
  {
    // figure out what cipher they want to use..
    // xgroup(setup)
    cout << _("The following cipher algorithms are available:") << "\n";
    int optNum = 0;
    auto algorithms = CipherV1::GetAlgorithmList();
    for (auto &it : algorithms)
    {
      cout << ++optNum << ". " << it.name
        << " : " << gettext(it.description.c_str()) << "\n";
      if(it.keyLength.min() == it.keyLength.max())
      {
        // shown after algorithm name and description.
        // xgroup(setup)
        cout << autosprintf(_(" -- key length %i bits")
            , it.keyLength.min()) << "\n";
      } else
      {
        cout << autosprintf(
            // shown after algorithm name and description.
            // xgroup(setup)
            _(" -- Supports key lengths of %i to %i bits"),
            it.keyLength.min(), it.keyLength.max()) << "\n";
      }

      if(it.blockSize.min() == it.blockSize.max())
      {
        cout << autosprintf(
            // shown after algorithm name and description.
            // xgroup(setup)
            _(" -- block size %i bytes"), it.blockSize.min()) 
          << "\n";
      } else
      {
        cout << autosprintf(
            // shown after algorithm name and description.
            // xgroup(setup)
            _(" -- Supports block sizes of %i to %i bytes"),
            it.blockSize.min(), it.blockSize.max()) << "\n";
      }
    }

    // xgroup(setup)
    cout << "\n" << _("Enter the number corresponding to your choice: ");
    char answer[10];
    char *res = fgets( answer, sizeof(answer), stdin );
    int cipherNum = (res == 0 ? 0 : atoi( answer ));
    cout << "\n";

    if( cipherNum < 1 || cipherNum > (int)algorithms.size() )
    {
      cerr << _("Invalid selection.") << "\n";
      continue;
    }

    CipherV1::CipherAlgorithm alg;
    for (auto &it : algorithms) 
    {
      if (!--cipherNum)
      {
        alg = it;
        break;
      }
    }

    // xgroup(setup)
    cout << autosprintf(_("Selected algorithm \"%s\""), alg.name.c_str()) 
      << "\n\n";

    return alg;
  }
}

static
Interface selectNameCoding(const CipherV1::CipherAlgorithm &alg)
{
  for(;;)
  {
    // figure out what cipher they want to use..
    // xgroup(setup)
    cout << _("The following filename encoding algorithms are available:")
      << "\n";
    NameIO::AlgorithmList algorithms = NameIO::GetAlgorithmList();
    NameIO::AlgorithmList::const_iterator it;
    int optNum = 1;
    map<int, NameIO::AlgorithmList::const_iterator> algMap;
    for(it = algorithms.begin(); it != algorithms.end(); ++it)
    {
      cout << optNum << ". " << it->name
        << " : " << gettext(it->description.c_str()) << "\n";
      algMap[optNum++] = it;
    }

    // xgroup(setup)
    cout << "\n" << _("Enter the number corresponding to your choice: ");
    char answer[10];
    char *res = fgets( answer, sizeof(answer), stdin );
    int algNum = (res == 0 ? 0 : atoi( answer ));
    cout << "\n";

    if( algNum < 1 || algNum >= optNum )
    {
      cerr << _("Invalid selection.") << "\n";
      continue;
    }

    it = algMap[algNum];

    // xgroup(setup)
    cout << autosprintf(_("Selected algorithm \"%s\""), it->name.c_str()) 
      << "\"\n\n";

    return it->iface;
  }
}

static
int selectKeySize( const CipherV1::CipherAlgorithm &alg )
{
  if(alg.keyLength.min() == alg.keyLength.max())
  {
    cout << autosprintf(_("Using key size of %i bits"), 
        alg.keyLength.min()) << "\n";
    return alg.keyLength.min();
  }

  cout << autosprintf(
      // xgroup(setup)
      _("Please select a key size in bits.  The cipher you have chosen\n"
        "supports sizes from %i to %i bits in increments of %i bits.\n"
        "For example: "), alg.keyLength.min(), alg.keyLength.max(), 
      alg.keyLength.inc()) << "\n";

  int numAvail = (alg.keyLength.max() - alg.keyLength.min()) 
    / alg.keyLength.inc();

  if(numAvail < 5)
  {
    // show them all
    for(int i=0; i<=numAvail; ++i)
    {
      if(i) 
        cout << ", ";
      cout << alg.keyLength.min() + i * alg.keyLength.inc();
    }
  } else
  {
    // partial
    for(int i=0; i<3; ++i)
    {
      if(i) 
        cout << ", ";
      cout << alg.keyLength.min() + i * alg.keyLength.inc();
    }
    cout << " ... " << alg.keyLength.max() - alg.keyLength.inc();
    cout << ", " << alg.keyLength.max();
  }
  // xgroup(setup)
  cout << "\n" << _("Selected key size: ");

  char answer[10];
  char *res = fgets( answer, sizeof(answer), stdin );
  int keySize = (res == 0 ? 0 : atoi( answer ));
  cout << "\n";

  keySize = alg.keyLength.closest( keySize );

  // xgroup(setup)
  cout << autosprintf(_("Using key size of %i bits"), keySize) << "\n\n";

  return keySize;
}

static
int selectBlockSize( const CipherV1::CipherAlgorithm &alg )
{
  if(alg.blockSize.min() == alg.blockSize.max())
  {
    cout << autosprintf(
        // xgroup(setup)
        _("Using filesystem block size of %i bytes"),
        alg.blockSize.min()) << "\n";
    return alg.blockSize.min();
  }

  cout << autosprintf(
      // xgroup(setup)
      _("Select a block size in bytes.  The cipher you have chosen\n"
        "supports sizes from %i to %i bytes in increments of %i.\n"
        "Or just hit enter for the default (%i bytes)\n"),
      alg.blockSize.min(), alg.blockSize.max(), alg.blockSize.inc(),
      DefaultBlockSize);

  // xgroup(setup)
  cout << "\n" << _("filesystem block size: ");

  int blockSize = DefaultBlockSize;
  char answer[10];
  char *res = fgets( answer, sizeof(answer), stdin );
  cout << "\n";

  if( res != 0 && atoi( answer )  >= alg.blockSize.min() )
    blockSize = atoi( answer );

  blockSize = alg.blockSize.closest( blockSize );

  // xgroup(setup)
  cout << autosprintf(_("Using filesystem block size of %i bytes"), 
      blockSize) << "\n\n";

  return blockSize;
}

static
bool boolDefaultNo(const char *prompt)
{
  cout << prompt << "\n";
  cout << _("The default here is No.\n"
      "Any response that does not begin with 'y' will mean No: ");

  char answer[10];
  char *res = fgets( answer, sizeof(answer), stdin );
  cout << "\n";

  if(res != 0 && tolower(answer[0]) == 'y')
    return true;
  else
    return false;
}

static 
void selectBlockMAC(int *macBytes, int *macRandBytes)
{
  // xgroup(setup)
  bool addMAC = boolDefaultNo(
      _("Enable block authentication code headers\n"
        "on every block in a file?  This adds about 12 bytes per block\n"
        "to the storage requirements for a file, and significantly affects\n"
        "performance but it also means [almost] any modifications or errors\n"
        "within a block will be caught and will cause a read error."));

  if(addMAC)
    *macBytes = 8;
  else
    *macBytes = 0;

  // xgroup(setup)
  cout << _("Add random bytes to each block header?\n"
      "This adds a performance penalty, but ensures that blocks\n"
      "have different authentication codes.  Note that you can\n"
      "have the same benefits by enabling per-file initialization\n"
      "vectors, which does not come with as great of performance\n"
      "penalty. \n"
      "Select a number of bytes, from 0 (no random bytes) to 8: ");

  char answer[10];
  int randSize = 0;
  char *res = fgets( answer, sizeof(answer), stdin );
  cout << "\n";

  randSize = (res == 0 ? 0 : atoi( answer ));
  if(randSize < 0)
    randSize = 0;
  if(randSize > 8)
    randSize = 8;

  *macRandBytes = randSize;
}

static
bool boolDefaultYes(const char *prompt)
{
  cout << prompt << "\n";
  cout << _("The default here is Yes.\n"
      "Any response that does not begin with 'n' will mean Yes: ");

  char answer[10];
  char *res = fgets( answer, sizeof(answer), stdin );
  cout << "\n";

  if(res != 0 && tolower(answer[0]) == 'n')
    return false;
  else
    return true;
}

static 
bool selectUniqueIV()
{
  // xgroup(setup)
  return boolDefaultYes(
      _("Enable per-file initialization vectors?\n"
        "This adds about 8 bytes per file to the storage requirements.\n"
        "It should not affect performance except possibly with applications\n"
        "which rely on block-aligned file io for performance."));
}

static 
bool selectChainedIV()
{
  // xgroup(setup)
  return boolDefaultYes(
      _("Enable filename initialization vector chaining?\n"
        "This makes filename encoding dependent on the complete path, \n"
        "rather then encoding each path element individually."));
}

static 
bool selectExternalChainedIV()
{
  // xgroup(setup)
  return boolDefaultNo(
      _("Enable filename to IV header chaining?\n"
        "This makes file data encoding dependent on the complete file path.\n"
        "If a file is renamed, it will not decode sucessfully unless it\n"
        "was renamed by encfs with the proper key.\n"
        "If this option is enabled, then hard links will not be supported\n"
        "in the filesystem."));
}

static 
bool selectZeroBlockPassThrough()
{
  // xgroup(setup)
  return boolDefaultYes(
      _("Enable file-hole pass-through?\n"
        "This avoids writing encrypted blocks when file holes are created."));
}

RootPtr createConfig( EncFS_Context *ctx,
    const shared_ptr<EncFS_Opts> &opts )
{
  const std::string rootDir = opts->rootDir;
  bool enableIdleTracking = opts->idleTracking;
  bool forceDecode = opts->forceDecode;
  const std::string passwordProgram = opts->passwordProgram;
  bool useStdin = opts->useStdin;
  bool reverseEncryption = opts->reverseEncryption;
  ConfigMode configMode = opts->configMode;
  bool annotate = opts->annotate;

  RootPtr rootInfo;

  // creating new volume key.. should check that is what the user is
  // expecting...
  // xgroup(setup)
  cout << _("Creating new encrypted volume.") << endl;

  char answer[10] = {0};
  if(configMode == Config_Prompt)
  {
    // xgroup(setup)
    cout << _("Please choose from one of the following options:\n"
        " enter \"x\" for expert configuration mode,\n"
        " enter \"p\" for pre-configured paranoia mode,\n"
        " anything else, or an empty line will select standard mode.\n"
        "?> ");

    if (annotate)
      cerr << "$PROMPT$ config_option" << endl;

    char *res = fgets( answer, sizeof(answer), stdin );
    (void)res;
    cout << "\n";
  }

  int keySize = 0;
  int blockSize = 0;
  CipherV1::CipherAlgorithm alg;
  Interface nameIOIface;
  int blockMACBytes = 0;
  int blockMACRandBytes = 0;
  bool uniqueIV = false;
  bool chainedIV = false;
  bool externalIV = false;
  bool allowHoles = true;
  long desiredKDFDuration = NormalKDFDuration;

  if (reverseEncryption)
  {
    uniqueIV = false;
    chainedIV = false;
    externalIV = false;
    blockMACBytes = 0;
    blockMACRandBytes = 0;
  }

  if(configMode == Config_Paranoia || answer[0] == 'p')
  {
    if (reverseEncryption)
    {
      LOG(ERROR) << "Paranoia configuration not supported for --reverse";
      return rootInfo;
    }

    // xgroup(setup)
    cout << _("Paranoia configuration selected.") << "\n";
    // look for AES with 256 bit key..
    // Use block filename encryption mode.
    // Enable per-block HMAC headers at substantial performance penalty..
    // Enable per-file initialization vector headers.
    // Enable filename initialization vector chaning
    keySize = 256;
    blockSize = DefaultBlockSize;
    alg = findCipherAlgorithm("AES", keySize);
    nameIOIface = BlockNameIO::CurrentInterface();
    blockMACBytes = 8;
    blockMACRandBytes = 0; // using uniqueIV, so this isn't necessary
    uniqueIV = true;
    chainedIV = true;
    externalIV = true;
    desiredKDFDuration = ParanoiaKDFDuration;
  } else if(configMode == Config_Standard || answer[0] != 'x')
  {
    // xgroup(setup)
    cout << _("Standard configuration selected.") << "\n";
    // AES w/ 192 bit key, block name encoding, per-file initialization
    // vectors are all standard.
    keySize = 192;
    blockSize = DefaultBlockSize;
    alg = findCipherAlgorithm("AES", keySize);
    blockMACBytes = 0;
    externalIV = false;
    nameIOIface = BlockNameIO::CurrentInterface();

    if (reverseEncryption)
    {
      cout << _("--reverse specified, not using unique/chained IV") 
        << "\n";
    } else
    {
      uniqueIV = true;
      chainedIV = true;
    }
  }

  if(answer[0] == 'x' || alg.name.empty())
  {
    if(answer[0] != 'x')
    {
      // xgroup(setup)
      cout << _("Sorry, unable to locate cipher for predefined "
          "configuration...\n"
          "Falling through to Manual configuration mode.");
    } else
    {
      // xgroup(setup)
      cout << _("Manual configuration mode selected.");
    }
    cout << endl;

    // query user for settings..
    alg = selectCipherAlgorithm();
    keySize = selectKeySize( alg );
    blockSize = selectBlockSize( alg );
    nameIOIface = selectNameCoding( alg );
    if (reverseEncryption)
    {
      cout << _("--reverse specified, not using unique/chained IV") << "\n";
    } else
    {
      chainedIV = selectChainedIV();
      uniqueIV = selectUniqueIV();
      if(chainedIV && uniqueIV)
        externalIV = selectExternalChainedIV();
      else
      {
        // xgroup(setup)
        cout << _("External chained IV disabled, as both 'IV chaining'\n"
            "and 'unique IV' features are required for this option.") 
          << "\n";
        externalIV = false;
      }
      selectBlockMAC(&blockMACBytes, &blockMACRandBytes);
      allowHoles = selectZeroBlockPassThrough();
    }
  }

  shared_ptr<CipherV1> cipher = CipherV1::New( alg.iface, keySize );
  if(!cipher)
  {
    LOG(ERROR) << "Unable to instanciate cipher " << alg.name
      << ", key size " << keySize << ", block size " << blockSize;
    return rootInfo;
  } else
  {
    VLOG(1) << "Using cipher " << alg.name
      << ", key size " << keySize << ", block size " << blockSize;
  }

  EncfsConfig config;

  config.mutable_cipher()->MergeFrom( cipher->interface() );
  config.set_block_size( blockSize );
  config.mutable_naming()->MergeFrom( nameIOIface );
  config.set_creator( "EncFS " VERSION );
  config.set_revision( ProtoSubVersion );
  config.set_block_mac_bytes( blockMACBytes );
  config.set_block_mac_rand_bytes( blockMACRandBytes );
  config.set_unique_iv( uniqueIV );
  config.set_chained_iv( chainedIV );
  config.set_external_iv( externalIV );
  config.set_allow_holes( allowHoles );

  EncryptedKey *key = config.mutable_key();
  key->clear_salt();
  key->clear_kdf_iterations(); // filled in by keying function
  key->set_kdf_duration( desiredKDFDuration );
  key->set_size(keySize / 8);

  cout << "\n";
  // xgroup(setup)
  cout << _("Configuration finished.  The filesystem to be created has\n"
      "the following properties:") << endl;
  showFSInfo( config );

  if( config.external_iv() )
  {
    cout << 
      _("-------------------------- WARNING --------------------------\n")
      <<
      _("The external initialization-vector chaining option has been\n"
          "enabled.  This option disables the use of hard links on the\n"
          "filesystem. Without hard links, some programs may not work.\n"
          "The programs 'mutt' and 'procmail' are known to fail.  For\n"
          "more information, please see the encfs mailing list.\n"
          "If you would like to choose another configuration setting,\n"
          "please press CTRL-C now to abort and start over.") << endl;
    cout << endl;
  }

  // xgroup(setup)
  cout << _("Now you will need to enter a password for your filesystem.\n"
      "You will need to remember this password, as there is absolutely\n"
      "no recovery mechanism.  However, the password can be changed\n"
      "later using encfsctl.\n\n");

  int encodedKeySize = cipher->encodedKeySize();
  unsigned char *encodedKey = new unsigned char[ encodedKeySize ];

  CipherKey volumeKey = cipher->newRandomKey();

  // get user key and use it to encode volume key
  CipherKey userKey;
  VLOG(1) << "useStdin: " << useStdin;
  if(useStdin)
  {
    if (annotate)
      cerr << "$PROMPT$ new_passwd" << endl;
  }
  userKey = getNewUserKey( config, useStdin, passwordProgram, rootDir );

  cipher->setKey( userKey );
  cipher->writeKey( volumeKey, encodedKey );
  userKey.reset();

  key->set_ciphertext(encodedKey, encodedKeySize);
  delete[] encodedKey;

  if(!volumeKey.valid())
  {
    LOG(ERROR) << "Failure generating new volume key! "
      << "Please report this error.";
    return rootInfo;
  }

  cipher->setKey( volumeKey );
  if(!saveConfig( rootDir, config ))
    return rootInfo;

  // fill in config struct
  shared_ptr<NameIO> nameCoder = NameIO::New( config.naming(), cipher );
  if(!nameCoder)
  {
    LOG(WARNING) << "Name coding interface not supported";
    cout << _("The filename encoding interface requested is not available") 
      << endl;
    return rootInfo;
  }

  nameCoder->setChainedNameIV( config.chained_iv() );
  nameCoder->setReverseEncryption( reverseEncryption );

  FSConfigPtr fsConfig (new FSConfig);
  fsConfig->cipher = cipher;
  fsConfig->key = volumeKey;
  fsConfig->nameCoding = nameCoder;
  fsConfig->config = shared_ptr<EncfsConfig>(new EncfsConfig(config));
  fsConfig->forceDecode = forceDecode;
  fsConfig->reverseEncryption = reverseEncryption;
  fsConfig->idleTracking = enableIdleTracking;
  fsConfig->opts = opts;

  rootInfo = RootPtr( new EncFS_Root );
  rootInfo->cipher = cipher;
  rootInfo->volumeKey = volumeKey;
  rootInfo->root = shared_ptr<DirNode>( 
      new DirNode( ctx, rootDir, fsConfig ));

  return rootInfo;
}

void showFSInfo( const EncfsConfig &config )
{
  shared_ptr<CipherV1> cipher = CipherV1::New( config.cipher(), -1 );
  {
    cout << autosprintf(
        // xgroup(diag)
        _("Filesystem cipher: \"%s\", version %i:%i:%i"),
        config.cipher().name().c_str(), config.cipher().major(),
        config.cipher().minor(), config.cipher().age());
    // check if we support this interface..
    if(!cipher)
      cout << _(" (NOT supported)\n");
    else
    {
      // if we're using a newer interface, show the version number
      if( config.cipher() != cipher->interface() )
      {
        Interface iface = cipher->interface();
        // xgroup(diag)
        cout << autosprintf(_(" (using %i:%i:%i)\n"),
            iface.major(), iface.minor(), iface.age());
      } else
        cout << "\n";
    }
  }

  // xgroup(diag)
  cout << autosprintf(_("Filename encoding: \"%s\", version %i:%i:%i"),
          config.naming().name().c_str(), config.naming().major(),
          config.naming().minor(), config.naming().age());
    
  if (!cipher)
  {
      cout <<  "\n";
  } else
  {
    // Set a null key - the cipher won't work, but it will at least know the
    // key size and blocksize.
    CipherKey tmpKey(config.key().size());
    cipher->setKey(tmpKey);

    // check if we support the filename encoding interface..
    shared_ptr<NameIO> nameCoder = NameIO::New( config.naming(), cipher );
    if(!nameCoder)
    {
      // xgroup(diag)
      cout << _(" (NOT supported)\n");
    } else
    {
      // if we're using a newer interface, show the version number
      if( config.naming() != nameCoder->interface() )
      {
        Interface iface = nameCoder->interface();
        cout << autosprintf(_(" (using %i:%i:%i)\n"),
            iface.major(), iface.minor(), iface.age());
      } else
        cout << "\n";
    }
  }
  const EncryptedKey &key = config.key();
  {
    cout << autosprintf(_("Key Size: %i bits"), 8 * key.size());
    cipher = getCipher(config);
    if(!cipher)
    {
      // xgroup(diag)
      cout << _(" (NOT supported)\n");
    } else
      cout << "\n";
  }
  if(key.kdf_iterations() > 0 && key.salt().size() > 0)
  {
    cout << autosprintf(_("Using PBKDF2, with %i iterations"), 
        key.kdf_iterations()) << "\n";
    cout << autosprintf(_("Salt Size: %i bits"), 
        8*(int)key.salt().size()) << "\n";
  }
  if(config.block_mac_bytes() || config.block_mac_rand_bytes())
  {
    if(config.revision() < V5Latest)
    {
      cout << autosprintf(
          // xgroup(diag)
          _("Block Size: %i bytes + %i byte MAC header"),
          config.block_size(),
          config.block_mac_bytes() + config.block_mac_rand_bytes()) << endl;
    } else
    {
      // new version stores the header as part of that block size..
      cout << autosprintf(
          // xgroup(diag)
          _("Block Size: %i bytes, including %i byte MAC header"),
          config.block_size(),
          config.block_mac_bytes() + config.block_mac_rand_bytes()) << endl;
    }
  } else
  {
    // xgroup(diag)
    cout << autosprintf(_("Block Size: %i bytes"), config.block_size());
    cout << "\n";
  }

  if(config.unique_iv())
  {
    // xgroup(diag)
    cout << _("Each file contains 8 byte header with unique IV data.\n");
  }
  if(config.chained_iv())
  {
    // xgroup(diag)
    cout << _("Filenames encoded using IV chaining mode.\n");
  }
  if(config.external_iv())
  {
    // xgroup(diag)
    cout << _("File data IV is chained to filename IV.\n");
  }
  if(config.allow_holes())
  {
    // xgroup(diag)
    cout << _("File holes passed through to ciphertext.\n");
  }
  cout << "\n";
}

shared_ptr<CipherV1> getCipher(const EncfsConfig &config)
{
  return getCipher(config.cipher(), 8 * config.key().size());
}

shared_ptr<CipherV1> getCipher(const Interface &iface, int keySize)
{
  return CipherV1::New( iface, keySize );
}

CipherKey makeNewKey(EncfsConfig &config, const char *password, int passwdLen)
{
  CipherKey userKey;
  shared_ptr<CipherV1> cipher = getCipher(config);

  EncryptedKey *key = config.mutable_key();

  unsigned char salt[20];
  if(!cipher->pseudoRandomize( salt, sizeof(salt)))
  {
    cout << _("Error creating salt\n");
    return userKey;
  }
  key->set_salt(salt, sizeof(salt));

  int iterations = key->kdf_iterations();
  userKey = cipher->newKey(password, passwdLen,
                           &iterations, key->kdf_duration(),
                           salt, sizeof(salt));
  key->set_kdf_iterations(iterations);

  return userKey;
}

CipherKey decryptKey(const EncfsConfig &config, const char *password, int passwdLen)
{
  const EncryptedKey &key = config.key();
  CipherKey userKey;
  shared_ptr<CipherV1> cipher = getCipher(config.cipher(), 8 * key.size());

  if(!key.salt().empty())
  {
    int iterations = key.kdf_iterations();
    userKey = cipher->newKey(password, passwdLen,
                             &iterations, key.kdf_duration(), 
                             (const byte *)key.salt().data(),
                             key.salt().size());

    if (iterations != key.kdf_iterations()) 
    {
      LOG(ERROR) << "Error in KDF, iteration mismatch";
      return userKey;
    }
  } else
  {
    // old KDF, no salt..
    userKey = cipher->newKey( password, passwdLen );
  }

  return userKey;
}

// Doesn't use SecureMem, since we don't know how much will be read.
// Besides, password is being produced by another program.
std::string readPassword( int FD )
{
  SecureMem *buf = new SecureMem(1024);
  string result;

  while(1)
  {
    ssize_t rdSize = recv(FD, buf->data(), buf->size(), 0);

    if(rdSize > 0)
    {
      result.append( (char*)buf->data(), rdSize );
    } else
      break;
  }

  // chop off trailing "\n" if present..
  // This is done so that we can use standard programs like ssh-askpass
  // without modification, as it returns trailing newline..
  if(!result.empty() && result[ result.length()-1 ] == '\n' )
    result.resize( result.length() -1 );

  delete buf;
  return result;
}

SecureMem *passwordFromProgram(const std::string &passProg,
    const std::string &rootDir) 
{
  // have a child process run the command and get the result back to us.
  int fds[2], pid;
  int res;

  res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
  if(res == -1)
  {
    perror(_("Internal error: socketpair() failed"));
    return NULL;
  }
  VLOG(1) << "getUserKey: fds = " << fds[0] << ", " << fds[1];

  pid = fork();
  if(pid == -1)
  {
    perror(_("Internal error: fork() failed"));
    close(fds[0]);
    close(fds[1]);
    return NULL;
  }

  if(pid == 0)
  {
    const char *argv[4];
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = passProg.c_str();
    argv[3] = 0;

    // child process.. run the command and send output to fds[0]
    close(fds[1]); // we don't use the other half..

    // make a copy of stdout and stderr descriptors, and set an environment
    // variable telling where to find them, in case a child wants it..
    int stdOutCopy = dup( STDOUT_FILENO );
    int stdErrCopy = dup( STDERR_FILENO );
    // replace STDOUT with our socket, which we'll used to receive the
    // password..
    dup2( fds[0], STDOUT_FILENO );

    // ensure that STDOUT_FILENO and stdout/stderr are not closed on exec..
    fcntl(STDOUT_FILENO, F_SETFD, 0); // don't close on exec..
    fcntl(stdOutCopy, F_SETFD, 0);
    fcntl(stdErrCopy, F_SETFD, 0);

    char tmpBuf[8];

    setenv(ENCFS_ENV_ROOTDIR, rootDir.c_str(), 1);

    snprintf(tmpBuf, sizeof(tmpBuf)-1, "%i", stdOutCopy);
    setenv(ENCFS_ENV_STDOUT, tmpBuf, 1);

    snprintf(tmpBuf, sizeof(tmpBuf)-1, "%i", stdErrCopy);
    setenv(ENCFS_ENV_STDERR, tmpBuf, 1);

    execvp( argv[0], (char * const *)argv ); // returns only on error..

    perror(_("Internal error: failed to exec program"));
    exit(1);
  }

  close(fds[0]);
  string password = readPassword(fds[1]);
  close(fds[1]);

  waitpid(pid, NULL, 0);

  SecureMem *result = new SecureMem(password.length()+1);
  if (result)
    strncpy((char *)result->data(), password.c_str(), result->size());
  password.assign(password.length(), '\0');

  return result;
}

SecureMem *passwordFromStdin()
{
  SecureMem *buf = new SecureMem(MaxPassBuf);

  char *res = fgets( (char *)buf->data(), buf->size(), stdin );
  if (res)
  {
    // Kill the trailing newline.
    int last = strnlen((char *)buf->data(), buf->size());
    if (last > 0 && buf->data()[last-1] == '\n')
      buf->data()[ last-1 ] = '\0';
  }
  
  return buf;
}

SecureMem *passwordFromPrompt()
{
  SecureMem *buf = new SecureMem(MaxPassBuf);

  // xgroup(common)
  char *res = readpassphrase( _("EncFS Password: "),
      (char *)buf->data(), buf->size()-1, RPP_ECHO_OFF );
  if (!res) 
  {
    delete buf;
    buf = NULL;
  }
  
  return buf;
}

SecureMem *passwordFromPrompts()
{
  SecureMem *buf = new SecureMem(MaxPassBuf);
  SecureMem *buf2 = new SecureMem(MaxPassBuf);

  do
  {
    // xgroup(common)
    char *res1 = readpassphrase(_("New Encfs Password: "), 
        (char *)buf->data(), buf->size()-1, RPP_ECHO_OFF);
    // xgroup(common)
    char *res2 = readpassphrase(_("Verify Encfs Password: "), 
        (char *)buf2->data(), buf2->size()-1, RPP_ECHO_OFF);

    if(res1 && res2
       && !strncmp((char*)buf->data(), (char*)buf2->data(), MaxPassBuf))
    {
      break; 
    } else
    {
      // xgroup(common) -- probably not common, but group with the others
      cerr << _("Passwords did not match, please try again\n");
    }
  } while(1);

  delete buf2;
  return buf;
}

CipherKey getUserKey(const EncfsConfig &config, bool useStdin)
{
  CipherKey userKey;
  SecureMem *password;

  if (useStdin)
    password = passwordFromStdin();
  else
    password = passwordFromPrompt();

  if (password)
  {
    userKey = decryptKey(config, (char*)password->data(),
                         strlen((char*)password->data()));
    delete password;
  }

  return userKey;
}

CipherKey getUserKey( const EncfsConfig &config, const std::string &passProg,
    const std::string &rootDir )
{
  CipherKey result;
  SecureMem *password = passwordFromProgram(passProg, rootDir);

  if (password)
  {
    result = decryptKey(config, (char*)password->data(),
                        strlen((char*)password->data()));
    delete password;
  }

  return result;
}

CipherKey getNewUserKey(EncfsConfig &config,
    bool useStdin, const std::string &passProg,
    const std::string &rootDir)
{
  CipherKey result;
  SecureMem *password;

  if (useStdin)
    password = passwordFromStdin();
  else if (!passProg.empty())
    password = passwordFromProgram(passProg, rootDir);
  else
    password = passwordFromPrompts();

  if (password)
  {
    result = makeNewKey(config, (char*)password->data(),
                        strlen((char*)password->data()));
    delete password;
  }

  return result;
}

RootPtr initFS( EncFS_Context *ctx, const shared_ptr<EncFS_Opts> &opts )
{
  RootPtr rootInfo;
  EncfsConfig config;

  if(readConfig( opts->rootDir, config ) != Config_None)
  {
    if(opts->reverseEncryption)
    {
      if (config.block_mac_bytes() != 0 || config.block_mac_rand_bytes() != 0
          || config.unique_iv() || config.external_iv()
          || config.chained_iv() )
      {  
        cout << _("The configuration loaded is not compatible with --reverse\n");
        return rootInfo;
      }
    }

    // first, instanciate the cipher.
    shared_ptr<CipherV1> cipher = getCipher(config);
    if(!cipher)
    {
      Interface iface = config.cipher();
      LOG(ERROR) << "Unable to find cipher " << iface.name()
          << ", version " << iface.major()
          << ":" << iface.minor() << ":" << iface.age();
      // xgroup(diag)
      cout << _("The requested cipher interface is not available\n");
      return rootInfo;
    }

    // get user key
    CipherKey userKey;

    if(opts->passwordProgram.empty())
    {
      if (opts->annotate)
        cerr << "$PROMPT$ passwd" << endl;
      userKey = getUserKey( config, opts->useStdin );
    } else
      userKey = getUserKey( config, opts->passwordProgram, opts->rootDir );

    if(!userKey.valid())
      return rootInfo;

    cipher->setKey(userKey); 

    VLOG(1) << "cipher encoded key size = " << cipher->encodedKeySize();
    // decode volume key..
    CipherKey volumeKey = cipher->readKey(
        (const unsigned char *)config.key().ciphertext().data(), opts->checkKey);
    userKey.reset();

    if(!volumeKey.valid())
    {
      // xgroup(diag)
      cout << _("Error decoding volume key, password incorrect\n");
      return rootInfo;
    }

    cipher->setKey(volumeKey);

    shared_ptr<NameIO> nameCoder = NameIO::New( config.naming(), cipher );
    if(!nameCoder)
    {
      Interface iface = config.naming();
      LOG(ERROR) << "Unable to find nameio interface " << iface.name()
          << ", version " << iface.major()
          << ":" << iface.minor() << ":" << iface.age();
      // xgroup(diag)
      cout << _("The requested filename coding interface is "
          "not available\n");
      return rootInfo;
    }

    nameCoder->setChainedNameIV( config.chained_iv() );
    nameCoder->setReverseEncryption( opts->reverseEncryption );

    FSConfigPtr fsConfig( new FSConfig );
    fsConfig->cipher = cipher;
    fsConfig->key = volumeKey;
    fsConfig->nameCoding = nameCoder;
    fsConfig->config = shared_ptr<EncfsConfig>(new EncfsConfig(config));
    fsConfig->forceDecode = opts->forceDecode;
    fsConfig->reverseEncryption = opts->reverseEncryption;
    fsConfig->opts = opts;

    rootInfo = RootPtr( new EncFS_Root );
    rootInfo->cipher = cipher;
    rootInfo->volumeKey = volumeKey;
    rootInfo->root = shared_ptr<DirNode>( 
        new DirNode( ctx, opts->rootDir, fsConfig ));
  } else
  {
    if(opts->createIfNotFound)
    {
      // creating a new encrypted filesystem
      rootInfo = createConfig( ctx, opts );
    }
  }

  return rootInfo;
}

int remountFS(EncFS_Context *ctx)
{
  VLOG(1) << "Attempting to reinitialize filesystem";

  RootPtr rootInfo = initFS( ctx, ctx->opts );
  if(rootInfo)
  {
    ctx->setRoot(rootInfo->root);
    return 0;
  } else
  {
    LOG(WARNING) << "Remount failed";
    return -EACCES;
  }
}

}  // namespace encfs
