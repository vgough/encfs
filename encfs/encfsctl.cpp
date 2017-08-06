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

#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <limits.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#define NO_DES
#include <openssl/ssl.h>

#include "Cipher.h"
#include "CipherKey.h"
#include "DirNode.h"
#include "Error.h"
#include "FSConfig.h"
#include "FileNode.h"
#include "FileUtils.h"
#include "Interface.h"
#include "autosprintf.h"
#include "config.h"
#include "i18n.h"
#include "intl/gettext.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

using namespace std;
using gnu::autosprintf;
using namespace encfs;

static int showInfo(int argc, char **argv);
static int showVersion(int argc, char **argv);
static int chpasswd(int argc, char **argv);
static int chpasswdAutomaticly(int argc, char **argv);
static int ckpasswdAutomaticly(int argc, char **argv);
static int cmd_ls(int argc, char **argv);
static int cmd_decode(int argc, char **argv);
static int cmd_encode(int argc, char **argv);
static int cmd_showcruft(int argc, char **argv);
static int cmd_cat(int argc, char **argv);
static int cmd_export(int argc, char **argv);
static int cmd_showKey(int argc, char **argv);

struct CommandOpts {
  const char *name;
  int minOptions;
  int maxOptions;
  int (*func)(int argc, char **argv);
  const char *argStr;
  const char *usageStr;
} commands[] = {
    {"info", 1, 1, showInfo, "(root dir)",
     // xgroup(usage)
     gettext_noop("  -- show information (Default command)")},
    {"showKey", 1, 1, cmd_showKey, "(root dir)",
     // xgroup(usage)
     gettext_noop("  -- show key")},
    {"passwd", 1, 1, chpasswd, "(root dir)",
     // xgroup(usage)
     gettext_noop("  -- change password for volume")},
    {"autopasswd", 1, 1, chpasswdAutomaticly, "(root dir)",
     // xgroup(usage)
     gettext_noop("  -- change password for volume, taking password"
                  " from standard input.\n\tNo prompts are issued.")},
    {"autocheckpasswd", 1, 1, ckpasswdAutomaticly, "(root dir)",
     // xgroup(usage)
     gettext_noop("  -- check password for volume, taking password"
                  " from standard input.\n\tNo prompts are issued.")},
    {"ls", 1, 2, cmd_ls, 0, 0},
    {"showcruft", 1, 1, cmd_showcruft, "(root dir)",
     // xgroup(usage)
     gettext_noop("  -- show undecodable filenames in the volume")},
    {"cat", 2, 3, cmd_cat, "[--extpass=prog] (root dir) path",
     // xgroup(usage)
     gettext_noop("  -- decodes the file and cats it to standard out")},
    {"decode", 1, 100, cmd_decode,
     "[--extpass=prog] (root dir) [encoded-name ...]",
     // xgroup(usage)
     gettext_noop("  -- decodes name and prints plaintext version")},
    {"encode", 1, 100, cmd_encode,
     "[--extpass=prog] (root dir) [plaintext-name ...]",
     // xgroup(usage)
     gettext_noop("  -- encodes a filename and print result")},
    {"export", 2, 2, cmd_export, "(root dir) path",
     // xgroup(usage)
     gettext_noop("  -- decrypts a volume and writes results to path")},
    {"--version", 0, 0, showVersion, "",
     // xgroup(usage)
     gettext_noop("  -- print version number and exit")},
    {0, 0, 0, 0, 0, 0}};

static void usage(const char *name) {
  cerr << autosprintf(_("encfsctl version %s"), VERSION) << "\n"
       << _("Usage:\n")
       // displays usage commands, eg "./encfs (root dir) ..."
       // xgroup(usage)
       << autosprintf(
              _("%s (root dir)\n"
                "  -- displays information about the filesystem, or \n"),
              name);

  int offset = 0;
  while (commands[offset].name != 0) {
    if (commands[offset].argStr != 0) {
      cerr << "encfsctl " << commands[offset].name << " "
           << commands[offset].argStr << "\n"
           << gettext(commands[offset].usageStr) << "\n";
    }
    ++offset;
  }

  cerr << "\n"
       // xgroup(usage)
       << autosprintf(_("Example: \n%s info ~/.crypt\n"), name) << "\n";
}

static bool checkDir(string &rootDir) {
  if (!isDirectory(rootDir.c_str())) {
    cerr << autosprintf(_("directory %s does not exist.\n"), rootDir.c_str());
    return false;
  }
  if (rootDir[rootDir.length() - 1] != '/') rootDir.append("/");

  return true;
}

static int showVersion(int argc, char **argv) {
  (void)argc;
  (void)argv;
  // xgroup(usage)
  cerr << autosprintf(_("encfsctl version %s"), VERSION) << "\n";

  return EXIT_SUCCESS;
}

static int showInfo(int argc, char **argv) {
  (void)argc;
  string rootDir = argv[1];
  if (!checkDir(rootDir)) return EXIT_FAILURE;

  std::shared_ptr<EncFSConfig> config(new EncFSConfig);
  ConfigType type = readConfig(rootDir, config.get());

  // show information stored in config..
  switch (type) {
    case Config_None:
      // xgroup(diag)
      cout << _("Unable to load or parse config file\n");
      return EXIT_FAILURE;
    case Config_Prehistoric:
      // xgroup(diag)
      cout << _(
          "A really old EncFS filesystem was found. \n"
          "It is not supported in this EncFS build.\n");
      return EXIT_FAILURE;
    case Config_V3:
      // xgroup(diag)
      cout << "\n"
           << autosprintf(_("Version 3 configuration; "
                            "created by %s\n"),
                          config->creator.c_str());
      break;
    case Config_V4:
      // xgroup(diag)
      cout << "\n"
           << autosprintf(_("Version 4 configuration; "
                            "created by %s\n"),
                          config->creator.c_str());
      break;
    case Config_V5:
      // xgroup(diag)
      cout << "\n"
           << autosprintf(_("Version 5 configuration; "
                            "created by %s (revision %i)\n"),
                          config->creator.c_str(), config->subVersion);
      break;
    case Config_V6:
      // xgroup(diag)
      cout << "\n"
           << autosprintf(_("Version 6 configuration; "
                            "created by %s (revision %i)\n"),
                          config->creator.c_str(), config->subVersion);
      break;
  }

  showFSInfo(config.get());

  return EXIT_SUCCESS;
}

static RootPtr initRootInfo(int &argc, char **&argv) {
  RootPtr result;
  std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
  opts->createIfNotFound = false;
  opts->checkKey = false;

  static struct option long_options[] = {{"extpass", 1, 0, 'p'}, {0, 0, 0, 0}};

  for (;;) {
    int option_index = 0;

    int res = getopt_long(argc, argv, "", long_options, &option_index);
    if (res == -1) break;

    switch (res) {
      case 'p':
        opts->passwordProgram.assign(optarg);
        break;
      default:
        RLOG(WARNING) << "getopt error: " << res;
        break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc == 0) {
    cerr << _("Incorrect number of arguments") << "\n";
  } else {
    opts->rootDir = string(argv[0]);

    --argc;
    ++argv;

    if (checkDir(opts->rootDir)) result = initFS(NULL, opts);

    if (!result)
      cerr << _("Unable to initialize encrypted filesystem - check path.\n");
  }

  return result;
}

static RootPtr initRootInfo(const char *crootDir) {
  string rootDir(crootDir);
  RootPtr result;

  if (checkDir(rootDir)) {
    std::shared_ptr<EncFS_Opts> opts(new EncFS_Opts());
    opts->rootDir = rootDir;
    opts->createIfNotFound = false;
    opts->checkKey = false;
    result = initFS(NULL, opts);
  }

  if (!result)
    cerr << _("Unable to initialize encrypted filesystem - check path.\n");

  return result;
}

static int cmd_showKey(int argc, char **argv) {
  (void)argc;
  RootPtr rootInfo = initRootInfo(argv[1]);

  if (!rootInfo)
    return EXIT_FAILURE;
  else {
    // encode with itself
    string b64Key = rootInfo->cipher->encodeAsString(rootInfo->volumeKey,
                                                     rootInfo->volumeKey);

    cout << b64Key << "\n";

    return EXIT_SUCCESS;
  }
}

static int cmd_decode(int argc, char **argv) {
  RootPtr rootInfo = initRootInfo(argc, argv);
  if (!rootInfo) return EXIT_FAILURE;

  if (argc > 0) {
    for (int i = 0; i < argc; ++i) {
      string name = rootInfo->root->plainPath(argv[i]);
      cout << name << "\n";
    }
  } else {
    char buf[PATH_MAX + 1];
    while (cin.getline(buf, PATH_MAX)) {
      cout << rootInfo->root->plainPath(buf) << "\n";
    }
  }
  return EXIT_SUCCESS;
}

static int cmd_encode(int argc, char **argv) {
  RootPtr rootInfo = initRootInfo(argc, argv);
  if (!rootInfo) return EXIT_FAILURE;

  if (argc > 0) {
    for (int i = 0; i < argc; ++i) {
      string name = rootInfo->root->cipherPathWithoutRoot(argv[i]);
      cout << name << "\n";
    }
  } else {
    char buf[PATH_MAX + 1];
    while (cin.getline(buf, PATH_MAX)) {
      cout << rootInfo->root->cipherPathWithoutRoot(buf) << "\n";
    }
  }
  return EXIT_SUCCESS;
}

static int cmd_ls(int argc, char **argv) {
  (void)argc;

  RootPtr rootInfo = initRootInfo(argv[1]);

  if (!rootInfo) return EXIT_FAILURE;

  // show files in directory
  {
    DirTraverse dt = rootInfo->root->openDir("/");
    if (dt.valid()) {
      for (string name = dt.nextPlaintextName(); !name.empty();
           name = dt.nextPlaintextName()) {
        std::shared_ptr<FileNode> fnode =
            rootInfo->root->lookupNode(name.c_str(), "encfsctl-ls");
        struct stat stbuf;
        fnode->getAttr(&stbuf);

        struct tm stm;
        localtime_r(&stbuf.st_mtime, &stm);
        stm.tm_year += 1900;
        // TODO: when I add "%s" to the end and name.c_str(), I get a
        // seg fault from within strlen.  Why ???
        printf("%11i %4i-%02i-%02i %02i:%02i:%02i %s\n", int(stbuf.st_size),
               int(stm.tm_year), int(stm.tm_mon), int(stm.tm_mday),
               int(stm.tm_hour), int(stm.tm_min), int(stm.tm_sec),
               name.c_str());
      }
    }
  }

  return EXIT_SUCCESS;
}

// apply an operation to every block in the file
template <typename T>
int processContents(const std::shared_ptr<EncFS_Root> &rootInfo,
                    const char *path, T &op) {
  int errCode = 0;
  std::shared_ptr<FileNode> node =
      rootInfo->root->openNode(path, "encfsctl", O_RDONLY, &errCode);

  if (!node) {
    // try treating filename as an enciphered path
    string plainName = rootInfo->root->plainPath(path);
    node = rootInfo->root->lookupNode(plainName.c_str(), "encfsctl");
    if (node) {
      errCode = node->open(O_RDONLY);
      if (errCode < 0) node.reset();
    }
  }

  if (!node) {
    cerr << "unable to open " << path << "\n";
    return errCode;
  } else {
    unsigned char buf[512];
    int blocks = (node->getSize() + sizeof(buf) - 1) / sizeof(buf);
    // read all the data in blocks
    for (int i = 0; i < blocks; ++i) {
      int bytes = node->read(i * sizeof(buf), buf, sizeof(buf));
      int res = op(buf, bytes);
      if (res < 0) return res;
    }
  }
  return 0;
}

class WriteOutput {
  int _fd;

 public:
  WriteOutput(int fd) { _fd = fd; }
  ~WriteOutput() { close(_fd); }

  int operator()(const void *buf, int count) {
    return (int)write(_fd, buf, count);
  }
};

static int cmd_cat(int argc, char **argv) {
  RootPtr rootInfo = initRootInfo(argc, argv);

  if (!rootInfo) return EXIT_FAILURE;

  const char *path = argv[0];
  WriteOutput output(STDOUT_FILENO);
  int errCode = processContents(rootInfo, path, output);

  return errCode;
}

static int copyLink(const struct stat &stBuf,
                    const std::shared_ptr<EncFS_Root> &rootInfo,
                    const string &cpath, const string &destName) {
  std::vector<char> buf(stBuf.st_size + 1, '\0');
  int res = ::readlink(cpath.c_str(), buf.data(), stBuf.st_size);
  if (res == -1) {
    cerr << "unable to readlink of " << cpath << "\n";
    return EXIT_FAILURE;
  }

  buf[res] = '\0';
  string decodedLink = rootInfo->root->plainPath(buf.data());

  res = ::symlink(decodedLink.c_str(), destName.c_str());
  if (res == -1) {
    cerr << "unable to create symlink for " << cpath << " to " << decodedLink
         << "\n";
  }

  return EXIT_SUCCESS;
}

static int copyContents(const std::shared_ptr<EncFS_Root> &rootInfo,
                        const char *encfsName, const char *targetName) {
  std::shared_ptr<FileNode> node =
      rootInfo->root->lookupNode(encfsName, "encfsctl");

  if (!node) {
    cerr << "unable to open " << encfsName << "\n";
    return EXIT_FAILURE;
  } else {
    struct stat st;

    if (node->getAttr(&st) != 0) return EXIT_FAILURE;

    if ((st.st_mode & S_IFMT) == S_IFLNK) {
      string d = rootInfo->root->cipherPath(encfsName);
      char linkContents[PATH_MAX + 2];

      if (readlink(d.c_str(), linkContents, PATH_MAX + 1) <= 0) {
        cerr << "unable to read link " << encfsName << "\n";
        return EXIT_FAILURE;
      }
      if (symlink(rootInfo->root->plainPath(linkContents).c_str(),
                  targetName) != 0) {
        cerr << "unable to create symlink " << targetName << "\n";
        return EXIT_FAILURE;
      }
    } else {
      int outfd = creat(targetName, st.st_mode);

      WriteOutput output(outfd);
      processContents(rootInfo, encfsName, output);
    }
  }
  return EXIT_SUCCESS;
}

static bool endsWith(const string &str, char ch) {
  if (str.empty())
    return false;
  else
    return str[str.length() - 1] == ch;
}

static int traverseDirs(const std::shared_ptr<EncFS_Root> &rootInfo,
                        string volumeDir, string destDir) {
  if (!endsWith(volumeDir, '/')) volumeDir.append("/");
  if (!endsWith(destDir, '/')) destDir.append("/");

  // Lookup directory node so we can create a destination directory
  // with the same permissions
  {
    struct stat st;
    std::shared_ptr<FileNode> dirNode =
        rootInfo->root->lookupNode(volumeDir.c_str(), "encfsctl");
    if (dirNode->getAttr(&st)) return EXIT_FAILURE;

    mkdir(destDir.c_str(), st.st_mode);
  }

  // show files in directory
  DirTraverse dt = rootInfo->root->openDir(volumeDir.c_str());
  if (dt.valid()) {
    for (string name = dt.nextPlaintextName(); !name.empty();
         name = dt.nextPlaintextName()) {
      // Recurse to subdirectories
      if (name != "." && name != "..") {
        string plainPath = volumeDir + name;
        string cpath = rootInfo->root->cipherPath(plainPath.c_str());
        string destName = destDir + name;

        int r = EXIT_SUCCESS;
        struct stat stBuf;
        if (!lstat(cpath.c_str(), &stBuf)) {
          if (S_ISDIR(stBuf.st_mode)) {
            traverseDirs(rootInfo, (plainPath + '/').c_str(), destName + '/');
          } else if (S_ISLNK(stBuf.st_mode)) {
            r = copyLink(stBuf, rootInfo, cpath, destName);
          } else {
            r = copyContents(rootInfo, plainPath.c_str(), destName.c_str());
          }
        } else {
          r = EXIT_FAILURE;
        }

        if (r != EXIT_SUCCESS) return r;
      }
    }
  }
  return EXIT_SUCCESS;
}

static int cmd_export(int argc, char **argv) {
  (void)argc;

  RootPtr rootInfo = initRootInfo(argv[1]);

  if (!rootInfo) return EXIT_FAILURE;

  string destDir = argv[2];
  // if the dir doesn't exist, then create it (with user permission)
  if (!checkDir(destDir) && !userAllowMkdir(destDir.c_str(), 0700))
    return EXIT_FAILURE;

  return traverseDirs(rootInfo, "/", destDir);
}

int showcruft(const std::shared_ptr<EncFS_Root> &rootInfo,
              const char *dirName) {
  int found = 0;
  DirTraverse dt = rootInfo->root->openDir(dirName);
  if (dt.valid()) {
    bool showedDir = false;
    for (string name = dt.nextInvalid(); !name.empty();
         name = dt.nextInvalid()) {
      string cpath = rootInfo->root->cipherPath(dirName);
      cpath += '/';
      cpath += name;

      if (!showedDir) {
        // just before showing a list of files in a directory
        cout << autosprintf(_("In directory %s: \n"), dirName);
        showedDir = true;
      }
      ++found;
      cout << cpath << "\n";
    }

    // now go back and look for directories to recurse into..
    dt = rootInfo->root->openDir(dirName);
    if (dt.valid()) {
      for (string name = dt.nextPlaintextName(); !name.empty();
           name = dt.nextPlaintextName()) {
        if (name == "." || name == "..") continue;

        string plainPath = dirName;
        plainPath += '/';
        plainPath += name;

        string cpath = rootInfo->root->cipherPath(plainPath.c_str());

        if (isDirectory(cpath.c_str()))
          found += showcruft(rootInfo, plainPath.c_str());
      }
    }
  }

  return found;
}

/*
    iterate recursively through the filesystem and print out names of files
    which have filenames which cannot be decoded with the given key..
*/
static int cmd_showcruft(int argc, char **argv) {
  (void)argc;

  RootPtr rootInfo = initRootInfo(argv[1]);

  if (!rootInfo) return EXIT_FAILURE;

  int filesFound = showcruft(rootInfo, "/");

  // TODO: the singular version should say "Found an invalid file", but all the
  // translations
  // depend upon this broken singular form, so it isn't easy to change.
  cerr << autosprintf(ngettext("Found %i invalid file.",
                               "Found %i invalid files.", filesFound),
                      filesFound)
       << "\n";

  return EXIT_SUCCESS;
}

static int do_chpasswd(bool useStdin, bool annotate, bool checkOnly, int argc,
                       char **argv) {
  (void)argc;
  string rootDir = argv[1];
  if (!checkDir(rootDir)) return EXIT_FAILURE;

  EncFSConfig *config = new EncFSConfig;
  ConfigType cfgType = readConfig(rootDir, config);

  if (cfgType == Config_None) {
    cout << _("Unable to load or parse config file\n");
    return EXIT_FAILURE;
  }

  // instanciate proper cipher
  std::shared_ptr<Cipher> cipher =
      Cipher::New(config->cipherIface, config->keySize);
  if (!cipher) {
    cout << autosprintf(_("Unable to find specified cipher \"%s\"\n"),
                        config->cipherIface.name().c_str());
    return EXIT_FAILURE;
  }

  // ask for existing password
  cout << _("Enter current Encfs password\n");
  if (annotate) cerr << "$PROMPT$ passwd" << endl;
  CipherKey userKey = config->getUserKey(useStdin);
  if (!userKey) return EXIT_FAILURE;

  // decode volume key using user key -- at this point we detect an incorrect
  // password if the key checksum does not match (causing readKey to fail).
  CipherKey volumeKey = cipher->readKey(config->getKeyData(), userKey);

  if (!volumeKey) {
    cout << _("Invalid password\n");
    return EXIT_FAILURE;
  }

  if (checkOnly) {
    cout << _("Password is correct\n");
    return EXIT_SUCCESS;
  }

  // Now, get New user key..
  userKey.reset();
  cout << _("Enter new Encfs password\n");
  // reinitialize salt and iteration count
  config->kdfIterations = 0;  // generate new

  if (useStdin) {
    if (annotate) cerr << "$PROMPT$ new_passwd" << endl;
    userKey = config->getUserKey(true);
  } else
    userKey = config->getNewUserKey();

  // re-encode the volume key using the new user key and write it out..
  int result = EXIT_FAILURE;
  if (userKey) {
    int encodedKeySize = cipher->encodedKeySize();
    unsigned char *keyBuf = new unsigned char[encodedKeySize];

    // encode volume key with new user key
    cipher->writeKey(volumeKey, keyBuf, userKey);
    userKey.reset();

    config->assignKeyData(keyBuf, encodedKeySize);
    delete[] keyBuf;

    if (saveConfig(cfgType, rootDir, config)) {
      // password modified -- changes volume key of filesystem..
      cout << _("Volume Key successfully updated.\n");
      result = EXIT_SUCCESS;
    } else {
      cout << _("Error saving modified config file.\n");
    }
  } else {
    cout << _("Error creating key\n");
  }

  volumeKey.reset();

  return result;
}

static int chpasswd(int argc, char **argv) {
  return do_chpasswd(false, false, false, argc, argv);
}

static int chpasswdAutomaticly(int argc, char **argv) {
  return do_chpasswd(true, false, false, argc, argv);
}

static int ckpasswdAutomaticly(int argc, char **argv) {
  return do_chpasswd(true, false, true, argc, argv);
}

int main(int argc, char **argv) {
  START_EASYLOGGINGPP(argc, argv);
  encfs::initLogging();

#if defined(ENABLE_NLS) && defined(LOCALEDIR)
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  SSL_load_error_strings();
  SSL_library_init();

  if (argc < 2) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  // Skip over uninteresting args.
  while (argc > 2 && *argv[1] == '-') {
    VLOG(1) << "skipping arg " << argv[1];
    argc--;
    argv[1] = argv[0];
    argv++;
  }

  if (argc == 2 && !(*argv[1] == '-' && *(argv[1] + 1) == '-')) {
    // default command when only 1 argument given -- treat the argument as
    // a directory..
    return showInfo(argc, argv);
  } else {
    // find the specified command
    int offset = 0;
    while (commands[offset].name != 0) {
      if (!strcmp(argv[1], commands[offset].name)) break;
      ++offset;
    }

    if (commands[offset].name == 0) {
      cerr << autosprintf(_("invalid command: \"%s\""), argv[1]) << "\n";
    } else {
      if ((argc - 2 < commands[offset].minOptions) ||
          (argc - 2 > commands[offset].maxOptions)) {
        cerr << autosprintf(
                    _("Incorrect number of arguments for command \"%s\""),
                    argv[1])
             << "\n";
      } else
        return (*commands[offset].func)(argc - 1, argv + 1);
    }
  }

  return EXIT_FAILURE;
}
