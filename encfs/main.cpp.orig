/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2004, Valient Gough
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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <pthread.h>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "Context.h"
#include "Error.h"
#include "FileUtils.h"
#include "MemoryPool.h"
#include "autosprintf.h"
#include "config.h"
#include "encfs.h"
#include "fuse.h"
#include "i18n.h"
#include "openssl.h"

// Fuse version >= 26 requires another argument to fuse_unmount, which we
// don't have.  So use the backward compatible call instead..
extern "C" void fuse_unmount_compat22(const char *mountpoint);
#define fuse_unmount fuse_unmount_compat22

/* Arbitrary identifiers for long options that do
 * not have a short version */
#define LONG_OPT_ANNOTATE 513
#define LONG_OPT_NOCACHE 514
#define LONG_OPT_REQUIRE_MAC 515

using namespace std;
using namespace encfs;
using gnu::autosprintf;

INITIALIZE_EASYLOGGINGPP

namespace encfs {

class DirNode;

// Maximum number of arguments that we're going to pass on to fuse.  Doesn't
// affect how many arguments we can handle, just how many we can pass on..
const int MaxFuseArgs = 32;
/**
 * EncFS_Args stores the parsed command-line arguments
 *
 * See also: struct EncFS_Opts (FileUtils.h), stores internal settings that are
 * derived from the arguments
 */
struct EncFS_Args {
  bool isDaemon;    // true == spawn in background, log to syslog
  bool isThreaded;  // true == threaded
  bool isVerbose;   // false == only enable warning/error messages
  int idleTimeout;  // 0 == idle time in minutes to trigger unmount
  const char *fuseArgv[MaxFuseArgs];
  int fuseArgc;

  std::shared_ptr<EncFS_Opts> opts;

  // for debugging
  // In case someone sends me a log dump, I want to know how what options are
  // in effect.  Not internationalized, since it is something that is mostly
  // useful for me!
  string toString() {
    ostringstream ss;
    ss << (isDaemon ? "(daemon) " : "(fg) ");
    ss << (isThreaded ? "(threaded) " : "(UP) ");
    if (idleTimeout > 0) ss << "(timeout " << idleTimeout << ") ";
    if (opts->checkKey) ss << "(keyCheck) ";
    if (opts->forceDecode) ss << "(forceDecode) ";
    if (opts->ownerCreate) ss << "(ownerCreate) ";
    if (opts->useStdin) ss << "(useStdin) ";
    if (opts->annotate) ss << "(annotate) ";
    if (opts->reverseEncryption) ss << "(reverseEncryption) ";
    if (opts->mountOnDemand) ss << "(mountOnDemand) ";
    if (opts->delayMount) ss << "(delayMount) ";
    for (int i = 0; i < fuseArgc; ++i) ss << fuseArgv[i] << ' ';

    return ss.str();
  }

  EncFS_Args() : opts(new EncFS_Opts()) {}
};

static int oldStderr = STDERR_FILENO;

}  // namespace encfs

static void usage(const char *name) {
  // xgroup(usage)
  cerr << autosprintf(_("Build: encfs version %s"), VERSION) << "\n\n"
       // xgroup(usage)
       << autosprintf(
              _("Usage: %s [options] rootDir mountPoint [-- [FUSE Mount "
                "Options]]"),
              name)
       << "\n\n"
       // xgroup(usage)
       << _("Common Options:\n"
            "  -H\t\t\t"
            "show optional FUSE Mount Options\n"
            "  -s\t\t\t"
            "disable multithreaded operation\n"
            "  -f\t\t\t"
            "run in foreground (don't spawn daemon).\n"
            "\t\t\tError messages will be sent to stderr\n"
            "\t\t\tinstead of syslog.\n")

       // xgroup(usage)
       << _("  -v, --verbose\t\t"
            "verbose: output encfs debug messages\n"
            "  -i, --idle=MINUTES\t"
            "Auto unmount after period of inactivity\n"
            "  --anykey\t\t"
            "Do not verify correct key is being used\n"
            "  --forcedecode\t\t"
            "decode data even if an error is detected\n"
            "\t\t\t(for filesystems using MAC block headers)\n")
       << _("  --public\t\t"
            "act as a typical multi-user filesystem\n"
            "\t\t\t(encfs must be run as root)\n")
       << _("  --reverse\t\t"
            "reverse encryption\n")

       // xgroup(usage)
       << _("  --extpass=program\tUse external program for password prompt\n"
            "\n"
            "Example, to mount at ~/crypt with raw storage in ~/.crypt :\n"
            "    encfs ~/.crypt ~/crypt\n"
            "\n")
       // xgroup(usage)
       << _("For more information, see the man page encfs(1)") << "\n"
       << endl;
}

static void FuseUsage() {
  // xgroup(usage)
  cerr << _("encfs [options] rootDir mountPoint -- [FUSE Mount Options]\n"
            "valid FUSE Mount Options follow:\n")
       << endl;

  int argc = 2;
  const char *argv[] = {"...", "-h"};
  fuse_main(argc, const_cast<char **>(argv), (fuse_operations *)NULL, NULL);
}

#define PUSHARG(ARG)                        \
  do {                                      \
    rAssert(out->fuseArgc < MaxFuseArgs);   \
    out->fuseArgv[out->fuseArgc++] = (ARG); \
  } while (0)

static string slashTerminate(const string &src) {
  string result = src;
  if (result[result.length() - 1] != '/') result.append("/");
  return result;
}

static bool processArgs(int argc, char *argv[],
                        const std::shared_ptr<EncFS_Args> &out) {
  // set defaults
  out->isDaemon = true;
  out->isThreaded = true;
  out->isVerbose = false;
  out->idleTimeout = 0;
  out->fuseArgc = 0;
  out->opts->idleTracking = false;
  out->opts->checkKey = true;
  out->opts->forceDecode = false;
  out->opts->ownerCreate = false;
  out->opts->useStdin = false;
  out->opts->annotate = false;
  out->opts->reverseEncryption = false;
  out->opts->requireMac = false;

  bool useDefaultFlags = true;

  // pass executable name through
  out->fuseArgv[0] = lastPathElement(argv[0]);
  ++out->fuseArgc;

  // leave a space for mount point, as FUSE expects the mount point before
  // any flags
  out->fuseArgv[1] = NULL;
  ++out->fuseArgc;

  // TODO: can flags be internationalized?
  static struct option long_options[] = {
      {"fuse-debug", 0, 0, 'd'},   // Fuse debug mode
      {"forcedecode", 0, 0, 'D'},  // force decode
      // {"foreground", 0, 0, 'f'}, // foreground mode (no daemon)
      {"fuse-help", 0, 0, 'H'},         // fuse_mount usage
      {"idle", 1, 0, 'i'},              // idle timeout
      {"anykey", 0, 0, 'k'},            // skip key checks
      {"no-default-flags", 0, 0, 'N'},  // don't use default fuse flags
      {"ondemand", 0, 0, 'm'},          // mount on-demand
      {"delaymount", 0, 0, 'M'},        // delay initial mount until use
      {"public", 0, 0, 'P'},            // public mode
      {"extpass", 1, 0, 'p'},           // external password program
      // {"single-thread", 0, 0, 's'},  // single-threaded mode
      {"stdinpass", 0, 0, 'S'},  // read password from stdin
      {"annotate", 0, 0,
       LONG_OPT_ANNOTATE},                  // Print annotation lines to stderr
      {"nocache", 0, 0, LONG_OPT_NOCACHE},  // disable caching
      {"verbose", 0, 0, 'v'},               // verbose mode
      {"version", 0, 0, 'V'},               // version
      {"reverse", 0, 0, 'r'},               // reverse encryption
      {"standard", 0, 0, '1'},              // standard configuration
      {"paranoia", 0, 0, '2'},              // standard configuration
      {"require-macs", 0, 0, LONG_OPT_REQUIRE_MAC},  // require MACs
      {0, 0, 0, 0}};

  while (1) {
    int option_index = 0;

    // 's' : single-threaded mode
    // 'f' : foreground mode
    // 'v' : verbose mode (same as --verbose)
    // 'd' : fuse debug mode (same as --fusedebug)
    // 'i' : idle-timeout, takes argument
    // 'm' : mount-on-demand
    // 'S' : password from stdin
    // 'o' : arguments meant for fuse
    int res =
        getopt_long(argc, argv, "HsSfvdmi:o:", long_options, &option_index);

    if (res == -1) break;

    switch (res) {
      case '1':
        out->opts->configMode = Config_Standard;
        break;
      case '2':
        out->opts->configMode = Config_Paranoia;
        break;
      case 's':
        out->isThreaded = false;
        break;
      case 'S':
        out->opts->useStdin = true;
        break;
      case LONG_OPT_ANNOTATE:
        out->opts->annotate = true;
        break;
      case LONG_OPT_REQUIRE_MAC:
        out->opts->requireMac = true;
        break;
      case 'f':
        out->isDaemon = false;
        // this option was added in fuse 2.x
        PUSHARG("-f");
        break;
      case 'v':
        out->isVerbose = true;
        break;
      case 'd':
        PUSHARG("-d");
        break;
      case 'i':
        out->idleTimeout = strtol(optarg, (char **)NULL, 10);
        out->opts->idleTracking = true;
        break;
      case 'k':
        out->opts->checkKey = false;
        break;
      case 'D':
        out->opts->forceDecode = true;
        break;
      case 'r':
        out->opts->reverseEncryption = true;
        /* Reverse encryption does not support writing unless uniqueIV
         * is disabled (expert mode) */
        out->opts->readOnly = true;
        /* By default, the kernel caches file metadata for one second.
         * This is fine for EncFS' normal mode, but for --reverse, this
         * means that the encrypted view will be up to one second out of
         * date.
         * Quoting Goswin von Brederlow:
         * "Caching only works correctly if you implement a disk based
         * filesystem, one where only the fuse process can alter
         * metadata and all access goes only through fuse. Any overlay
         * filesystem where something can change the underlying
         * filesystem without going through fuse can run into
         * inconsistencies."
         * However, disabling the caches causes a factor 3
         * slowdown. If you are concerned about inconsistencies,
         * please use --nocache. */
        break;
      case LONG_OPT_NOCACHE:
        /* Disable EncFS block cache
         * Causes reverse grow tests to fail because short reads
         * are returned */
        out->opts->noCache = true;
        /* Disable kernel stat() cache
         * Causes reverse grow tests to fail because stale stat() data
         * is returned */
        PUSHARG("-oattr_timeout=0");
        /* Disable kernel dentry cache
         * Fallout unknown, disabling for safety */
        PUSHARG("-oentry_timeout=0");
        break;
      case 'm':
        out->opts->mountOnDemand = true;
        break;
      case 'M':
        out->opts->delayMount = true;
        break;
      case 'N':
        useDefaultFlags = false;
        break;
      case 'o':
        PUSHARG("-o");
        PUSHARG(optarg);
        break;
      case 'p':
        out->opts->passwordProgram.assign(optarg);
        break;
      case 'P':
        if (geteuid() != 0)
          RLOG(WARNING) << "option '--public' ignored for non-root user";
        else {
          out->opts->ownerCreate = true;
          // add 'allow_other' option
          // add 'default_permissions' option (default)
          PUSHARG("-o");
          PUSHARG("allow_other");
        }
        break;
      case 'V':
        // xgroup(usage)
        cerr << autosprintf(_("encfs version %s"), VERSION) << endl;
        exit(EXIT_SUCCESS);
        break;
      case 'H':
        FuseUsage();
        exit(EXIT_SUCCESS);
        break;
      case '?':
        // invalid options..
        break;
      case ':':
        // missing parameter for option..
        break;
      default:
        RLOG(WARNING) << "getopt error: " << res;
        break;
    }
  }

  if (!out->isThreaded) PUSHARG("-s");

  // we should have at least 2 arguments left over - the source directory and
  // the mount point.
  if (optind + 2 <= argc) {
    // both rootDir and mountPoint are assumed to be slash terminated in the
    // rest of the code.
    out->opts->rootDir = slashTerminate(argv[optind++]);
    out->opts->mountPoint = slashTerminate(argv[optind++]);
  } else {
    // no mount point specified
    cerr << _("Missing one or more arguments, aborting.");
    return false;
  }

  // If there are still extra unparsed arguments, pass them onto FUSE..
  if (optind < argc) {
    rAssert(out->fuseArgc < MaxFuseArgs);

    while (optind < argc) {
      rAssert(out->fuseArgc < MaxFuseArgs);
      out->fuseArgv[out->fuseArgc++] = argv[optind];
      ++optind;
    }
  }

  // Add default flags unless --no-default-flags was passed
  if (useDefaultFlags) {

    // Expose the underlying stable inode number
    PUSHARG("-o");
    PUSHARG("use_ino");

    // "default_permissions" comes with a performance cost, and only makes
    // sense if "allow_other"" is used.
    // But it works around the issues "open_readonly_workaround" causes,
    // so enable it unconditionally.
    // See https://github.com/vgough/encfs/issues/181 and
    // https://github.com/vgough/encfs/issues/112 for more info.
    PUSHARG("-o");
    PUSHARG("default_permissions");

#if defined(__APPLE__)
    // With OSXFuse, the 'local' flag selects a local filesystem mount icon in
    // Finder.
    PUSHARG("-o");
    PUSHARG("local");
#endif
  }

  // sanity check
  if (out->isDaemon && (!isAbsolutePath(out->opts->mountPoint.c_str()) ||
                        !isAbsolutePath(out->opts->rootDir.c_str()))) {
    cerr <<
        // xgroup(usage)
        _("When specifying daemon mode, you must use absolute paths "
          "(beginning with '/')")
         << endl;
    return false;
  }

  // the raw directory may not be a subdirectory of the mount point.
  {
    string testMountPoint = out->opts->mountPoint;
    string testRootDir = out->opts->rootDir.substr(0, testMountPoint.length());

    if (testMountPoint == testRootDir) {
      cerr <<
          // xgroup(usage)
          _("The raw directory may not be a subdirectory of the "
            "mount point.")
           << endl;
      return false;
    }
  }

  if (out->opts->delayMount && !out->opts->mountOnDemand) {
    cerr <<
        // xgroup(usage)
        _("You must use mount-on-demand with delay-mount") << endl;
    return false;
  }

  if (out->opts->mountOnDemand && out->opts->passwordProgram.empty()) {
    cerr <<
        // xgroup(usage)
        _("Must set password program when using mount-on-demand") << endl;
    return false;
  }

  // check that the directories exist, or that we can create them..
  if (!isDirectory(out->opts->rootDir.c_str()) &&
      !userAllowMkdir(out->opts->annotate ? 1 : 0, out->opts->rootDir.c_str(),
                      0700)) {
    cerr << _("Unable to locate root directory, aborting.");
    return false;
  }
  if (!isDirectory(out->opts->mountPoint.c_str()) &&
      !userAllowMkdir(out->opts->annotate ? 2 : 0,
                      out->opts->mountPoint.c_str(), 0700)) {
    cerr << _("Unable to locate mount point, aborting.");
    return false;
  }

  // fill in mount path for fuse
  out->fuseArgv[1] = out->opts->mountPoint.c_str();

  return true;
}

static void *idleMonitor(void *);

void *encfs_init(fuse_conn_info *conn) {
  EncFS_Context *ctx = (EncFS_Context *)fuse_get_context()->private_data;

  // set fuse connection options
  conn->async_read = true;

  if (ctx->args->isDaemon) {
    // Switch to using syslog.
    encfs::rlogAction = el::base::DispatchAction::SysLog;
  }

  // if an idle timeout is specified, then setup a thread to monitor the
  // filesystem.
  if (ctx->args->idleTimeout > 0) {
    VLOG(1) << "starting idle monitoring thread";
    ctx->running = true;

    int res = pthread_create(&ctx->monitorThread, 0, idleMonitor, (void *)ctx);
    if (res != 0) {
      RLOG(ERROR) << "error starting idle monitor thread, "
                     "res = "
                  << res << ", errno = " << errno;
    }
  }

  if (ctx->args->isDaemon && oldStderr >= 0) {
    VLOG(1) << "Closing stderr";
    close(oldStderr);
    oldStderr = -1;
  }

  return (void *)ctx;
}

void encfs_destroy(void *_ctx) {}

int main(int argc, char *argv[]) {
#if defined(ENABLE_NLS) && defined(LOCALEDIR)
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  // anything that comes from the user should be considered tainted until
  // we've processed it and only allowed through what we support.
  std::shared_ptr<EncFS_Args> encfsArgs(new EncFS_Args);
  for (int i = 0; i < MaxFuseArgs; ++i)
    encfsArgs->fuseArgv[i] = NULL;  // libfuse expects null args..

  if (argc == 1 || !processArgs(argc, argv, encfsArgs)) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  if (encfsArgs->isVerbose) {
    el::Loggers::setVerboseLevel(1);
  }

  encfs::initLogging(encfsArgs->isVerbose);

  VLOG(1) << "Root directory: " << encfsArgs->opts->rootDir;
  VLOG(1) << "Fuse arguments: " << encfsArgs->toString();

  fuse_operations encfs_oper;
  // in case this code is compiled against a newer FUSE library and new
  // members have been added to fuse_operations, make sure they get set to
  // 0..
  memset(&encfs_oper, 0, sizeof(fuse_operations));

  encfs_oper.getattr = encfs_getattr;
  encfs_oper.readlink = encfs_readlink;
  encfs_oper.readdir = encfs_readdir;
  encfs_oper.mknod = encfs_mknod;
  encfs_oper.mkdir = encfs_mkdir;
  encfs_oper.unlink = encfs_unlink;
  encfs_oper.rmdir = encfs_rmdir;
  encfs_oper.symlink = encfs_symlink;
  encfs_oper.rename = encfs_rename;
  encfs_oper.link = encfs_link;
  encfs_oper.chmod = encfs_chmod;
  encfs_oper.chown = encfs_chown;
  encfs_oper.truncate = encfs_truncate;
  encfs_oper.utime = encfs_utime;  // deprecated for utimens
  encfs_oper.open = encfs_open;
  encfs_oper.read = encfs_read;
  encfs_oper.write = encfs_write;
  encfs_oper.statfs = encfs_statfs;
  encfs_oper.flush = encfs_flush;
  encfs_oper.release = encfs_release;
  encfs_oper.fsync = encfs_fsync;
#ifdef HAVE_XATTR
  encfs_oper.setxattr = encfs_setxattr;
  encfs_oper.getxattr = encfs_getxattr;
  encfs_oper.listxattr = encfs_listxattr;
  encfs_oper.removexattr = encfs_removexattr;
#endif  // HAVE_XATTR
  // encfs_oper.opendir = encfs_opendir;
  // encfs_oper.readdir = encfs_readdir;
  // encfs_oper.releasedir = encfs_releasedir;
  // encfs_oper.fsyncdir = encfs_fsyncdir;
  encfs_oper.init = encfs_init;
  encfs_oper.destroy = encfs_destroy;
  // encfs_oper.access = encfs_access;
  encfs_oper.create = encfs_create;
  encfs_oper.ftruncate = encfs_ftruncate;
  encfs_oper.fgetattr = encfs_fgetattr;
  // encfs_oper.lock = encfs_lock;
  encfs_oper.utimens = encfs_utimens;
  // encfs_oper.bmap = encfs_bmap;

  openssl_init(encfsArgs->isThreaded);

  // context is not a smart pointer because it will live for the life of
  // the filesystem.
  auto ctx = std::shared_ptr<EncFS_Context>(new EncFS_Context);
  ctx->publicFilesystem = encfsArgs->opts->ownerCreate;
  RootPtr rootInfo = initFS(ctx.get(), encfsArgs->opts);

  int returnCode = EXIT_FAILURE;

  if (rootInfo) {
    // turn off delayMount, as our prior call to initFS has already
    // respected any delay, and we want future calls to actually
    // mount.
    encfsArgs->opts->delayMount = false;

    // set the globally visible root directory node
    ctx->setRoot(rootInfo->root);
    ctx->args = encfsArgs;
    ctx->opts = encfsArgs->opts;

    if (encfsArgs->isThreaded == false && encfsArgs->idleTimeout > 0) {
      // xgroup(usage)
      cerr << _("Note: requested single-threaded mode, but an idle\n"
                "timeout was specified.  The filesystem will operate\n"
                "single-threaded, but threads will still be used to\n"
                "implement idle checking.")
           << endl;
    }

    // reset umask now, since we don't want it to interfere with the
    // pass-thru calls..
    umask(0);

    if (encfsArgs->isDaemon) {
      // keep around a pointer just in case we end up needing it to
      // report a fatal condition later (fuse_main exits unexpectedly)...
      oldStderr = dup(STDERR_FILENO);
    }

    try {
      time_t startTime, endTime;

      if (encfsArgs->opts->annotate) cerr << "$STATUS$ fuse_main_start" << endl;

      // FIXME: workaround for fuse_main returning an error on normal
      // exit.  Only print information if fuse_main returned
      // immediately..
      time(&startTime);

      // fuse_main returns an error code in newer versions of fuse..
      int res = fuse_main(encfsArgs->fuseArgc,
                          const_cast<char **>(encfsArgs->fuseArgv), &encfs_oper,
                          (void *)ctx.get());

      time(&endTime);

      if (encfsArgs->opts->annotate) cerr << "$STATUS$ fuse_main_end" << endl;

      if (res == 0) returnCode = EXIT_SUCCESS;

      if (res != 0 && encfsArgs->isDaemon && (oldStderr >= 0) &&
          (endTime - startTime <= 1)) {
        // the users will not have seen any message from fuse, so say a
        // few words in libfuse's memory..
        FILE *out = fdopen(oldStderr, "a");
        // xgroup(usage)
        fputs(_("fuse failed.  Common problems:\n"
                " - fuse kernel module not installed (modprobe fuse)\n"
                " - invalid options -- see usage message\n"),
              out);
        fclose(out);
      }
    } catch (std::exception &ex) {
      RLOG(ERROR) << "Internal error: Caught exception from main loop: "
                  << ex.what();
    } catch (...) {
      RLOG(ERROR) << "Internal error: Caught unexpected exception";
    }

    if (ctx->args->idleTimeout > 0) {
      ctx->running = false;
      // wake up the thread if it is waiting..
      VLOG(1) << "waking up monitoring thread";
      pthread_mutex_lock(&ctx->wakeupMutex);
      pthread_cond_signal(&ctx->wakeupCond);
      pthread_mutex_unlock(&ctx->wakeupMutex);
      VLOG(1) << "joining with idle monitoring thread";
      pthread_join(ctx->monitorThread, 0);
      VLOG(1) << "join done";
    }
  }

  // cleanup so that we can check for leaked resources..
  rootInfo.reset();
  ctx->setRoot(std::shared_ptr<DirNode>());

  MemoryPool::destroyAll();
  openssl_shutdown(encfsArgs->isThreaded);

  return returnCode;
}

/*
    Idle monitoring thread.  This is only used when idle monitoring is enabled.
    It will cause the filesystem to be automatically unmounted (causing us to
    commit suicide) if the filesystem stays idle too long.  Idle time is only
    checked if there are no open files, as I don't want to risk problems by
    having the filesystem unmounted from underneath open files!
*/
const int ActivityCheckInterval = 10;
static bool unmountFS(EncFS_Context *ctx);

static void *idleMonitor(void *_arg) {
  EncFS_Context *ctx = (EncFS_Context *)_arg;
  std::shared_ptr<EncFS_Args> arg = ctx->args;

  const int timeoutCycles = 60 * arg->idleTimeout / ActivityCheckInterval;
  int idleCycles = -1;

  pthread_mutex_lock(&ctx->wakeupMutex);

  while (ctx->running) {
    int usage = ctx->getAndResetUsageCounter();

    if (usage == 0 && ctx->isMounted())
      ++idleCycles;
    else
      idleCycles = 0;

    if (idleCycles >= timeoutCycles) {
      int openCount = ctx->openFileCount();
      if (openCount == 0) {
        if (unmountFS(ctx)) {
          // wait for main thread to wake us up
          pthread_cond_wait(&ctx->wakeupCond, &ctx->wakeupMutex);
          break;
        }
      } else {
        RLOG(WARNING) << "Filesystem " << arg->opts->mountPoint
                      << " inactivity detected, but still " << openCount
                      << " opened files";
      }
    }

    VLOG(1) << "idle cycle count: " << idleCycles << ", timeout after "
            << timeoutCycles;

    struct timeval currentTime;
    gettimeofday(&currentTime, 0);
    struct timespec wakeupTime;
    wakeupTime.tv_sec = currentTime.tv_sec + ActivityCheckInterval;
    wakeupTime.tv_nsec = currentTime.tv_usec * 1000;
    pthread_cond_timedwait(&ctx->wakeupCond, &ctx->wakeupMutex, &wakeupTime);
  }

  pthread_mutex_unlock(&ctx->wakeupMutex);

  VLOG(1) << "Idle monitoring thread exiting";

  return 0;
}

static bool unmountFS(EncFS_Context *ctx) {
  std::shared_ptr<EncFS_Args> arg = ctx->args;
  if (arg->opts->mountOnDemand) {
    VLOG(1) << "Detaching filesystem due to inactivity: "
            << arg->opts->mountPoint;

    ctx->setRoot(std::shared_ptr<DirNode>());
    return false;
  } else {
    // Time to unmount!
    RLOG(WARNING) << "Unmounting filesystem due to inactivity: "
                  << arg->opts->mountPoint;
    fuse_unmount(arg->opts->mountPoint.c_str());
    return true;
  }
}
