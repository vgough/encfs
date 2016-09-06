# 3.1 preferred, but we can often get by with 2.8.
cmake_minimum_required(VERSION 2.8)
project(EncFS C CXX)

set (ENCFS_MAJOR 1)
set (ENCFS_MINOR 9)
set (ENCFS_PATCH 0)
set (ENCFS_VERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}.${ENCFS_PATCH}")
set (ENCFS_SOVERSION "1.9")
set (ENCFS_NAME "Encrypted Filesystem")

option (IWYU "Build with IWYU analyais." OFF)
option (BUILD_SHARED_LIBS "build shared libraries" OFF)
option (USE_INTERNAL_TINYXML "use built-in TinyXML2" ON)
option (ENABLE_NLS "compile with Native Language Support (using gettext)" ON)
option (INSTALL_LIBENCFS "install libencfs" OFF)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_SOURCE_DIR}/cmake")

# We need C++ 11
if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.0)
  # CMake 3.1 has built-in CXX standard checks.
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED on)
else ()
  if (CMAKE_COMPILER_IS_GNUCXX)
    message ("** Assuming that GNU CXX uses -std=c++11 flag for C++11 compatibility.")
    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
  elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message ("** Assuming that Clang uses -std=c++11 flag for C++11 compatibility.")
    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
  else()
    message ("** No CMAKE C++11 check. If the build breaks, you're on your own.")
  endif()
endif ()

add_definitions( -DPACKAGE="encfs" )

# http://www.cmake.org/Wiki/CMake_RPATH_handling#Mac_OS_X_and_the_RPATH
if (APPLE)
   set(CMAKE_MACOSX_RPATH ON)
   set(CMAKE_SKIP_BUILD_RPATH FALSE)
   set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
   set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
   set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
   list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
   if("${isSystemDir}" STREQUAL "-1")
     set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
   endif()
endif()

# Check for FUSE.
find_package (FUSE REQUIRED)
include_directories (${FUSE_INCLUDE_DIR})
add_definitions (-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26)

# Check for OpenSSL.
find_package (OpenSSL REQUIRED)
include_directories (${OPENSSL_INCLUDE_DIR})

if (USE_INTERNAL_TINYXML)
  message("-- Using local TinyXML2 copy")
  add_subdirectory(internal/tinyxml2-3.0.0)
  include_directories(${CMAKE_SOURCE_DIR}/internal/tinyxml2-3.0.0)
  link_directories(${CMAKE_BINARY_DIR}/internal/tinyxml2-3.0.0)
  set(TINYXML_LIBRARIES tinyxml2)
else ()
  find_package (TinyXML REQUIRED)
  include_directories (${TINYXML_INCLUDE_DIR})
endif ()

find_program (POD2MAN pod2man)

# Check for include files and stdlib properties.
include (CheckIncludeFileCXX)
check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)

# Check if xattr functions take extra arguments, as they do on OSX.
# Output error is misleading, so do this test quietly.
include (CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_QUIET_SAVE ${CMAKE_REQUIRED_QUIET})
set (CMAKE_REQUIRED_QUIET True)
check_cxx_source_compiles ("#include <sys/types.h>
  #include <sys/xattr.h>
  int main() { getxattr(0,0,0,0,0,0); return 1; }
  " XATTR_ADD_OPT)
set (CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_SAVE})

# Check if we have some standard functions.
include (CheckFuncs)
check_function_exists_glibc (lchmod HAVE_LCHMOD)
check_function_exists_glibc (utimensat HAVE_UTIMENSAT)

set (CMAKE_THREAD_PREFER_PTHREAD)
find_package (Threads REQUIRED)

# Logging.
add_definitions (-DELPP_THREAD_SAFE -DELPP_DISABLE_DEFAULT_CRASH_HANDLING)
check_include_file_cxx (syslog.h HAVE_SYSLOG_H)
if (HAVE_SYSLOG_H)
  message ("-- Enabled syslog logging support")
  add_definitions(-DELPP_SYSLOG)
endif (HAVE_SYSLOG_H)
# Include top-level path to find logging files.
include_directories (${CMAKE_SOURCE_DIR})

# Packaging config.
set (CPACK_PACKAGE_NAME "encfs")
set (CPACK_PACKAGE_VERSION_MAJOR ${ENCFS_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${ENCFS_MINOR})
set (CPACK_SOURCE_GENERATOR TGZ)
set (CPACK_SOURCE_IGNORE_FILES
  "/build/")
include (CPack)

# Translations
if (ENABLE_NLS)
  add_subdirectory(po)

  add_definitions(-DENABLE_NLS)
  add_definitions(-DLOCALEDIR="${CMAKE_INSTALL_PREFIX}/share/locale")
endif (ENABLE_NLS)

add_subdirectory (base)
add_subdirectory (encfs)

# Tests
enable_testing()
add_test (NAME checkops
          COMMAND encfs/checkops)

find_program (PERL_PROGRAM perl)
if (PERL_PROGRAM)
  file(GLOB pl_test_files "tests/*.t.pl")
  #add_test (NAME scriptedtests
  #          COMMAND ${PERL_PROGRAM} -I ${CMAKE_SOURCE_DIR}
  #             -MTest::Harness
  #             -e "$$Test::Harness::verbose=1; runtests @ARGV;"
  #             ${pl_test_files})
endif (PERL_PROGRAM)
