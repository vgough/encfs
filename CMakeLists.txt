cmake_minimum_required(VERSION 2.8)
project(Encfs)

set (ENCFS_MAJOR 2)
set (ENCFS_MINOR 0)
set (ENCFS_VERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}")

option (BUILD_SHARED_LIBS "Build dynamic link libraries" OFF)

option (WITH_OPENSSL "WithOpenSSL" OFF)
option (WITH_COMMON_CRYPTO "WithCommonCrypto" OFF)
option (WITH_BOTAN "WithBotan" ON)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
    "${CMAKE_SOURCE_DIR}/CMakeModules/")

# Include Crypto checks here so that they can set values in config.h
if (WITH_COMMON_CRYPTO)
  set (WITH_BOTAN OFF)
  set (WITH_OPENSSL OFF)

  find_library (SECURITY_FRAMEWORK Security)
  mark_as_advanced (SECURITY_FRAMEWORK)
elseif (WITH_BOTAN)
  set (WITH_COMMON_CRYPTO OFF)
  set (WITH_OPENSSL OFF)

  find_package (Botan REQUIRED)
elseif (WITH_OPENSSL)
  set (WITH_BOTAN OFF)
  set (WITH_COMMON_CRYPTO OFF)

  find_package (OpenSSL REQUIRED)
  include (OpenSSLTests)
endif (WITH_COMMON_CRYPTO)

# Tweak compiler flags.
set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

include (CheckCXXCompilerFlag)
check_cxx_compiler_flag (-std=c++11 HAVE_C11_FLAG)
check_cxx_compiler_flag (-std=gnu++11 HAVE_GNU11_FLAG)

if (HAVE_GNU11_FLAG)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")
elseif (HAVE_C11_FLAG)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif (HAVE_GNU11_FLAG)

# Flume specific flags.
find_package (FUSE REQUIRED)
include_directories (${FUSE_INCLUDE_DIR})
add_definitions (-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26)
if (APPLE)
    add_definitions (-D__FreeBSD__=10)
endif (APPLE)

# Packaging config.
set (CPACK_PACKAGE_NAME "Encfs")
set (CPACK_PACKAGE_VERSION_MAJOR ${ENCFS_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${ENCFS_MINOR})
set (CPACK_SOURCE_GENERATOR TGZ)
set (CPACK_SOURCE_IGNORE_FILES
    "/_darcs/"
    "/build/")
include (CPack)

# Check for external files.
include (CheckIncludeFileCXX)
check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)

check_include_file_cxx (tr1/memory HAVE_TR1_MEMORY)
check_include_file_cxx (tr1/unordered_map HAVE_TR1_UNORDERED_MAP)
check_include_file_cxx (tr1/unordered_set HAVE_TR1_UNORDERED_SET)
check_include_file_cxx (tr1/tuple HAVE_TR1_TUPLE)

check_include_file_cxx (valgrind/valgrind.h HAVE_VALGRIND_VALGRIND_H)
check_include_file_cxx (valgrind/memcheck.h HAVE_VALGRIND_MEMCHECK_H)

# Used with CommonCrypto
check_include_file_cxx (Security/SecRandom.h HAVE_SEC_RANDOM_H)

# Check if xattr functions take extra argument.
include (CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES ("#include <sys/types.h>
  #include <sys/xattr.h>
  int main() { getxattr(0,0,0,0,0,0); return 1; } " XATTR_ADD_OPT)

include (CheckFunctionExists)
check_function_exists(lchmod HAVE_LCHMOD)

# Libraries or programs used for multiple modules.
find_package (Protobuf REQUIRED)
include_directories (${PROTOBUF_INCLUDE_DIR})

find_package (GLog REQUIRED)
include_directories (${GLOG_INCLUDE_DIRS})

find_package (Threads)

set (CMAKE_THREAD_PREFER_PTHREAD)
find_program (POD2MAN pod2man)

find_package (GTest)
if (GTEST_FOUND) 
    include_directories(${GTEST_INCLUDE_DIR})
    enable_testing()
endif (GTEST_FOUND)

# Prefix for encfs module includes.
include_directories (${Encfs_BINARY_DIR})
include_directories (${Encfs_SOURCE_DIR})

# Subdirectories.
add_subdirectory(base)
add_subdirectory(cipher)
add_subdirectory(fs)
add_subdirectory(encfs)
add_subdirectory(util)
add_subdirectory(po)

# Test target.
if (GTEST_FOUND)
    add_custom_target (test COMMAND ${CMAKE_TEST_COMMAND} DEPENDS
        cipher/cipher-tests fs/fs-tests)
endif (GTEST_FOUND)


