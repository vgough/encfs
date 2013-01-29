cmake_minimum_required(VERSION 2.8)
project(Encfs)

set (ENCFS_MAJOR 2)
set (ENCFS_MINOR 0)
set (ENCFS_PATCH 0)
set (ENCFS_VERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}.${ENCFS_PATCH}")

option (BUILD_SHARED_LIBS "Build dynamic link libraries" OFF)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
    "${CMAKE_SOURCE_DIR}/CMakeModules/")

set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

set (CPACK_PACKAGE_NAME "Encfs")
set (CPACK_PACKAGE_VERSION_MAJOR ${ENCFS_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${ENCFS_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${ENCFS_PATCH})
set (CPACK_SOURCE_GENERATOR TGZ)
set (CPACK_SOURCE_IGNORE_FILES
    "/_darcs/"
    "/build/")
include (CPack)

include (CheckIncludeFileCXX)
check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)

check_include_file_cxx (tr1/memory HAVE_TR1_MEMORY)
check_include_file_cxx (tr1/unordered_map HAVE_TR1_UNORDERED_MAP)
check_include_file_cxx (tr1/unordered_set HAVE_TR1_UNORDERED_SET)
check_include_file_cxx (tr1/tuple HAVE_TR1_TUPLE)

check_include_file_cxx (valgrind/valgrind.h HAVE_VALGRIND_VALGRIND_H)
check_include_file_cxx (valgrind/memcheck.h HAVE_VALGRIND_MEMCHECK_H)

# TODO: move this to cipher directory.
find_package (OpenSSL REQUIRED)
include (OpenSSLTests)

# Check if xattr functions take extra argument.
include (CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES ("#include <sys/types.h>
  #include <sys/xattr.h>
  int main() { getxattr(0,0,0,0,0,0); return 1; } " XATTR_ADD_OPT)

add_definitions (-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26)
if (APPLE)
    add_definitions (-D__FreeBSD__=10)
endif (APPLE)

find_package (GLog REQUIRED)
include_directories (${GLOG_INCLUDE_DIRS})

find_program (POD2MAN pod2man)

include_directories (${Encfs_BINARY_DIR})
include_directories (${Encfs_SOURCE_DIR})

add_subdirectory(base)
add_subdirectory(cipher)
add_subdirectory(fs)
add_subdirectory(encfs)
add_subdirectory(util)
add_subdirectory(po)

