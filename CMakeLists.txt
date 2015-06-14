cmake_minimum_required(VERSION 3.0)
project(EncFS C CXX)

set (ENCFS_MAJOR 1)
set (ENCFS_MINOR 9)
set (ENCFS_VERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}")
set (ENCFS_SOVERSION 7)
set (ENCFS_NAME "Encrypted Filesystem")

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_SOURCE_DIR}/cmake")

# We need C++ 11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)

# Check for FUSE.
find_package (FUSE REQUIRED)
include_directories (${FUSE_INCLUDE_DIR})
add_definitions (-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26)

# Check for OpenSSL.
find_package (OpenSSL REQUIRED)
include_directories (${OPENSSL_INCLUDE_DIR})

find_package(Boost
  1.34.0
  REQUIRED
  COMPONENTS serialization)
include_directories (${Boost_INCLUDE_DIRS})

find_package (RLog REQUIRED)
add_definitions (-DRLOG_COMPONENT="encfs")
include_directories (${RLOG_INCLUDE_DIR})

find_program (POD2MAN pod2man)
include (FindGettext)

# Check for include files and stdlib properties.
include (CheckIncludeFileCXX)
check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)

check_include_file_cxx (tr1/memory HAVE_TR1_MEMORY)
check_include_file_cxx (tr1/unordered_map HAVE_TR1_UNORDERED_MAP)
check_include_file_cxx (tr1/unordered_set HAVE_TR1_UNORDERED_SET)
check_include_file_cxx (tr1/tuple HAVE_TR1_TUPLE)

# Check if xattr functions take extra arguments, as they do on OSX.
include (CheckCXXSourceCompiles)
check_cxx_source_compiles ("#include <sys/types.h>
  #include <sys/xattr.h>
  int main() { getxattr(0,0,0,0,0,0); return 1; }
  " XATTR_ADD_OPT)

# Check if we have lchmod.
include (CheckFuncs)
check_function_exists_glibc (lchmod HAVE_LCHMOD)

set (CMAKE_THREAD_PREFER_PTHREAD)
find_package (Threads REQUIRED)

# Packaging config.
set (CPACK_PACKAGE_NAME "encfs")
set (CPACK_PACKAGE_VERSION_MAJOR ${ENCFS_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${ENCFS_MINOR})
set (CPACK_SOURCE_GENERATOR TGZ)
set (CPACK_SOURCE_IGNORE_FILES
  "/build/")
include (CPack)

configure_file (${CMAKE_SOURCE_DIR}/config.h.cmake
  ${CMAKE_BINARY_DIR}/config.h)

include_directories (${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR})

set(SOURCE_FILES
  encfs/autosprintf.cpp
  encfs/base64.cpp
  encfs/BlockFileIO.cpp
  encfs/BlockNameIO.cpp
  encfs/Cipher.cpp
  encfs/CipherFileIO.cpp
  encfs/CipherKey.cpp
  encfs/ConfigReader.cpp
  encfs/ConfigVar.cpp
  encfs/Context.cpp
  encfs/DirNode.cpp
  encfs/encfs.cpp
  encfs/FileIO.cpp
  encfs/FileNode.cpp
  encfs/FileUtils.cpp
  encfs/Interface.cpp
  encfs/MACFileIO.cpp
  encfs/MemoryPool.cpp
  encfs/NameIO.cpp
  encfs/NullCipher.cpp
  encfs/NullNameIO.cpp
  encfs/openssl.cpp
  encfs/RawFileIO.cpp
  encfs/readpassphrase.cpp
  encfs/SSL_Cipher.cpp
  encfs/StreamNameIO.cpp
)
add_library(encfs1 SHARED ${SOURCE_FILES})
set_property(TARGET encfs1 PROPERTY VERSION ${ENCFS_VERSION})
set_property(TARGET encfs1 PROPERTY SOVERSION ${ENCFS_SOVERSION})
target_link_libraries(encfs1
  ${FUSE_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${Boost_LIBRARIES}
  ${RLOG_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
)

add_executable (encfs encfs/main.cpp)
target_link_libraries (encfs encfs1)

add_executable (encfsctl encfs/encfsctl.cpp)
target_link_libraries (encfsctl encfs1)

add_executable (makekey encfs/makeKey.cpp)
target_link_libraries (makekey encfs1)

add_executable (checkops encfs/test.cpp)
target_link_libraries (checkops encfs1)

# Reference all headers, to make certain IDEs happy.
file (GLOB_RECURSE all_headers ${CMAKE_SOURCE_DIR}/*.h)
add_custom_target (all_placeholder SOURCES ${all_headers})

if (POD2MAN)
  add_custom_target (encfs-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_SOURCE_DIR}/encfs/encfs.pod encfs.1)

  add_custom_target (encfsctl-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_SOURCE_DIR}/encfs/encfsctl.pod encfsctl.1)

  install (FILES ${CMAKE_BINARY_DIR}/encfs.1 ${CMAKE_BINARY_DIR}/encfsctl.1
    DESTINATION share/man/man1)
endif (POD2MAN)

install (TARGETS encfs DESTINATION bin)
install (FILES ${CMAKE_SOURCE_DIR}/encfs/encssh DESTINATION bin)
