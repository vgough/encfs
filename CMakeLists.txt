# 3.1 preferred, but we can often get by with 2.8.
cmake_minimum_required(VERSION 2.8)
project(EncFS C CXX)

set (ENCFS_MAJOR 1)
set (ENCFS_MINOR 9)
set (ENCFS_PATCH 0)
set (ENCFS_VERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}.${ENCFS_PATCH}")
set (ENCFS_SOVERSION "1.9")
set (ENCFS_NAME "Encrypted Filesystem")

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_SOURCE_DIR}/cmake")

# We need C++ 11
if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.0)
  # CMake 3.1 has built-in CXX standard checks.
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED on)
else ()
  if (CMAKE_COMPILER_IS_GNUCXX)
    message ("Assuming that GNU CXX uses -std=c++11 flag for C++11 compatibility.")
    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
  else()
    message ("No CMAKE C++11 check. If the build breaks, you're on your own.")
  endif()
endif ()

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

# Look for old pre-C++11 headers.
check_include_file_cxx (tr1/memory HAVE_TR1_MEMORY)

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

# Compile-time configuration.
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
add_library(encfs SHARED ${SOURCE_FILES})
set_property(TARGET encfs PROPERTY VERSION ${ENCFS_VERSION})
set_property(TARGET encfs PROPERTY SOVERSION ${ENCFS_SOVERSION})
target_link_libraries(encfs
  ${FUSE_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${Boost_LIBRARIES}
  ${RLOG_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
)
install (TARGETS encfs DESTINATION lib)

# Set RPATH to library install path.
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

add_executable (encfs-bin encfs/main.cpp)
target_link_libraries (encfs-bin encfs)
set_target_properties (encfs-bin PROPERTIES OUTPUT_NAME "encfs")
install (TARGETS encfs-bin DESTINATION bin)

add_executable (encfsctl encfs/encfsctl.cpp)
target_link_libraries (encfsctl encfs)
install (TARGETS encfsctl DESTINATION bin)

add_executable (makekey encfs/makeKey.cpp)
target_link_libraries (makekey encfs)

add_executable (checkops encfs/test.cpp)
target_link_libraries (checkops encfs)

install (FILES encfs/encfssh DESTINATION bin)

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

# Translations
if (GETTEXT_FOUND)
  file(GLOB po_files "po/*.po")
  foreach(pofile ${po_files})
    get_filename_component(lang ${pofile} NAME_WE)
    #message("-- Found gettext PO file for ${lang}: ${pofile}")

    gettext_process_po_files(${lang} ALL PO_FILES ${pofile})
  endforeach()
endif (GETTEXT_FOUND)

# Tests
enable_testing()
add_test (NAME checkops
          COMMAND checkops)

find_program (PERL_PROGRAM perl)
if (PERL_PROGRAM)
  file(GLOB pl_test_files "tests/*.t.pl")
  #add_test (NAME scriptedtests
  #          COMMAND ${PERL_PROGRAM} -I ${CMAKE_SOURCE_DIR}
  #             -MTest::Harness
  #             -e "$$Test::Harness::verbose=1; runtests @ARGV;"
  #             ${pl_test_files})
endif (PERL_PROGRAM)
