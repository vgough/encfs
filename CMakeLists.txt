set(CMAKE_LEGACY_CYGWIN_WIN32 0)

# 3.0.2 preferred, but we can often get by with 2.8.
cmake_minimum_required(VERSION 2.8)
if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION} LESS 3.0.2)
  message(WARNING "You should use cmake 3.0.2 or newer for configuration to run correctly.")
endif()

project(EncFS C CXX)

set (ENCFS_MAJOR 1)
set (ENCFS_MINOR 9)
set (ENCFS_PATCH 5)
set (ENCFS_VERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}.${ENCFS_PATCH}")
set (ENCFS_SOVERSION "${ENCFS_MAJOR}.${ENCFS_MINOR}")
set (ENCFS_NAME "Encrypted Filesystem")

option(IWYU "Build with IWYU analysis." OFF)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/cmake")

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_LIST_DIR}/vendor/github.com/muflihun/easyloggingpp/cmake")

option (BUILD_UNIT_TESTS "build EncFS unit tests" ON)
option (USE_INTERNAL_TINYXML "use built-in TinyXML2" ON)
option (USE_INTERNAL_EASYLOGGING "use built-in Easylogging++" ON)
option (BUILD_SHARED_LIBS "build internal libraries as shared" OFF)
option (ENABLE_NLS "compile with Native Language Support (using gettext)" ON)
option (INSTALL_LIBENCFS "install libencfs" OFF)
option (LINT "enable lint output" OFF)

if (NOT DEFINED LIB_INSTALL_DIR)
  set (LIB_INSTALL_DIR lib)
endif ()

if (CYGWIN)
  if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX /usr)
  endif()
endif()

# We need C++ 11
if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.0)
  # CMake 3.1 has built-in CXX standard checks.
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED on)
else ()
  if (CMAKE_COMPILER_IS_GNUCXX)
    message ("** Assuming that GNU CXX uses -std=c++11 flag for C++11 compatibility.")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message ("** Assuming that Clang uses -std=c++11 flag for C++11 compatibility.")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  else()
    message ("** No CMAKE C++11 check. If the build breaks, you're on your own.")
  endif()
endif ()

# Let's enable some compilation warnings
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Let's enable some shared lib flags
if (BUILD_SHARED_LIBS)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif ()

add_definitions( -DPACKAGE="encfs" )

# http://www.cmake.org/Wiki/CMake_RPATH_handling#Mac_OS_X_and_the_RPATH
if (APPLE)
   set(CMAKE_MACOSX_RPATH ON)
   set(CMAKE_SKIP_BUILD_RPATH FALSE)
   set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
   set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}")
   set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
   list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}" isSystemDir)
   if("${isSystemDir}" STREQUAL "-1")
     set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}")
   endif()
endif()

if (CYGWIN OR WIN32 OR APPLE)
  set(DEFAULT_CASE_INSENSITIVE TRUE)
else()
  set(DEFAULT_CASE_INSENSITIVE FALSE)
endif()

if (CYGWIN)
  find_program(PKILL NAMES "pkill")
  if(NOT PKILL)
    message(FATAL_ERROR "pkill not found, please install procps-ng package.")
  endif()
endif()

# Check for FUSE.
find_package (FUSE REQUIRED)
include_directories (SYSTEM ${FUSE_INCLUDE_DIR})
add_definitions (-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=29)
if (CYGWIN)
  # Cygwin build is intended to use WinFsp
  add_definitions(-DCYGFUSE)
endif()

# Check for OpenSSL.
find_package (OpenSSL REQUIRED)
include_directories (SYSTEM ${OPENSSL_INCLUDE_DIR})

find_program (POD2MAN pod2man)

# Check for include files and stdlib properties.
include (CheckIncludeFileCXX)
if (NOT CYGWIN)
  check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
  check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)
endif()

include(CheckStructHasMember)
check_struct_has_member("struct dirent" d_type dirent.h HAVE_DIRENT_D_TYPE LANGUAGE CXX)

# Check if xattr functions take extra arguments, as they do on OSX.
include (CheckCXXSourceCompiles)
check_cxx_source_compiles ("#include <sys/types.h>
  #include <sys/xattr.h>
  int main() { getxattr(0,0,0,0,0,0); return 1; }
  " XATTR_ADD_OPT)

# If awailable on current architecture (typically embedded 32-bit), link with it explicitly;
# GCC autodetection is faulty, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81358 and
# find_libray is no great help here since it is sometimes(!) not in standard paths.
set(CMAKE_REQUIRED_FLAGS "-latomic")
CHECK_CXX_SOURCE_COMPILES("int main() {return 0;}" COMPILER_NEEDS_LATOMIC)
if(COMPILER_NEEDS_LATOMIC)
        set(ATOMIC_LIBRARY atomic)
endif()
# compensate the effect of extra linking of libatomic on platforms where intrinsics are used
set(CMAKE_REQUIRED_FLAGS "-Wl,--as-needed")
CHECK_CXX_SOURCE_COMPILES("int main() {return 0;}" LINKER_SUPPORTS_WLASNEEDED)
if(LINKER_SUPPORTS_WLASNEEDED)
        SET(EXTRA_LINKER_FLAGS "-Wl,--as-needed")
endif()

set(CMAKE_REQUIRED_FLAGS)

# Check if we have some standard functions.
include (CheckFuncs)
check_function_exists_glibc (lchmod HAVE_LCHMOD)
check_function_exists_glibc (utimensat HAVE_UTIMENSAT)
if (APPLE)
  message ("-- There is no usable FDATASYNC on Apple")
  set(HAVE_FDATASYNC FALSE)
else()
  check_function_exists_glibc (fdatasync HAVE_FDATASYNC)
endif (APPLE)

set (CMAKE_THREAD_PREFER_PTHREAD)
find_package (Threads REQUIRED)

# Logging.
add_definitions (-DELPP_THREAD_SAFE -DELPP_DISABLE_DEFAULT_CRASH_HANDLING)
add_definitions (-DELPP_NO_DEFAULT_LOG_FILE)
add_definitions (-DELPP_CUSTOM_COUT=std::cerr)
check_include_file_cxx (syslog.h HAVE_SYSLOG_H)
if (HAVE_SYSLOG_H)
  message ("-- Enabled syslog logging support")
  add_definitions(-DELPP_SYSLOG)
endif (HAVE_SYSLOG_H)

# Packaging config.
set (CPACK_PACKAGE_NAME "encfs")
set (CPACK_PACKAGE_VERSION_MAJOR ${ENCFS_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${ENCFS_MINOR})
set (CPACK_SOURCE_GENERATOR TGZ)
set (CPACK_SOURCE_IGNORE_FILES
  "/build/")
include (CPack)

# Compile-time configuration.
configure_file (${CMAKE_CURRENT_LIST_DIR}/config.h.cmake
  ${CMAKE_BINARY_DIR}/config.h)

include_directories (${CMAKE_BINARY_DIR})
include_directories (${CMAKE_CURRENT_LIST_DIR})

# Translations
if (ENABLE_NLS)
  find_package (Intl)
  if (Intl_FOUND)
    include_directories (SYSTEM ${Intl_INCLUDE_DIRS})
  endif()

  add_subdirectory(po)

  add_definitions(-DENABLE_NLS)
  add_definitions(-DLOCALEDIR="${CMAKE_INSTALL_PREFIX}/share/locale")
endif (ENABLE_NLS)

if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.5) # Need 3.6 or above.
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy-4.0" "clang-tidy40" "clang-tidy" DOC "Path to clang-tidy executable")
  if(NOT CLANG_TIDY_EXE)
    message(STATUS "clang-tidy not found.")
  else()
    message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
    string(CONCAT TIDY_OPTS "-checks=*"
      ",-cert-err58-cpp"
      ",-cppcoreguidelines-pro-*"
      ",-google-build-using-namespace"
      ",-google-readability-casting"
      ",-google-readability-todo"
      ",-google-runtime-int"
      ",-google-runtime-references"
      ",-modernize-loop-convert"
      ",-performance-inefficient-string-concatenation"
      ",-readability-inconsistent-declaration-parameter-name"
      ",-readability-named-parameter"
      )
    set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" ${TIDY_OPTS})
    #set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-fix" "-checks=-*,google-readability-redundant-smartptr-get")
  endif()
else()
  message(STATUS "clang-tidy check skipped, need newer cmake")
endif()

if (USE_INTERNAL_TINYXML)
  message("-- Using vendored TinyXML2")
  set(TINYXML_DIR vendor/github.com/leethomason/tinyxml2)
  if (BUILD_SHARED_LIBS)
    set(BUILD_STATIC_LIBS OFF CACHE BOOL "build static libs")
    set(BUILD_SHARED_LIBS ON CACHE BOOL "build shared libs")
    set(TINYXML_LIBRARIES tinyxml2)
  else ()
    set(BUILD_STATIC_LIBS ON CACHE BOOL "build static libs")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "build shared libs")
    set(TINYXML_LIBRARIES tinyxml2_static)
  endif ()
  set(BUILD_TESTS OFF CACHE BOOL "build tests")
  add_subdirectory(${TINYXML_DIR} EXCLUDE_FROM_ALL)
  include_directories(SYSTEM ${CMAKE_CURRENT_LIST_DIR}/${TINYXML_DIR})
  link_directories(${CMAKE_BINARY_DIR}/${TINYXML_DIR})
else ()
  find_package (TinyXML REQUIRED)
  include_directories (SYSTEM ${TINYXML_INCLUDE_DIR})
endif ()

if (USE_INTERNAL_EASYLOGGING)
  message("-- Using vendored Easylogging++")
  set(EASYLOGGING_DIR vendor/github.com/muflihun/easyloggingpp)
  set(build_static_lib ON CACHE BOOL "build static libs")
  add_subdirectory(${EASYLOGGING_DIR} EXCLUDE_FROM_ALL)
  include_directories(SYSTEM ${CMAKE_CURRENT_LIST_DIR}/${EASYLOGGING_DIR}/src)
  link_directories(${CMAKE_BINARY_DIR}/${EASYLOGGING_DIR})
  set(EASYLOGGINGPP_LIBRARY easyloggingpp)
else ()
  set(EASYLOGGINGPP_USE_SHARED_LIBS ON CACHE BOOL "look for shared lib")
  find_package (EASYLOGGINGPP REQUIRED)
  include_directories (SYSTEM ${EASYLOGGINGPP_INCLUDE_DIR})
endif ()

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
  encfs/Error.cpp
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
  encfs/XmlReader.cpp
)
add_library(encfs ${SOURCE_FILES})
set_target_properties(encfs PROPERTIES
  VERSION ${ENCFS_VERSION}
  SOVERSION ${ENCFS_SOVERSION})
target_link_libraries(encfs
  ${EXTRA_LINKER_FLAGS}
  ${FUSE_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${TINYXML_LIBRARIES}
  ${EASYLOGGINGPP_LIBRARY}
  ${CMAKE_THREAD_LIBS_INIT}
  ${Intl_LIBRARIES}
  ${ATOMIC_LIBRARY}
)
if (INSTALL_LIBENCFS)
  install (TARGETS encfs DESTINATION ${LIB_INSTALL_DIR})
endif (INSTALL_LIBENCFS)

if (IWYU)
  if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.2)
    find_program(iwyu_path NAMES include-what-you-use iwyu)
    if (iwyu_path)
      message ("-- Enabled IWYU")
      set_property(TARGET encfs PROPERTY CXX_INCLUDE_WHAT_YOU_USE ${iwyu_path})
    endif()
  endif()
endif()

# Set RPATH to library install path.
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}")

add_executable (encfs-bin encfs/main.cpp)
target_link_libraries (encfs-bin encfs)
set_target_properties (encfs-bin PROPERTIES OUTPUT_NAME "encfs")
install (TARGETS encfs-bin DESTINATION bin)

if(LINT AND CLANG_TIDY_EXE)
  set_target_properties(encfs PROPERTIES CXX_CLANG_TIDY "${DO_CLANG_TIDY}")
  set_target_properties(encfs-bin PROPERTIES CXX_CLANG_TIDY "${DO_CLANG_TIDY}")
endif()

add_executable (encfsctl encfs/encfsctl.cpp)
target_link_libraries (encfsctl encfs)
install (TARGETS encfsctl DESTINATION bin)

add_executable (makekey encfs/makeKey.cpp)
target_link_libraries (makekey encfs)

add_executable (checkops encfs/test.cpp)
target_link_libraries (checkops encfs)

install (PROGRAMS encfs/encfssh DESTINATION bin)

# Reference all headers, to make certain IDEs happy.
file (GLOB_RECURSE all_headers ${CMAKE_CURRENT_LIST_DIR}/*.h)
add_custom_target (all_placeholder SOURCES ${all_headers})

if (POD2MAN)
  set (MAN_DESTINATION "share/man/man1")
  if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    set (MAN_DESTINATION "man/man1")
  endif()

  add_custom_target (encfs-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_CURRENT_LIST_DIR}/encfs/encfs.pod encfs.1)

  add_custom_target (encfsctl-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_CURRENT_LIST_DIR}/encfs/encfsctl.pod encfsctl.1)

  add_custom_target (encfssh-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_CURRENT_LIST_DIR}/encfs/encfssh.pod encfssh.1)

  install (FILES ${CMAKE_BINARY_DIR}/encfs.1 ${CMAKE_BINARY_DIR}/encfsctl.1 ${CMAKE_BINARY_DIR}/encfssh.1
    DESTINATION ${MAN_DESTINATION})
endif (POD2MAN)

if (BUILD_UNIT_TESTS)
  enable_testing()

  set(GOOGLETEST_DIR vendor/github.com/google/googletest)
  add_subdirectory(${GOOGLETEST_DIR} EXCLUDE_FROM_ALL)
  link_directories(${CMAKE_BINARY_DIR}/${GOOGLETEST_DIR}/googletest)

  set(GOOGLEBENCH_DIR vendor/github.com/google/benchmark)
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "benchmark tests")
  add_subdirectory(${GOOGLEBENCH_DIR} EXCLUDE_FROM_ALL)
  link_directories(${CMAKE_BINARY_DIR}/${GOOGLEBENCH_DIR})

  # Unit tests.
  add_subdirectory(test EXCLUDE_FROM_ALL)

  # Integration test target - runs against built encfs.
  add_custom_target(integration COMMAND ${CMAKE_CURRENT_LIST_DIR}/integration.sh)
endif ()
