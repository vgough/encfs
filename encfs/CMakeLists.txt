include_directories (${CMAKE_SOURCE_DIR}/base)
link_directories (${CMAKE_SOURCE_DIR}/base)
include_directories (${CMAKE_SOURCE_DIR}/cipher)
link_directories (${CMAKE_SOURCE_DIR}/cipher)

include_directories (${CMAKE_BINARY_DIR}/base)

set(SOURCE_FILES
  BlockFileIO.cpp
  BlockNameIO.cpp
  CipherFileIO.cpp
  Context.cpp
  DirNode.cpp
  encfs.cpp
  FileIO.cpp
  FileNode.cpp
  FileUtils.cpp
  MACFileIO.cpp
  NameIO.cpp
  NullNameIO.cpp
  RawFileIO.cpp
  StreamNameIO.cpp
)
add_library(encfs ${SOURCE_FILES})
set_target_properties(encfs PROPERTIES
  VERSION ${ENCFS_VERSION}
  SOVERSION ${ENCFS_SOVERSION})
target_link_libraries(encfs
  encfs-base
  encfs-cipher
  ${FUSE_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${TINYXML_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
)
if (INSTALL_LIBENCFS)
  install (TARGETS encfs DESTINATION lib)
endif (INSTALL_LIBENCFS)

# Set RPATH to library install path.
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

add_executable (encfs-bin main.cpp)
target_link_libraries (encfs-bin encfs)
set_target_properties (encfs-bin PROPERTIES OUTPUT_NAME "encfs")
install (TARGETS encfs-bin DESTINATION bin)

add_executable (encfsctl encfsctl.cpp)
target_link_libraries (encfsctl encfs)
install (TARGETS encfsctl DESTINATION bin)

add_executable (makekey makeKey.cpp)
target_link_libraries (makekey encfs)

add_executable (checkops test.cpp)
target_link_libraries (checkops encfs)

install (FILES encfssh DESTINATION bin)

# Reference all headers, to make certain IDEs happy.
file (GLOB_RECURSE all_headers ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
add_custom_target (all_placeholder SOURCES ${all_headers})

if (POD2MAN)
  add_custom_target (encfs-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_CURRENT_SOURCE_DIR}/encfs.pod encfs.1)

  add_custom_target (encfsctl-man ALL
    COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION} --center=${ENCFS_NAME}
            ${CMAKE_CURRENT_SOURCE_DIR}//encfsctl.pod encfsctl.1)

    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/encfs.1 ${CMAKE_CURRENT_BINARY_DIR}/encfsctl.1
    DESTINATION share/man/man1)
endif (POD2MAN)

