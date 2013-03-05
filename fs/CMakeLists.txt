find_package (FUSE REQUIRED)
include_directories (${FUSE_INCLUDE_DIR})

protobuf_generate_cpp (PROTO_SRCS PROTO_HDRS ${Encfs_SOURCE_DIR}/protos/fsconfig.proto)

enable_testing ()
find_package (GTest)

include_directories (${Encfs_BINARY_DIR}/base)
add_library (encfs-fs
    encfs.cpp
    Context.cpp
    FileIO.cpp
    RawFileIO.cpp
    BlockFileIO.cpp
    CipherFileIO.cpp
    MACFileIO.cpp
    NameIO.cpp
    StreamNameIO.cpp
    BlockNameIO.cpp
    NullNameIO.cpp
    DirNode.cpp
    FileNode.cpp
    FileUtils.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

target_link_libraries (encfs-fs
    ${PROTOBUF_LIBRARY}
)

# Unit tests are optional, depends on libgtest (Google's C++ test framework).
if (GTEST_FOUND)
    link_directories (${Encfs_BINARY_DIR}/base)
    link_directories (${Encfs_BINARY_DIR}/cipher)

    include_directories (${GTEST_INCLUDE_DIR})
    add_executable (unittests
        MemBlockFileIO.cpp
        MemFileIO.cpp
        testing.cpp
        test_IO.cpp
        test_BlockIO.cpp
    )

    target_link_libraries (unittests
        ${GTEST_BOTH_LIBRARIES}
        encfs-fs
        encfs-cipher
        encfs-base
        ${GLOG_LIBRARIES}
    )

    add_test (UnitTests unittests)
    GTEST_ADD_TESTS (unittests "${UnitTestArgs}" test_IO.cpp test_BlockIO.cpp)
    add_custom_target (test COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS unittests)

endif (GTEST_FOUND)
