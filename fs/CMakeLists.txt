protobuf_generate_cpp (PROTO_SRCS PROTO_HDRS ${PROJECT_SOURCE_DIR}/protos/fsconfig.proto)

include_directories (${PROJECT_BINARY_DIR}/base)
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

add_executable (checkops
    checkops.cpp
)
target_link_libraries (checkops
    encfs-fs
    encfs-cipher
    encfs-base
    ${GLOG_LIBRARIES}
)

# Unit tests are optional, depends on libgtest (Google's C++ test framework).
if (GTEST_FOUND)
    link_directories (${PROJECT_BINARY_DIR}/base)
    link_directories (${PROJECT_BINARY_DIR}/cipher)

    include_directories (${GTEST_INCLUDE_DIR})
    add_executable (fs-tests
        MemBlockFileIO.cpp
        MemFileIO.cpp
        testing.cpp
        test_IO.cpp
        test_BlockIO.cpp
    )

    target_link_libraries (fs-tests
        ${GTEST_BOTH_LIBRARIES}
        encfs-fs
        encfs-cipher
        encfs-base
        ${GLOG_LIBRARIES}
    )

    add_test (FSTests fs-tests)
    GTEST_ADD_TESTS (fs-tests "${FSTestArgs}" test_IO.cpp test_BlockIO.cpp)
endif (GTEST_FOUND)
