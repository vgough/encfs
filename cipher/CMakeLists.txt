include_directories (${OPENSSL_INCLUDE_DIR})

link_directories (${Encfs_BINARY_DIR}/base)

enable_testing ()
find_package (GTest REQUIRED)

add_library (encfs-cipher
    readpassphrase.cpp
    BlockCipher.cpp
    Cipher.cpp
    CipherKey.cpp
    MemoryPool.cpp
    NullCipher.cpp
    openssl.cpp
    SSL_Cipher.cpp
)

target_link_libraries (encfs-cipher
    ${OPENSSL_LIBRARIES}
)

#include_directories (${GTEST_INCLUDE_DIR})
#add_executable (unittests
#MemBlockFileIO.cpp
#MemFileIO.cpp
#testing.cpp
#test_IO.cpp
#test_BlockIO.cpp
#)

#target_link_libraries (unittests
#${GTEST_BOTH_LIBRARIES}
#encfs-fs
#encfs-base
#${GLOG_LIBRARIES}
#)

#add_test (UnitTests unittests)
#GTEST_ADD_TESTS (unittests "${UnitTestArgs}" test_IO.cpp test_BlockIO.cpp)
#add_custom_target (test COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS unittests)

