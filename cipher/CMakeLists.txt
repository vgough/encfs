include_directories (${OPENSSL_INCLUDE_DIR})

link_directories (${Encfs_BINARY_DIR}/base)

add_library (encfs-cipher
    BlockCipher.cpp
    Cipher.cpp
    CipherKey.cpp
    MAC.cpp
    MemoryPool.cpp
    NullCipher.cpp
    openssl.cpp
    PBKDF.cpp
    readpassphrase.cpp
    SSL_Cipher.cpp
    StreamCipher.cpp
)

target_link_libraries (encfs-cipher
    ${OPENSSL_LIBRARIES}
)

if (GTEST_FOUND)
    link_directories (${PROJECT_BINARY_DIR}/base)
    include_directories (${GTEST_INCLUDE_DIR})

    file (GLOB TEST_FILES "*_test.cpp")

    add_executable (cipher-tests
        testing.cpp
        ${TEST_FILES}
    )

    target_link_libraries (cipher-tests
        ${GTEST_BOTH_LIBRARIES}
        encfs-cipher
        encfs-base
        ${GLOG_LIBRARIES}
    )

    add_test (CipherTests cipher-tests)
    GTEST_ADD_TESTS (cipher-tests "${CipherTestArgs}" ${TEST_FILES})
endif (GTEST_FOUND)
