link_directories (${Encfs_BINARY_DIR}/base)

if (WITH_COMMON_CRYPTO)
  find_library (SECURITY_FRAMEWORK Security)
  mark_as_advanced (SECURITY_FRAMEWORK)
  set (EXTRA_LIBS ${SECURITY_FRAMEWORK})
  set (EXTRA_SOURCE CommonCrypto.cpp)
elseif (WITH_OPENSSL)
  find_package (OpenSSL REQUIRED)
  include (OpenSSLTests)
  include_directories (${OPENSSL_INCLUDE_DIR})
  set (EXTRA_LIBS ${OPENSSL_LIBRARIES})
  set (EXTRA_SOURCE openssl.cpp)
elseif (WITH_BOTAN)
  find_package (Botan REQUIRED)
  set (EXTRA_LIBS ${BOTAN_LIBRARIES})
  set (EXTRA_SOURCE botan.cpp)
endif (WITH_COMMON_CRYPTO)

add_library (encfs-cipher
    BlockCipher.cpp
    CipherKey.cpp
    CipherV1.cpp
    MAC.cpp
    MemoryPool.cpp
    NullCiphers.cpp
    PBKDF.cpp
    readpassphrase.cpp
    StreamCipher.cpp
    ${EXTRA_SOURCE}
)

target_link_libraries (encfs-cipher
    ${EXTRA_LIBS}
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
