
include (CheckFunctionExists)

set (CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
set (CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})

check_function_exists (EVP_bf_cbc HAVE_EVP_BF)
if (NOT HAVE_EVP_BF)
    message (STATUS "    Blowfish support disabled.")
endif (NOT HAVE_EVP_BF)

check_function_exists (EVP_aes_128_cbc HAVE_EVP_AES)
if (NOT HAVE_EVP_AES)
    message (STATUS "    AES support disabled.")
endif (NOT HAVE_EVP_AES)

check_function_exists (EVP_aes_128_xts HAVE_EVP_AES_XTS)
if (NOT HAVE_EVP_AES_XTS)
    message (STATUS "    AES/XTS support disabled.")
endif (NOT HAVE_EVP_AES_XTS)

set (CMAKE_REQUIRED_LIBRARIES)
set (CMAKE_REQUIRED_INCLUDES)

