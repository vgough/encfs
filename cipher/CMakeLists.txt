include_directories (${CMAKE_SOURCE_DIR}/base)
link_directories (${CMAKE_SOURCE_DIR}/base)

add_library (encfs-cipher
  Cipher.cpp
  CipherKey.cpp
  MemoryPool.cpp
  NullCipher.cpp
  openssl.cpp
  readpassphrase.cpp
  SSL_Cipher.cpp
)

target_link_libraries (encfs-cipher
  encfs-base
  ${CMAKE_THREAD_LIBS_INIT}
)
