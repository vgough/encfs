# Compile-time configuration.
configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_library (encfs-base
  autosprintf.cpp
  base64.cpp
  ConfigReader.cpp
  ConfigVar.cpp
  Error.cpp
  Interface.cpp
  XmlReader.cpp
)


target_link_libraries (encfs-base
  ${TINYXML_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
)
