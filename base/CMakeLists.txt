find_package (TinyXML REQUIRED)
include_directories (${TINYXML_INCLUDE_DIR})
set (LIBS ${LIBS} ${TINYXML_LIBRARIES})

find_package (Protobuf REQUIRED)


protobuf_generate_cpp (PROTO_SRCS PROTO_HDRS ${Encfs_SOURCE_DIR}/protos/interface.proto)

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_library (encfs-base
    autosprintf.cpp
    base64.cpp
    ConfigReader.cpp
    ConfigVar.cpp
    Error.cpp
    Interface.cpp
    Range.h
    Registry.h
    XmlReader.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

target_link_libraries (encfs-base
    ${PROTOBUF_LIBRARY}
    ${TINYXML_LIBRARIES}
)

