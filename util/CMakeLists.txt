
include_directories (${Encfs_SOURCE_DIR}/base)
link_directories (${Encfs_BINARY_DIR}/base)

include_directories (${Encfs_SOURCE_DIR}/cipher)
link_directories (${Encfs_BINARY_DIR}/cipher)

include_directories (${Encfs_SOURCE_DIR}/fs)
link_directories (${Encfs_BINARY_DIR}/fs)

# TODO: move FUSE code into encfs-fs.
find_package (FUSE REQUIRED)
include_directories (${FUSE_INCLUDE_DIR})

include_directories (${CMAKE_BINARY_DIR}/base)


add_executable (encfsctl
    encfsctl.cpp)
target_link_libraries (encfsctl
    encfs-fs
    encfs-cipher
    encfs-base
    ${GLOG_LIBRARIES}
    ${FUSE_LIBRARIES}
)

if (POD2MAN)
    add_custom_target(util-man ALL
        COMMAND ${POD2MAN} -u --section=1 --release=${ENCFS_VERSION}
        --center="Encrypted Filesystem"
        ${CMAKE_CURRENT_SOURCE_DIR}/encfsctl.pod
        encfsctl.1)
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/encfsctl.1
        DESTINATION
        share/man/man1)
endif (POD2MAN)

install (TARGETS encfsctl DESTINATION bin)

